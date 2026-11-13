package deviceruntime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connectorconfig"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func checked[T any](t *testing.T, value T, err error) T { t.Helper(); require(t, err); return value }

type testCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	signer      *devicecert.CertificateAuthority
	now         time.Time
}

func newCA(t *testing.T) testCA {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := checked(t, key, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-40 * 24 * time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	data := checked(t, der, err)
	cert, err := x509.ParseCertificate(data)
	certificate := checked(t, cert, err)
	ca, err := devicecert.NewCertificateAuthority(certificate, signer)
	return testCA{certificate: certificate, key: signer, signer: checked(t, ca, err), now: now}
}

func (a testCA) serverCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKey := checked(t, key, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: a.now.Add(-time.Hour), NotAfter: a.now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.certificate, &serverKey.PublicKey, a.key)
	return tls.Certificate{Certificate: [][]byte{checked(t, der, err)}, PrivateKey: serverKey}
}

func (a testCA) sign(ctx context.Context, t *testing.T, csr []byte, ref domain.CredentialRef, notBefore time.Time) []byte {
	t.Helper()
	info, err := devicecert.ParseCSR(csr)
	parsed := checked(t, info, err)
	serial := big.NewInt(3)
	intent := domain.IssuanceIntent{ID: "fixture", Credential: ref, Mode: domain.Regular, Serial: serial.Bytes(), CSRHash: parsed.CSRHash, PublicKeyHash: parsed.PublicKeyHash, NotBefore: notBefore, NotAfter: notBefore.Add(domain.CertificateLifetime)}
	der, err := a.signer.Sign(ctx, intent, csr, serial, rand.Reader)
	return checked(t, der, err)
}

type (
	projectDoc struct {
		Alias        string      `json:"alias"`
		Root         string      `json:"root"`
		Directory    string      `json:"directory"`
		RootToken    string      `json:"root_token"`
		ProjectToken string      `json:"project_token"`
		Providers    []policyDoc `json:"providers"`
	}
	policyDoc struct {
		Provider         string              `json:"provider"`
		Permissions      []domain.Permission `json:"permissions"`
		MaxBudgetSeconds uint32              `json:"max_budget_seconds"`
		NativeModel      bool                `json:"native_model"`
		NativeEffort     bool                `json:"native_effort"`
	}
	configDoc struct {
		Version    int          `json:"schema_version"`
		Gateway    string       `json:"gateway_id"`
		Device     string       `json:"expected_device_id"`
		Enrollment string       `json:"enrollment_url"`
		WSS        string       `json:"wss_url"`
		CA         string       `json:"trust_ca_file"`
		DeviceCA   string       `json:"device_ca_file,omitempty"`
		Identity   string       `json:"identity_directory"`
		Executable string       `json:"delegate_executable"`
		Temporary  string       `json:"temporary_directory"`
		Control    string       `json:"control_timeout"`
		Network    string       `json:"network_timeout"`
		Projects   []projectDoc `json:"projects"`
	}
)

func fixtureConfig(t *testing.T, a testCA, endpoint, executable string, gatewayID ...string) *connectorconfig.Config {
	t.Helper()
	return fixtureConfigWithDeviceCA(t, a, nil, endpoint, executable, gatewayID...)
}

func fixtureConfigWithDeviceCA(t *testing.T, a testCA, deviceCA *testCA, endpoint, executable string, gatewayID ...string) *connectorconfig.Config {
	t.Helper()
	parent := t.TempDir()
	caPath := filepath.Join(parent, "ca.pem")
	require(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.certificate.Raw}), 0o600))
	if executable == "" {
		exe, err := os.Executable()
		executable = checked(t, exe, err)
	}
	doc := configDoc{Version: 1, Gateway: "gateway", Device: "device", Enrollment: endpoint + "/enroll", WSS: strings.Replace(endpoint, "https://", "wss://", 1) + "/connect", CA: caPath, Identity: filepath.Join(parent, "identity"), Executable: executable, Temporary: parent, Control: "5s", Network: "10s", Projects: []projectDoc{{Alias: "project", Root: parent, Directory: parent, RootToken: strings.Repeat("a", 64), ProjectToken: "private-local-canary", Providers: []policyDoc{{Provider: "fixture", Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60, NativeModel: true, NativeEffort: true}}}}}
	if deviceCA != nil {
		doc.DeviceCA = filepath.Join(parent, "device-ca.pem")
		require(t, os.WriteFile(doc.DeviceCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: deviceCA.certificate.Raw}), 0o600))
	}
	if len(gatewayID) > 0 {
		doc.Gateway = gatewayID[0]
	}
	data, err := json.Marshal(doc)
	require(t, err)
	path := filepath.Join(parent, "config.json")
	require(t, os.WriteFile(path, data, 0o600))
	cfg, err := connectorconfig.Load(path)
	return checked(t, cfg, err)
}

func newTLSServer(t *testing.T, a testCA, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{a.serverCertificate(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func openStore(t *testing.T, cfg *connectorconfig.Config) *deviceidentity.Store {
	t.Helper()
	store, err := deviceidentity.Open(cfg.IdentityDirectory())
	owned := checked(t, store, err)
	t.Cleanup(func() { require(t, owned.Close()) })
	return owned
}

func enrollmentInput(t *testing.T, request *http.Request) protocol.EnrollmentRequest {
	t.Helper()
	if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 {
		t.Error("enrollment was not TLS1.3")
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, protocol.MaxEnrollmentBodyBytes+1))
	require(t, err)
	var input protocol.EnrollmentRequest
	require(t, protocol.DecodeStrict(data, &input, protocol.MaxEnrollmentBodyBytes))
	return input
}

func enrollmentOutput(der []byte) protocol.EnrollmentResponse {
	return protocol.EnrollmentResponse{DeviceID: "device", Epoch: "epoch", Generation: 1, Mode: domain.Regular, CertificateDERBase64: base64.StdEncoding.EncodeToString(der)}
}

func TestEnrollmentLostResponseRetriesPersistedCSR(t *testing.T) {
	a := newCA(t)
	var csr []byte
	var output protocol.EnrollmentResponse
	calls := 0
	server := newTLSServer(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := enrollmentInput(t, r)
		decoded, err := base64.StdEncoding.Strict().DecodeString(input.CSRDERBase64)
		require(t, err)
		calls++
		if calls == 1 {
			csr = decoded
			output = enrollmentOutput(a.sign(r.Context(), t, csr, domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}, a.now))
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("HTTP1 hijacking unavailable")
				return
			}
			connection, _, hijackErr := hijacker.Hijack()
			require(t, hijackErr)
			require(t, connection.Close())
			return
		}
		if !bytes.Equal(csr, decoded) {
			t.Error("retry changed persisted CSR")
		}
		w.Header().Set("Content-Type", "application/json")
		require(t, json.NewEncoder(w).Encode(output))
	}))
	cfg := fixtureConfig(t, a, server.URL, "")
	store := openStore(t, cfg)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err := Enroll(t.Context(), cfg, store, token); !errors.Is(err, ErrEnrollment) {
		t.Fatalf("lost response not reported: %v", err)
	}
	require(t, store.Close())
	reopened, err := deviceidentity.Open(cfg.IdentityDirectory())
	restored := checked(t, reopened, err)
	t.Cleanup(func() { require(t, restored.Close()) })
	require(t, Enroll(t.Context(), cfg, restored, token))
	roots, err := cfg.Roots()
	require(t, err)
	_, ref, err := restored.Certificate(roots, time.Now())
	require(t, err)
	if calls != 2 || ref != (domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}) {
		t.Fatal("retry did not install exact credential")
	}
}

func TestEnrollmentRejectsSpoofedResponseAndKeepsKey(t *testing.T) {
	for _, variant := range []string{"device", "generation", "unknown-field", "invalid-der", "wrong-key", "untrusted-ca"} {
		t.Run(variant, func(t *testing.T) {
			a := newCA(t)
			server := newTLSServer(t, a, spoofedEnrollmentHandler(t, a, variant))
			cfg := fixtureConfig(t, a, server.URL, "")
			store := openStore(t, cfg)
			token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			err := Enroll(t.Context(), cfg, store, token)
			if !errors.Is(err, ErrEnrollment) || strings.Contains(err.Error(), "canary") {
				t.Fatalf("unredacted or accepted spoof: %v", err)
			}
			roots, err := cfg.Roots()
			require(t, err)
			if _, _, err = store.Certificate(roots, time.Now()); !errors.Is(err, deviceidentity.ErrAbsent) {
				t.Fatal("invalid enrollment installed certificate")
			}
			if _, err = store.EnsureKey(nil); err != nil {
				t.Fatal("invalid response lost persisted key/CSR")
			}
		})
	}
}

func TestDirectClientDisablesProxyRedirectAndCookies(t *testing.T) {
	roots := x509.NewCertPool()
	client, owned := directClient(roots, nil, time.Second)
	defer owned.CloseIdleConnections()
	if owned.Proxy != nil || client.Jar != nil || owned.TLSClientConfig.MinVersion != tls.VersionTLS13 || owned.MaxConnsPerHost != 1 {
		t.Fatal("network boundary inherited ambient state or lost bounds")
	}
	if !errors.Is(client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) {
		t.Fatal("redirect followed with enrollment token")
	}
}

func TestAlreadyCancelledEnrollmentDoesNotCreateKey(t *testing.T) {
	a := newCA(t)
	cfg := fixtureConfig(t, a, "https://gateway.example", "")
	store := openStore(t, cfg)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err := Enroll(ctx, cfg, store, token); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled enrollment continued")
	}
	if _, err := store.EnsureKey(nil); !errors.Is(err, deviceidentity.ErrInvalid) {
		t.Fatal("cancelled enrollment created a key")
	}
}

func spoofedEnrollmentHandler(t *testing.T, a testCA, variant string) http.HandlerFunc {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := enrollmentInput(t, r)
		csr, err := base64.StdEncoding.DecodeString(input.CSRDERBase64)
		require(t, err)
		if variant == "wrong-key" {
			key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require(t, keyErr)
			replacement, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			require(t, csrErr)
			csr = replacement
		}
		signer := a
		if variant == "untrusted-ca" {
			signer = newCA(t)
		}
		output := enrollmentOutput(signer.sign(r.Context(), t, csr, domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}, a.now))
		switch variant {
		case "device":
			output.DeviceID = "other"
		case "generation":
			output.Generation = 2
		case "invalid-der":
			output.CertificateDERBase64 = base64.StdEncoding.EncodeToString([]byte("canary"))
		}
		data, err := json.Marshal(output)
		require(t, err)
		if variant == "unknown-field" {
			data = append(data[:len(data)-1], []byte(`,"private_key":"canary"}`)...)
		}
		w.Header().Set("Content-Type", "application/json")
		_, writeErr := w.Write(data)
		require(t, writeErr)
	})
}

func TestEnrollmentSeparatesServerAndDeviceAuthorities(t *testing.T) {
	for _, variant := range []string{"distinct-authorities", "wrong-server-authority", "wrong-device-issuer"} {
		t.Run(variant, func(t *testing.T) {
			serverCA := newCA(t)
			deviceCA := newCA(t)
			issuer := deviceCA
			if variant == "wrong-device-issuer" {
				issuer = serverCA
			}
			var requests atomic.Int32
			server := newTLSServer(t, serverCA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				request := enrollmentInput(t, r)
				csr, err := base64.StdEncoding.Strict().DecodeString(request.CSRDERBase64)
				require(t, err)
				ref := domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}
				der := issuer.sign(r.Context(), t, csr, ref, issuer.now)
				w.Header().Set("Content-Type", "application/json")
				require(t, json.NewEncoder(w).Encode(enrollmentOutput(der)))
			}))
			transportTrust := serverCA
			if variant == "wrong-server-authority" {
				transportTrust = deviceCA
			}
			cfg := fixtureConfigWithDeviceCA(t, transportTrust, &deviceCA, server.URL, "")
			store := openStore(t, cfg)
			err := Enroll(t.Context(), cfg, store, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
			assertEnrollmentAuthorities(t, cfg, store, err, variant == "distinct-authorities")
			expectedRequests := int32(1)
			if variant == "wrong-server-authority" {
				expectedRequests = 0
			}
			if requests.Load() != expectedRequests {
				t.Fatal("HTTPS trust failure transmitted enrollment material")
			}
		})
	}
}

func assertEnrollmentAuthorities(t *testing.T, cfg *connectorconfig.Config, store *deviceidentity.Store, enrollErr error, accepted bool) {
	t.Helper()
	if !accepted {
		if !errors.Is(enrollErr, ErrEnrollment) {
			t.Fatal("foreign authority accepted")
		}
		if _, readErr := store.StoredCredentialRef(); !errors.Is(readErr, deviceidentity.ErrAbsent) {
			t.Fatal("foreign authority installed a credential")
		}
		return
	}
	require(t, enrollErr)
	roots, rootsErr := cfg.DeviceRoots()
	require(t, rootsErr)
	_, _, certErr := store.Certificate(roots, time.Now())
	require(t, certErr)
	serverRoots, serverErr := cfg.Roots()
	require(t, serverErr)
	if _, _, certErr = store.Certificate(serverRoots, time.Now()); certErr == nil {
		t.Fatal("issued client certificate trusted HTTPS authority")
	}
}
