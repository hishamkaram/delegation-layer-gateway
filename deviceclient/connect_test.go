package deviceclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

type gatewayFixture struct {
	mu                sync.Mutex
	server            *httptest.Server
	descriptor        contract.Descriptor
	ca                *devicecert.CertificateAuthority
	now               time.Time
	options           ConnectOptions
	receipts          map[string]contract.EnrollmentResponse
	requests          []contract.EnrollmentRequest
	scopes            []string
	issues            int64
	failNext          bool
	invalidResponse   bool
	selfHTTP          http.Handler
	tokenHTTP         http.Handler
	droppedResponse   []byte
	registryPath      string
	issuerUnavailable bool
	issuerRequests    int
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	f := &gatewayFixture{now: time.Now().UTC().Truncate(time.Second), receipts: make(map[string]contract.EnrollmentResponse)}
	ca, pemValue := testDeviceCA(t, f.now)
	f.ca = ca
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serveHTTP))
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	base := f.server.URL
	f.descriptor = contract.Descriptor{SchemaVersion: 1, GatewayID: "gateway-one", PublicURL: base, Issuer: base + "/", NativeClientID: "native-client", Audience: base + "/mcp", EnrollmentURL: base + "/v1/enroll", SelfEnrollmentURL: base + contract.EnrollmentPath, RevokeURL: base + contract.RevocationPath, DeviceWSSURL: "wss://" + strings.TrimPrefix(base, "https://") + "/device", DeviceCAPEM: pemValue, SupportedWireVersions: []int{1, 2}, Capabilities: []string{"self-enrollment-v1"}}
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server-ca.pem")
	writePrivate(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}))
	executable := filepath.Join(directory, "delegate")
	writePrivate(t, executable, []byte("selected executable"))
	if err := os.Chmod(executable, 0o700); err != nil {
		t.Fatal(err)
	}
	f.options = ConnectOptions{GatewayURL: base, ProfileDirectory: filepath.Join(directory, "profile"), DelegateExecutable: executable, DelegateRoot: directory, DelegateRootContext: strings.Repeat("a", 64), DeviceName: "Office", PrivateCAFile: certPath, Workspaces: []WorkspaceApproval{{Alias: "acceptance", Directory: directory, NativeContext: "opaque-approved-workspace"}}, Providers: []ProviderPolicy{{Provider: "claude", Permissions: []string{"read-only"}, MaxBudgetSeconds: 60}}, PresentChallenge: func(_ context.Context, c Challenge) error {
		if c.UserCode != "ABCD" || c.VerificationURI != base+"/activate" {
			return errors.New("bad challenge")
		}
		return nil
	}}
	return f
}

func testDeviceCA(t *testing.T, now time.Time) (*devicecert.CertificateAuthority, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := devicecert.NewCertificateAuthority(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writePrivate(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *gatewayFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case contract.DescriptorPath:
		f.json(w, f.descriptor)
	case "/.well-known/oauth-protected-resource/mcp":
		f.json(w, map[string]any{"resource": f.descriptor.Audience, "authorization_servers": []string{f.descriptor.Issuer}})
	case "/.well-known/openid-configuration":
		f.issuerRequests++
		if f.issuerUnavailable {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.json(w, issuerEndpoints{Issuer: f.descriptor.Issuer, Device: f.server.URL + "/oauth/device", Token: f.server.URL + "/oauth/token"})
	case "/oauth/device":
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.scopes = append(f.scopes, r.Form.Get("scope"))
		f.json(w, map[string]any{"device_code": "device-secret-DO-NOT-LOG", "user_code": "ABCD", "verification_uri": f.server.URL + "/activate", "expires_in": 60, "interval": 1})
	case "/oauth/token":
		f.json(w, map[string]any{"access_token": "access-secret-DO-NOT-LOG", "token_type": "Bearer", "expires_in": 60})
	case contract.EnrollmentPath:
		if f.selfHTTP != nil {
			f.serveSelfService(w, r)
		} else {
			f.selfEnroll(w, r)
		}
	case contract.RevocationPath:
		if f.selfHTTP != nil {
			f.serveSelfService(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "/v1/enroll":
		if f.tokenHTTP != nil {
			f.tokenHTTP.ServeHTTP(w, r)
		} else {
			f.tokenEnroll(w, r)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *gatewayFixture) json(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic("fixture response write failed")
	}
}

func (f *gatewayFixture) selfEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer access-secret-DO-NOT-LOG" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, contract.MaxBodyBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request contract.EnrollmentRequest
	if protocol.DecodeStrict(body, &request, contract.MaxBodyBytes) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.requests = append(f.requests, request)
	// The real local store must contain the exact intent before network admission.
	durable, err := os.ReadFile(filepath.Join(f.options.ProfileDirectory, "identity", "identity.json"))
	if err != nil || !strings.Contains(string(durable), request.RequestID) {
		w.WriteHeader(http.StatusConflict)
		return
	}
	response, ok := f.receipts[request.RequestID]
	if !ok {
		response.RequestID = request.RequestID
		response.OwnerPrincipal = "verified-principal"
		response.EnrollmentResponse, err = f.issue(r.Context(), request.CSRDERBase64, request.ExpectedGeneration+1)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.receipts[request.RequestID] = response
	}
	if f.failNext {
		f.failNext = false
		w.WriteHeader(http.StatusServiceUnavailable)
		f.json(w, map[string]string{"secret": "access-secret-DO-NOT-LOG"})
		return
	}
	if f.invalidResponse {
		response.RequestID = "wrong"
	}
	f.json(w, response)
}

func (f *gatewayFixture) tokenEnroll(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxEnrollmentBodyBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request protocol.EnrollmentRequest
	if protocol.DecodeStrict(body, &request, protocol.MaxEnrollmentBodyBytes) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !request.RequireOwned || request.Token != base64.RawURLEncoding.EncodeToString(make([]byte, 32)) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	response, err := f.issue(r.Context(), request.CSRDERBase64, 1)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.json(w, response)
}

func (f *gatewayFixture) issue(ctx context.Context, encoded string, generation uint64) (protocol.EnrollmentResponse, error) {
	csr, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return protocol.EnrollmentResponse{}, err
	}
	info, err := devicecert.ParseCSR(csr)
	if err != nil {
		return protocol.EnrollmentResponse{}, err
	}
	f.issues++
	number := big.NewInt(f.issues + 1)
	ref := domain.CredentialRef{Device: "device-one", Epoch: "epoch-one", Generation: generation}
	intent := domain.IssuanceIntent{ID: "issue-one", Credential: ref, Mode: domain.Regular, Serial: number.Bytes(), CSRHash: info.CSRHash, PublicKeyHash: info.PublicKeyHash, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(-time.Minute).Add(domain.CertificateLifetime)}
	der, err := f.ca.Sign(ctx, intent, csr, number, rand.Reader)
	return protocol.EnrollmentResponse{DeviceID: string(ref.Device), Epoch: string(ref.Epoch), Generation: ref.Generation, Mode: domain.Regular, CertificateDERBase64: base64.StdEncoding.EncodeToString(der)}, err
}

func TestConnectDurableLostResponseRetryReusesIdentity(t *testing.T) {
	f := newGatewayFixture(t)
	f.failNext = true
	if _, err := Connect(t.Context(), f.options); !errors.Is(err, ErrTransport) || strings.Contains(fmt.Sprintf("%+v", err), "secret") {
		t.Fatal("lost response was not safely reported", err)
	}
	status, err := Connect(t.Context(), f.options)
	if err != nil {
		t.Fatal(err)
	}
	if status.DeviceID != "device-one" || status.OwnerPrincipal != "verified-principal" || status.CredentialState != "valid" || status.CredentialGeneration != 1 {
		t.Fatalf("unexpected local status: %+v", status)
	}
	reused, err := Connect(t.Context(), f.options)
	if err != nil || reused.DeviceID != status.DeviceID {
		t.Fatal("reconnect failed", err)
	}
	f.mu.Lock()
	if f.issues != 1 || len(f.requests) != 2 || !reflect.DeepEqual(f.requests[0], f.requests[1]) || len(f.scopes) != 2 {
		t.Error("retry allocated a new device/request")
	}
	f.mu.Unlock()
	assertLocalStatusAndBusy(t, f.options.ProfileDirectory)

	f.mu.Lock()
	f.descriptor.GatewayID = "different-gateway"
	f.mu.Unlock()
	if _, err = Connect(t.Context(), f.options); !errors.Is(err, ErrTrustChanged) {
		t.Fatal("changed Gateway pin accepted", err)
	}
}

func assertLocalStatusAndBusy(t *testing.T, directory string) {
	t.Helper()
	observed, err := Status(t.Context(), directory)
	if err != nil || observed.CredentialState != "valid" || observed.ObservedAt.IsZero() {
		t.Fatal("dated local status missing", err)
	}
	assertPrivateAndSecretFree(t, directory)
	identity, err := deviceidentity.Open(filepath.Join(directory, "identity"))
	if err != nil {
		t.Fatal(err)
	}
	busy, observeErr := Status(t.Context(), directory)
	closeErr := identity.Close()
	if errors.Join(observeErr, closeErr) != nil || !busy.IdentityInUse || busy.CredentialState != "unknown" {
		t.Fatal("leased identity claimed validity/offline", observeErr, closeErr)
	}
}

func assertPrivateAndSecretFree(t *testing.T, directory string) {
	t.Helper()
	for _, relative := range []string{"profile.json", "identity/identity.json"} {
		path := filepath.Join(directory, relative)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("credential data permissions", relative, err)
		}
		data, err := os.ReadFile(path)
		if err != nil || strings.Contains(string(data), "secret-DO-NOT-LOG") {
			t.Fatal("authorization secret persisted", relative, err)
		}
	}
}

func TestExplicitReplacementScopesCASAndRetry(t *testing.T) {
	f := newGatewayFixture(t)
	if _, err := Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	options := f.options
	options.ReplaceExisting = true
	replaced, err := Connect(t.Context(), options)
	if err != nil || replaced.CredentialGeneration != 2 {
		t.Fatal("replacement did not advance same device", err)
	}
	retry, err := Connect(t.Context(), options)
	if err != nil || retry.CredentialGeneration != 2 || retry.DeviceID != replaced.DeviceID {
		t.Fatal("replacement retry changed identity", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issues != 2 || len(f.scopes) != 2 || f.scopes[1] != "device:enroll device:manage" || f.requests[1].ReplaceDeviceID != "device-one" || f.requests[1].ExpectedGeneration != 1 {
		t.Fatal("replacement lacked exact CAS and both scopes")
	}
}

func TestUnattendedEnrollmentUsesBoundedInputAndUnknownOwner(t *testing.T) {
	f := newGatewayFixture(t)
	f.options.PresentChallenge = nil
	data, err := json.Marshal(enrollmentToken{Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), DeviceID: "device-one", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	f.options.EnrollmentTokenReader = strings.NewReader(string(data))
	status, err := Connect(t.Context(), f.options)
	if err != nil || status.OwnerPrincipal != "" || status.DeviceID != "device-one" || status.CredentialState != "valid" {
		t.Fatal("unattended enrollment failed", err)
	}
	f.options.EnrollmentTokenReader = strings.NewReader(string(data))
	f.options.ReplaceExisting = true
	retry, retryErr := Connect(t.Context(), f.options)
	if retryErr != nil || retry.CredentialGeneration != status.CredentialGeneration {
		t.Fatal("same unattended token replacement retry did not reuse valid credential", retryErr)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) != 0 || f.issues != 1 {
		t.Fatal("token enrollment began browser authorization or reissued completed token")
	}
	assertPrivateAndSecretFree(t, f.options.ProfileDirectory)
}

func TestDiscoveryAndEnrollmentRejectMismatchedContracts(t *testing.T) {
	t.Run("unsupported wire", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.descriptor.SupportedWireVersions = []int{1}
		if _, err := Connect(t.Context(), f.options); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	})
	t.Run("public CA readable", func(t *testing.T) {
		f := newGatewayFixture(t)
		if err := os.Chmod(f.options.PrivateCAFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Connect(t.Context(), f.options); err != nil {
			t.Fatal("public trust CA required secret file mode", err)
		}
	})

	t.Run("untrusted TLS", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.options.PrivateCAFile = ""
		if _, err := Connect(t.Context(), f.options); !errors.Is(err, ErrTransport) {
			t.Fatal(err)
		}
	})
	t.Run("response request", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.invalidResponse = true
		if _, err := Connect(t.Context(), f.options); !errors.Is(err, ErrEnrollment) {
			t.Fatal(err)
		}
	})
	t.Run("private token mode", func(t *testing.T) {
		f := newGatewayFixture(t)
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("not a secret"), 0o644); err != nil {
			t.Fatal(err)
		}
		f.options.EnrollmentTokenFile = path
		if _, err := Connect(t.Context(), f.options); !errors.Is(err, ErrConfiguration) {
			t.Fatal(err)
		}
	})
}

func (f *gatewayFixture) serveSelfService(w http.ResponseWriter, r *http.Request) {
	if !f.failNext {
		f.selfHTTP.ServeHTTP(w, r)
		return
	}
	recorder := httptest.NewRecorder()
	f.selfHTTP.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusOK {
		for key, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(recorder.Code)
		if _, err := w.Write(recorder.Body.Bytes()); err != nil {
			panic("fixture response copy failed")
		}
		return
	}
	f.failNext = false
	f.droppedResponse = append([]byte(nil), recorder.Body.Bytes()...)
	w.WriteHeader(http.StatusServiceUnavailable)
}

func TestUnattendedReplacementRejectsDifferentDeviceBeforeRedemption(t *testing.T) {
	f := newGatewayFixture(t)
	if _, err := Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(enrollmentToken{Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), DeviceID: "different-device", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	options := f.options
	options.ReplaceExisting = true
	options.EnrollmentTokenReader = strings.NewReader(string(data))
	if _, err = Connect(t.Context(), options); !errors.Is(err, ErrConflict) {
		t.Fatal("different device token was not rejected before replacement", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issues != 1 || len(f.scopes) != 1 {
		t.Fatal("different device token produced a network enrollment side effect")
	}
}
