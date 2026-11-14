package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type enrollmentConfig struct {
	Version    int                 `json:"schema_version"`
	Gateway    string              `json:"gateway_id"`
	Device     string              `json:"expected_device_id"`
	Enrollment string              `json:"enrollment_url"`
	WSS        string              `json:"wss_url"`
	CA         string              `json:"trust_ca_file"`
	Identity   string              `json:"identity_directory"`
	Executable string              `json:"delegate_executable"`
	Temporary  string              `json:"temporary_directory"`
	Projects   []enrollmentProject `json:"projects"`
}
type (
	enrollmentProject struct {
		Alias        string             `json:"alias"`
		Root         string             `json:"root"`
		Directory    string             `json:"directory"`
		RootToken    string             `json:"root_token"`
		ProjectToken string             `json:"project_token"`
		Providers    []enrollmentPolicy `json:"providers"`
	}
	enrollmentPolicy struct {
		Provider     string              `json:"provider"`
		Permissions  []domain.Permission `json:"permissions"`
		MaxBudget    uint32              `json:"max_budget_seconds"`
		NativeModel  bool                `json:"native_model"`
		NativeEffort bool                `json:"native_effort"`
	}
)

func cliAuthority(t *testing.T, files config.TLSFiles) *devicecert.CertificateAuthority {
	t.Helper()
	data, err := os.ReadFile(files.Certificate)
	require(t, err)
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("missing fixture CA")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	require(t, err)
	data, err = os.ReadFile(files.PrivateKey)
	require(t, err)
	block, _ = pem.Decode(data)
	if block == nil {
		t.Fatal("missing fixture key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require(t, err)
	signer, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("wrong fixture key")
	}
	authority, err := devicecert.NewCertificateAuthority(certificate, signer)
	require(t, err)
	return authority
}

func cliSign(t *testing.T, ca *devicecert.CertificateAuthority, csr []byte, ref domain.CredentialRef) []byte {
	t.Helper()
	info, err := devicecert.ParseCSR(csr)
	require(t, err)
	serial := big.NewInt(3)
	now := time.Now().UTC().Truncate(time.Second)
	intent := domain.IssuanceIntent{ID: "fixture", Credential: ref, Mode: domain.Regular, Serial: serial.Bytes(), CSRHash: info.CSRHash, PublicKeyHash: info.PublicKeyHash, NotBefore: now, NotAfter: now.Add(domain.CertificateLifetime)}
	der, err := ca.Sign(t.Context(), intent, csr, serial, rand.Reader)
	require(t, err)
	return der
}

func TestCLIExplicitReplaceExistingUsesRealTLSAndDurableIdentity(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	serverFiles, caFiles, roots := cliTLS(t, parent)
	authority := cliAuthority(t, caFiles)
	directory := filepath.Join(parent, "identity")
	store, err := deviceidentity.Open(directory)
	require(t, err)
	csr, err := store.EnsureKey(rand.Reader)
	require(t, err)
	prior := domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}
	require(t, store.InstallEnrollment(cliSign(t, authority, csr, prior), prior, roots, time.Now()))
	require(t, store.Close())
	next := prior
	next.Generation = 2
	replacement := cliSign(t, authority, csr, next)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	handler := replacementEnrollmentHandler(t, token, csr, replacement)
	pair, err := tls.LoadX509KeyPair(serverFiles.Certificate, serverFiles.PrivateKey)
	require(t, err)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	t.Cleanup(server.Close)
	executable, err := os.Executable()
	require(t, err)
	cfg := enrollmentConfig{Version: 1, Gateway: "gateway", Device: "device", Enrollment: server.URL + "/enroll", WSS: strings.Replace(server.URL, "https://", "wss://", 1) + "/device", CA: caFiles.Certificate, Identity: directory, Executable: executable, Temporary: parent, Projects: []enrollmentProject{{Alias: "project", Root: parent, Directory: parent, RootToken: strings.Repeat("a", 64), ProjectToken: "private-local-canary", Providers: []enrollmentPolicy{{Provider: "fixture", Permissions: []domain.Permission{domain.ReadOnly}, MaxBudget: 60, NativeModel: true, NativeEffort: true}}}}}
	path := writePrivate(t, filepath.Join(parent, "config.json"), cfg)
	tokenFile := writePrivate(t, filepath.Join(parent, "token.json"), adminapi.Enrollment{Token: token, DeviceID: "device", ExpiresAt: time.Now().Add(time.Minute)})
	code, out, diagnostic := command(t, "connector", "enroll", "--config", path, "--token-file", tokenFile)
	if code != 1 || out != "" || strings.Contains(diagnostic, token) {
		t.Fatal("ordinary enrollment implicitly replaced or leaked credential")
	}
	code, out, diagnostic = command(t, "connector", "enroll", "--config", path, "--token-file", tokenFile, "--replace-existing")
	if code != 0 || diagnostic != "" || !strings.Contains(out, `"state":"enrolled"`) || strings.Contains(out, token) || strings.Contains(out, "certificate") {
		t.Fatalf("explicit replacement failed/redaction: %d %s %s", code, out, diagnostic)
	}
	reopened, err := deviceidentity.Open(directory)
	require(t, err)
	t.Cleanup(func() { require(t, reopened.Close()) })
	certificate, ref, err := reopened.Certificate(roots, time.Now())
	require(t, err)
	if ref != next || !bytes.Equal(certificate.Certificate[0], replacement) {
		t.Fatal("CLI did not commit expected replacement identity")
	}
}

func replacementEnrollmentHandler(t *testing.T, token string, csr, replacement []byte) http.HandlerFunc {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, readErr := io.ReadAll(io.LimitReader(r.Body, enrollment.MaxEnrollmentBodyBytes))
		if readErr != nil {
			t.Error(readErr)
			return
		}
		var request enrollment.EnrollmentRequest
		if decodeErr := protocol.DecodeStrict(data, &request, enrollment.MaxEnrollmentBodyBytes); decodeErr != nil {
			t.Error(decodeErr)
			return
		}
		if request.Token != token || request.CSRDERBase64 != base64.StdEncoding.EncodeToString(csr) {
			t.Error("CLI changed token/key CSR")
		}
		w.Header().Set("Content-Type", "application/json")
		if encodeErr := json.NewEncoder(w).Encode(enrollment.EnrollmentResponse{DeviceID: "device", Epoch: "epoch", Generation: 2, Mode: domain.Regular, CertificateDERBase64: base64.StdEncoding.EncodeToString(replacement)}); encodeErr != nil {
			t.Error(encodeErr)
		}
	})
}
