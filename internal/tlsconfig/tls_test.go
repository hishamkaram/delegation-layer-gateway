package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
)

type certificateFixture struct {
	files       config.TLSFiles
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

func writeFixture(t *testing.T, dir, name string, ca bool, now time.Time) certificateFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{"localhost"}}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	files := config.TLSFiles{Certificate: filepath.Join(dir, name+".pem"), PrivateKey: filepath.Join(dir, name+".key")}
	if err = os.WriteFile(files.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(files.PrivateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFixture{files: files, certificate: certificate, key: key}
}

func TestTLS13AndSeparateDeviceTrustBoundary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	serverFixture := writeFixture(t, dir, "server", false, now)
	caFixture := writeFixture(t, dir, "devices", true, now)
	bundle, err := Load(serverFixture.files, caFixture.files, "localhost", now)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Public.MinVersion != tls.VersionTLS13 || bundle.Devices.MinVersion != tls.VersionTLS13 || bundle.Devices.ClientAuth != tls.RequireAndVerifyClientCert || bundle.Authority == nil {
		t.Fatal("TLS boundary configuration")
	}
	// Use real TLS sockets: a public connection needs no client identity, while
	// the separate listener refuses an absent or foreign device certificate.
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverFixture.certificate)
	public := startTLS(t, bundle.Public)
	defer public.Close()
	checkHandshake(t, public, &tls.Config{RootCAs: serverRoots, ServerName: "localhost", MinVersion: tls.VersionTLS13}, true)
	checkHandshake(t, public, &tls.Config{RootCAs: serverRoots, ServerName: "localhost", MaxVersion: tls.VersionTLS12}, false)
	devices := startTLS(t, bundle.Devices)
	defer devices.Close()
	checkHandshake(t, devices, &tls.Config{RootCAs: serverRoots, ServerName: "localhost", MinVersion: tls.VersionTLS13}, false)
	client := deviceCertificate(t, caFixture, now)
	checkHandshake(t, devices, &tls.Config{RootCAs: serverRoots, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{client}}, true)
	if _, err = Load(serverFixture.files, caFixture.files, "wrong.example", now); err == nil {
		t.Fatal("hostname mismatch accepted")
	}
	if err = os.Chmod(caFixture.files.PrivateKey, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(serverFixture.files, caFixture.files, "localhost", now); err == nil {
		t.Fatal("public CA private key accepted")
	}
}

func startTLS(t *testing.T, config *tls.Config) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = config.Clone()
	server.StartTLS()
	return server
}

func checkHandshake(t *testing.T, server *httptest.Server, config *tls.Config, success bool) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: config}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		if success {
			t.Fatalf("TLS refused authorized peer: %v", err)
		}
		return
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if !success || response.StatusCode != http.StatusNoContent {
		t.Fatalf("TLS success=%t status=%d", success, response.StatusCode)
	}
}

func deviceCertificate(t *testing.T, ca certificateFixture, now time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uris, err := identity.CredentialURIs(domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: uris}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
