package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
)

type boundOutput struct {
	mu    sync.Mutex
	data  bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (w *boundOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.data.Write(data)
	if bytes.Contains(data, []byte("\n")) {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}

func (w *boundOutput) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.data.Bytes())
}

func cliTLS(t *testing.T, parent string) (config.TLSFiles, config.TLSFiles, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require(t, err)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	require(t, err)
	certificate, err := x509.ParseCertificate(caDER)
	require(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, certificate, &leafKey.PublicKey, key)
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return writeCLIPair(t, parent, "server", der, leafKey), writeCLIPair(t, parent, "devices", caDER, key), roots
}

func writeCLIPair(t *testing.T, parent, name string, der []byte, key *ecdsa.PrivateKey) config.TLSFiles {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require(t, err)
	files := config.TLSFiles{Certificate: filepath.Join(parent, name+".pem"), PrivateKey: filepath.Join(parent, name+".key")}
	require(t, os.WriteFile(files.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require(t, os.WriteFile(files.PrivateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return files
}

func TestServeActualTLSLifecycleReportsBoundAndReleasesLeases(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	audit := filepath.Join(parent, "audit")
	require(t, os.Mkdir(audit, 0o700))
	public, devices, roots := cliTLS(t, parent)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	publicAddress := listener.Addr().String()
	require(t, listener.Close())
	_, port, err := net.SplitHostPort(publicAddress)
	require(t, err)
	cfg := config.Gateway{GatewayID: "gateway", PublicURL: "https://localhost:" + port, PublicAddress: publicAddress, DeviceAddress: "127.0.0.1:0", TLS: public, DeviceCA: devices, Database: filepath.Join(parent, "gateway.sqlite"), AdminSocket: filepath.Join(parent, "admin.sock"), AuditDirectory: audit, Identity: config.Identity{Issuer: "https://issuer.invalid/", JWKSURL: "https://issuer.invalid/keys", Audience: "https://localhost:" + port + "/mcp"}, ControlTimeoutSeconds: 5, HTTPTimeoutSeconds: 10}
	initCode, initOut, initDiagnostic := command(t, "init", "--database", cfg.Database)
	if initCode != 0 || initDiagnostic != "" {
		t.Fatal("explicit init failed")
	}
	var identity struct {
		Gateway string `json:"gateway_id"`
	}
	require(t, json.Unmarshal([]byte(initOut), &identity))
	cfg.GatewayID = identity.Gateway
	path := writePrivate(t, filepath.Join(parent, "config.json"), cfg)
	owned := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer owned.CloseIdleConnections()
	client := &http.Client{Transport: owned, Timeout: time.Second}
	for range 2 {
		serveCycle(t, path, cfg.PublicURL, client)
	}
}

func serveCycle(t *testing.T, path, origin string, client *http.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	output := &boundOutput{ready: make(chan struct{})}
	var diagnostic bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- Run(ctx, []string{"serve", "--config", path}, output, &diagnostic) }()
	var joined bool
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Error("CLI failed to join server")
			}
		}
	})
	select {
	case <-output.ready:
	case code := <-done:
		joined = true
		t.Fatalf("serve exited before bind output: %d %s", code, diagnostic.String())
	case <-time.After(10 * time.Second):
		t.Fatal("serve never reported bound")
	}
	var bound struct {
		State  string `json:"state"`
		Public string `json:"public"`
		Device string `json:"device"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output.bytes()))
	decoder.DisallowUnknownFields()
	require(t, decoder.Decode(&bound))
	if bound.State != "bound" || bound.Public == "" || bound.Device == "" {
		t.Fatal("bind metadata overclaimed readiness or exposed config")
	}
	waitMetadata(t, client, origin)
	cancel()
	select {
	case code := <-done:
		joined = true
		if code != 0 || diagnostic.Len() != 0 {
			t.Fatalf("graceful context shutdown failed: %d %s", code, diagnostic.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("CLI abandoned server ownership")
	}
}

func waitMetadata(t *testing.T, client *http.Client, origin string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+"/.well-known/oauth-protected-resource", nil)
		require(t, err)
		response, callErr := client.Do(request)
		if callErr == nil {
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			require(t, readErr)
			require(t, closeErr)
			if response.StatusCode == 200 {
				return
			}
		}
		select {
		case <-deadline.C:
			t.Fatal("bound server never answered actual HTTPS metadata")
		case <-ticker.C:
		}
	}
}
