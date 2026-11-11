package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func checked[T any](t *testing.T, value T, err error) T { t.Helper(); require(t, err); return value }

func jsonBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	return checked(t, data, err)
}

type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	files       config.TLSFiles
}

func certificateAuthority(t *testing.T, parent, name string) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	private := checked(t, key, err)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-40 * 24 * time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	data := checked(t, der, err)
	cert, err := x509.ParseCertificate(data)
	return authority{certificate: checked(t, cert, err), key: private, files: writePair(t, parent, name, data, private)}
}

func writePair(t *testing.T, parent, name string, der []byte, key *ecdsa.PrivateKey) config.TLSFiles {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require(t, err)
	files := config.TLSFiles{Certificate: filepath.Join(parent, name+".pem"), PrivateKey: filepath.Join(parent, name+".key")}
	require(t, os.WriteFile(files.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require(t, os.WriteFile(files.PrivateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return files
}

func serverPair(t *testing.T, parent string, ca authority) config.TLSFiles {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	private := checked(t, key, err)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-40 * 24 * time.Hour), NotAfter: now.AddDate(1, 0, 0), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &private.PublicKey, ca.key)
	return writePair(t, parent, "server", checked(t, der, err), private)
}

type (
	jwtHeader struct {
		Algorithm string `json:"alg"`
		Key       string `json:"kid"`
	}
	jwtClaims struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Audience  string `json:"aud"`
		Expires   int64  `json:"exp"`
		NotBefore int64  `json:"nbf"`
		Scope     string `json:"scope"`
	}
	jwkDocument struct {
		Keys []jwkKey `json:"keys"`
	}
	jwkKey struct {
		Type      string `json:"kty"`
		Algorithm string `json:"alg"`
		Use       string `json:"use"`
		Key       string `json:"kid"`
		Modulus   string `json:"n"`
		Exponent  string `json:"e"`
	}
	fixture struct {
		cfg                config.Gateway
		runtime            *Runtime
		client             *http.Client
		admin              *http.Client
		jwks               *httptest.Server
		key                *rsa.PrivateKey
		publicCA, deviceCA authority
		cancel             context.CancelFunc
		join               func()
		now                func() time.Time
	}
)

func configFixture(t *testing.T) *fixture {
	t.Helper()
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	audit := filepath.Join(parent, "audit")
	require(t, os.Mkdir(audit, 0o700))
	f := &fixture{publicCA: certificateAuthority(t, parent, "public-ca"), deviceCA: certificateAuthority(t, parent, "device-ca"), now: time.Now}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	f.key = checked(t, key, err)
	keys := jsonBytes(t, jwkDocument{Keys: []jwkKey{{Type: "RSA", Algorithm: "RS256", Use: "sig", Key: "key", Modulus: base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), Exponent: "AQAB"}}})
	f.jwks = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, writeErr := w.Write(keys); writeErr != nil {
			return
		}
	}))
	t.Cleanup(f.jwks.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	port := checked(t, listener, err).Addr().String()
	require(t, listener.Close())
	_, number, err := net.SplitHostPort(port)
	require(t, err)
	origin := "https://localhost:" + number
	f.cfg = config.Gateway{GatewayID: "gateway", PublicURL: origin, PublicAddress: port, DeviceAddress: "127.0.0.1:0", TLS: serverPair(t, parent, f.publicCA), DeviceCA: f.deviceCA.files, Database: filepath.Join(parent, "gateway.sqlite"), AdminSocket: filepath.Join(parent, "admin.sock"), AuditDirectory: audit, Identity: config.Identity{Issuer: f.jwks.URL + "/", JWKSURL: f.jwks.URL + "/keys", Audience: origin + "/mcp"}, ControlTimeoutSeconds: 5, HTTPTimeoutSeconds: 10}
	created, createErr := registry.Create(t.Context(), f.cfg.Database, registry.CreateOptions{})
	require(t, createErr)
	generatedID, identityErr := created.Identity(t.Context())
	require(t, identityErr)
	require(t, created.Close())
	f.cfg.GatewayID = string(generatedID)
	roots := x509.NewCertPool()
	roots.AddCert(f.publicCA.certificate)
	owned := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	f.client = &http.Client{Transport: owned, Timeout: 10 * time.Second}
	t.Cleanup(owned.CloseIdleConnections)
	adminTransport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", f.cfg.AdminSocket)
	}}
	f.admin = &http.Client{Transport: adminTransport, Timeout: 10 * time.Second}
	t.Cleanup(adminTransport.CloseIdleConnections)
	return f
}

func (f *fixture) construct(t *testing.T) {
	t.Helper()
	runtime, err := New(t.Context(), f.cfg, Options{Now: f.now, JWKSClient: f.jwks.Client()})
	f.runtime = checked(t, runtime, err)
}

func (f *fixture) start(t *testing.T) { t.Helper(); f.construct(t); f.serve(t) }

func (f *fixture) serve(t *testing.T) {
	t.Helper()
	runtime := f.runtime
	ctx, cancel := context.WithCancel(t.Context())
	f.cancel = cancel
	done := make(chan struct{})
	var final error
	go func() { final = runtime.Serve(ctx); close(done) }()
	var once sync.Once
	f.join = func() {
		once.Do(func() {
			cancel()
			require(t, runtime.Close())
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("server failed to join owned resources")
			}
			if final != nil && !errors.Is(final, context.Canceled) {
				t.Errorf("server shutdown: %v", final)
			}
		})
	}
	t.Cleanup(f.join)
	// Listener bind precedes Serve; this actual request synchronizes startup.
	status, _ := f.request(t, f.client, http.MethodGet, f.cfg.PublicURL+"/.well-known/oauth-protected-resource", nil, "")
	if status != 200 {
		t.Fatal("metadata startup probe failed")
	}
}

func (f *fixture) token(t *testing.T, audience string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString(jsonBytes(t, jwtHeader{Algorithm: "RS256", Key: "key"}))
	body := base64.RawURLEncoding.EncodeToString(jsonBytes(t, jwtClaims{Issuer: f.cfg.Identity.Issuer, Audience: audience, Subject: "subject", Expires: time.Now().Add(time.Hour).Unix(), NotBefore: time.Now().Add(-time.Minute).Unix(), Scope: "inventory:read task:read task:dispatch task:cancel"}))
	unsigned := header + "." + body
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	require(t, err)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (f *fixture) request(t *testing.T, client *http.Client, method, url string, body []byte, token string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
	require(t, err)
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	require(t, err)
	defer func() { require(t, response.Body.Close()) }()
	data, err := io.ReadAll(response.Body)
	require(t, err)
	return response.StatusCode, data
}

func (f *fixture) adminCall(t *testing.T, path string, input, out any) {
	t.Helper()
	status, data := f.request(t, f.admin, http.MethodPost, "http://unix"+path, jsonBytes(t, input), "")
	if status != 200 {
		t.Fatalf("admin %s: %d %s", path, status, data)
	}
	if out != nil {
		require(t, json.Unmarshal(data, out))
	}
}

func assertNoCanary(t *testing.T, data []byte) {
	t.Helper()
	if strings.Contains(string(data), "private-canary") {
		t.Fatal("metadata leaked private canary")
	}
}
