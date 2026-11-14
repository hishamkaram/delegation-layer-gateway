package devicehub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

type (
	Settings              = transport.Settings
	ConnectionObservation = transport.ConnectionObservation
	CredentialStore       = transport.CredentialStore
)

const (
	ConnectionFailed      = transport.ConnectionFailed
	ConnectionEstablished = transport.ConnectionEstablished
	ConnectionClosed      = transport.ConnectionClosed
)

var (
	ErrConflict  = transport.ErrConflict
	ErrForbidden = transport.ErrForbidden
)

type clock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.value }

type credentialStore struct {
	mu      sync.Mutex
	value   domain.Credential
	revoked bool
	counter uint64
}

func (s *credentialStore) CheckCredential(ctx context.Context, ref domain.CredentialRef, now time.Time) (domain.Credential, error) {
	if checkErr := ctx.Err(); checkErr != nil {
		return domain.Credential{}, checkErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || ref != s.value.Ref || now.Before(s.value.NotBefore) || !now.Before(s.value.NotAfter) {
		return domain.Credential{}, domain.Reject(domain.Forbidden)
	}
	return s.value, nil
}

func (s *credentialStore) NextConnectionGeneration(ctx context.Context, ref domain.CredentialRef, boot domain.BootEpoch, now time.Time) (domain.ConnectionGeneration, error) {
	if _, checkErr := s.CheckCredential(ctx, ref, now); checkErr != nil {
		return domain.ConnectionGeneration{}, checkErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	return domain.ConnectionGeneration{BootEpoch: boot, Counter: s.counter}, nil
}
func (s *credentialStore) revoke() { s.mu.Lock(); defer s.mu.Unlock(); s.revoked = true }

type fixture struct {
	hub         *Hub
	server      *httptest.Server
	http        *http.Client
	certificate *x509.Certificate
	clock       *clock
	store       *credentialStore
	settings    transport.Settings
	probes      *sync.WaitGroup
}

func privateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func parseCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func newFixture(t *testing.T, settings transport.Settings) *fixture {
	t.Helper()
	probes := new(sync.WaitGroup)
	t.Cleanup(probes.Wait)
	now := time.Now().UTC().Truncate(time.Second)
	caKey := privateKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate := parseCertificate(t, caDER)
	ca, err := devicecert.NewCertificateAuthority(caCertificate, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key := privateKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := devicecert.ParseCSR(csr)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.CredentialRef{Device: "device-one", Epoch: "epoch-one", Generation: 1}
	intent := domain.IssuanceIntent{ID: "issuance-one", Credential: ref, Mode: domain.Regular, Serial: []byte{1, 2, 3}, CSRHash: info.CSRHash, PublicKeyHash: info.PublicKeyHash, NotBefore: now, NotAfter: now.Add(domain.CertificateLifetime)}
	leafDER, err := ca.Sign(t.Context(), intent, csr, new(big.Int).SetBytes(intent.Serial), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseCertificate(t, leafDER)
	clock := &clock{value: time.Now()}
	store := &credentialStore{value: domain.Credential{Ref: ref, Mode: domain.Regular, PublicKeyHash: info.PublicKeyHash, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}}
	hub, err := NewHub(t.Context(), Config{GatewayID: "gateway-one", BootEpoch: "boot-one", Settings: settings}, store, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := hub.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	server := httptest.NewUnstartedServer(hub)
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	httpClient := *server.Client()
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected test transport")
	}
	owned := transport.Clone()
	owned.TLSClientConfig = transport.TLSClientConfig.Clone()
	owned.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key, Leaf: leaf}}
	httpClient.Transport = owned
	t.Cleanup(owned.CloseIdleConnections)
	f := &fixture{hub: hub, server: server, http: &httpClient, certificate: leaf, clock: clock, store: store, settings: settings, probes: probes}
	return f
}

func (f *fixture) config() transport.ClientConfig {
	return transport.ClientConfig{URL: "wss" + strings.TrimPrefix(f.server.URL, "https"), GatewayID: "gateway-one", Certificate: f.certificate, Capabilities: protocol.CapabilityReport{ObservedAt: f.clock.now()}, Settings: f.settings}
}

func (f *fixture) dial(t *testing.T) *transport.Client {
	t.Helper()
	client, err := transport.Dial(t.Context(), f.config(), f.http, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if checkErr := f.hub.WaitReady(ctx, "device-one"); checkErr != nil {
		t.Fatal(checkErr)
	}
	return client
}

func inspect(t *testing.T) protocol.Frame {
	t.Helper()
	inner, err := protocol.Encode(protocol.InspectRequest{GatewayID: "gateway-one"}, protocol.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.Encode(protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: inner}, protocol.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Frame{Version: protocol.Version, Type: protocol.Request, OperationID: "operation-one", TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload}
}
