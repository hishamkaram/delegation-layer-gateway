package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type routingAdmin struct{}

func (routingAdmin) AuthorizeAdmin(ctx context.Context) error { return ctx.Err() }

// Real SQLite routing/credential authority and real mTLS. The fixture does not
// run Delegate or prove MCP grants/provider compatibility.
type routedFixture struct {
	gateway     domain.GatewayID
	path        string
	store       *registry.Store
	hub         *Hub
	server      *httptest.Server
	http        *http.Client
	certificate *x509.Certificate
	credential  domain.CredentialRef
	clock       *clock
}

func newRoutedFixture(t *testing.T) *routedFixture {
	t.Helper()
	return routedFixtureOptions(t, nil, false)
}

func routedFixtureOptions(t *testing.T, decorate func(RoutingAuthority) RoutingAuthority, recovery bool) *routedFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	lease, leaseErr := instance.Acquire(path + ".lock")
	if leaseErr != nil {
		t.Fatal(leaseErr)
	}
	t.Cleanup(func() {
		if closeErr := lease.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	store, storeErr := registry.Create(t.Context(), path, registry.CreateOptions{Admin: routingAdmin{}})
	if storeErr != nil {
		t.Fatal(storeErr)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	generatedID, identityErr := store.Identity(t.Context())
	if identityErr != nil {
		t.Fatal(identityErr)
	}
	caCertificate, certificate, ref := issueRoutingCredential(t, store, now, recovery)
	ownedClock := &clock{value: now.Add(time.Millisecond)}
	authority := RoutingAuthority(store)
	if decorate != nil {
		authority = decorate(store)
	}
	hub, hubErr := newTestHub(t, t.Context(), Config{GatewayID: generatedID, BootEpoch: "boot-one", Routing: authority}, store, ownedClock.now)
	if hubErr != nil {
		t.Fatal(hubErr)
	}
	t.Cleanup(func() {
		if closeErr := hub.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	server := httptest.NewUnstartedServer(hub)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := *server.Client()
	httpTransport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected fixture HTTP transport")
	}
	owned := httpTransport.Clone()
	owned.TLSClientConfig = httpTransport.TLSClientConfig.Clone()
	owned.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	client.Transport = owned
	t.Cleanup(owned.CloseIdleConnections)
	return &routedFixture{gateway: generatedID, path: path, store: store, hub: hub, server: server, http: &client, certificate: certificate.Leaf, credential: ref, clock: ownedClock}
}

func issueRoutingCredential(t *testing.T, store *registry.Store, now time.Time, recovery bool) (*x509.Certificate, tls.Certificate, domain.CredentialRef) {
	t.Helper()
	caKey := privateKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "routing device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, caErr := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if caErr != nil {
		t.Fatal(caErr)
	}
	caCertificate := parseCertificate(t, caDER)
	ca, authorityErr := devicecert.NewCertificateAuthority(caCertificate, caKey)
	if authorityErr != nil {
		t.Fatal(authorityErr)
	}
	key := privateKey(t)
	csr, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if csrErr != nil {
		t.Fatal(csrErr)
	}
	info, infoErr := devicecert.ParseCSR(csr)
	if infoErr != nil {
		t.Fatal(infoErr)
	}
	if _, registerErr := store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "device-one", Name: "routing fixture"}); registerErr != nil {
		t.Fatal(registerErr)
	}
	mode := domain.Regular
	if recovery {
		if _, recoveryErr := store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "recovery-one", Epoch: "epoch-two", Now: now}); recoveryErr != nil {
			t.Fatal(recoveryErr)
		}
		mode = domain.RecoveryOnly
	}
	token := domain.Hash([]byte("owned routing enrollment"))
	serial := make([]byte, 16)
	serial[0] = 1
	if grantErr := store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: token, Device: "device-one", Mode: mode, Generation: 1, CreatedAt: now, ExpiresAt: now.Add(domain.EnrollmentTTL)}); grantErr != nil {
		t.Fatal(grantErr)
	}
	intent, intentErr := store.BeginEnrollment(t.Context(), domain.EnrollmentAttempt{TokenHash: token, CSRHash: info.CSRHash, PublicKeyHash: info.PublicKeyHash, Issuance: "fixture-issuance", Serial: serial, Now: now})
	if intentErr != nil {
		t.Fatal(intentErr)
	}
	leafDER, signErr := ca.Sign(t.Context(), intent, csr, new(big.Int).SetBytes(serial), rand.Reader)
	if signErr != nil {
		t.Fatal(signErr)
	}
	if _, completeErr := store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: leafDER, Now: now}); completeErr != nil {
		t.Fatal(completeErr)
	}
	leaf := parseCertificate(t, leafDER)
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key, Leaf: leaf}
	return caCertificate, certificate, intent.Credential
}

// censusPeer represents the low-level connector ownership port. Service/CLI
// census races are covered separately by real helper-process connector tests.
type censusPeer struct {
	mu        sync.Mutex
	boot      string
	active    []protocol.ControlCall
	inventory *protocol.ControlInventory
	ack       protocol.ControlInventoryAck
}

func newCensusPeer() *censusPeer { return &censusPeer{boot: strings.Repeat("a", 32)} }
func (p *censusPeer) Inventory(ctx context.Context, g domain.ConnectionGeneration) (protocol.ControlInventory, error) {
	if ctx.Err() != nil {
		return protocol.ControlInventory{}, ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	wire := wireGeneration(g)
	if p.inventory != nil && p.inventory.Generation == wire {
		return cloneCensus(*p.inventory), nil
	}
	report := protocol.ControlInventory{PolicyVersion: protocol.RoutingPolicyVersion, ProcessBoot: p.boot, BarrierID: strings.Repeat("b", 32), Generation: wire, Complete: true, Active: append([]protocol.ControlCall(nil), p.active...)}
	p.inventory = &report
	return cloneCensus(report), nil
}

func cloneCensus(report protocol.ControlInventory) protocol.ControlInventory {
	report.Active = append([]protocol.ControlCall(nil), report.Active...)
	return report
}

func (p *censusPeer) Acknowledge(ctx context.Context, ack protocol.ControlInventoryAck) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ack = ack
	return nil
}

func (f *routedFixture) dial(t *testing.T, p ConnectorRouting) *Client {
	t.Helper()
	client, dialErr := Dial(t.Context(), ClientConfig{URL: "wss" + strings.TrimPrefix(f.server.URL, "https"), GatewayID: f.gateway, Certificate: f.certificate, Capabilities: protocol.CapabilityReport{ObservedAt: f.clock.now()}, Routing: p}, f.http, f.clock.now)
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if readyErr := f.hub.WaitReady(ctx, "device-one"); readyErr != nil {
		t.Fatal(readyErr)
	}
	return client
}

func (f *routedFixture) prepare(t *testing.T, frame protocol.Frame) *Reservation {
	t.Helper()
	r, reserveErr := f.hub.Reserve(t.Context(), "device-one", frame)
	if reserveErr != nil {
		t.Fatal(reserveErr)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if releaseErr := r.ReleaseUnused(ctx); releaseErr != nil {
			t.Error(releaseErr)
		}
	})
	route, routeErr := r.Routing()
	if routeErr != nil {
		t.Fatal(routeErr)
	}
	if acquireErr := f.store.AcquireRouting(t.Context(), route); acquireErr != nil {
		t.Fatal(acquireErr)
	}
	if armErr := r.ArmRouting(route); armErr != nil {
		t.Fatal(armErr)
	}
	return r
}

func (f *routedFixture) status(t *testing.T, g domain.ConnectionGeneration) routing.Readiness {
	t.Helper()
	status, statusErr := f.store.CheckRoutingReadiness(t.Context(), f.credential, g, f.clock.now())
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	return status
}

func (f *routedFixture) reply(t *testing.T, received *Received, disposition protocol.ControlDisposition) {
	t.Helper()
	completion := protocol.ControlCompletion{ProcessBoot: strings.Repeat("a", 32), Call: received.ControlCall(), Disposition: disposition}
	reply := protocol.Reply{Operation: completion.Call.Operation, Error: &protocol.Failure{Code: "pending", Retryable: true}}
	if replyErr := received.ReplyControl(t.Context(), reply, completion); replyErr != nil {
		t.Fatal(replyErr)
	}
}
