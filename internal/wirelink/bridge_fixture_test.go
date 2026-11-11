package wirelink_test

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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/testsupport"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
	"github.com/hishamkaram/delegation-layer-gateway/internal/wirelink"
)

type fixtureAdmin struct{}

func (fixtureAdmin) AuthorizeAdmin(ctx context.Context) error { return ctx.Err() }
func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustValue[T any](t *testing.T, value T, err error) T { t.Helper(); mustOK(t, err); return value }

func fixtureKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return mustValue(t, key, err)
}

func fixtureCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	return mustValue(t, cert, err)
}

// This peer reports an empty, fenced process census. It models only protocol
// ownership; it does not execute Delegate or prove physical task closure.
type censusPeer struct{}

func (censusPeer) Inventory(ctx context.Context, g domain.ConnectionGeneration) (protocol.ControlInventory, error) {
	return protocol.ControlInventory{PolicyVersion: protocol.RoutingPolicyVersion, ProcessBoot: strings.Repeat("a", 32), BarrierID: strings.Repeat("b", 32), Generation: protocol.Generation{BootEpoch: string(g.BootEpoch), Counter: g.Counter}, Complete: true}, ctx.Err()
}

func (censusPeer) Acknowledge(ctx context.Context, _ protocol.ControlInventoryAck) error {
	return ctx.Err()
}

type bridgeFixture struct {
	gateway domain.GatewayID
	store   *registry.Store
	hub     *transport.Hub
	client  *transport.Client
	link    *wirelink.Link
	service *gateway.Service
	actor   domain.Actor
	ref     domain.CredentialRef
	now     time.Time
}

func newBridgeFixture(t *testing.T) *bridgeFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second).Add(time.Millisecond)
	store, err := registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.sqlite"), registry.CreateOptions{Admin: fixtureAdmin{}})
	mustOK(t, err)
	t.Cleanup(func() { mustOK(t, store.Close()) })
	generatedID, identityErr := store.Identity(t.Context())
	if identityErr != nil {
		t.Fatal(identityErr)
	}
	ca, cert, ref := issueRoutingCredential(t, store, now.Truncate(time.Second))
	principal, err := store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "alice"})
	mustOK(t, err)
	actor := domain.Actor{Principal: principal.ID, Scopes: domain.ScopeSet{domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}}
	dest := domain.Destination{Device: "device-one", Project: "project-one"}
	contextBinding := protocol.ContextBinding{Root: protocol.WireContextGuard("root"), Project: protocol.WireContextGuard("project")}
	mustOK(t, store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: dest, Context: domain.ContextBinding{Root: domain.RootGuard(contextBinding.Root), Project: domain.ProjectGuard(contextBinding.Project)}}))
	mustOK(t, store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: actor.Principal, Destination: dest}, Scopes: actor.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 300}}))
	initialConnection, connectionErr := store.NextConnectionGeneration(t.Context(), ref, "fixture-root-boot", now)
	mustOK(t, connectionErr)
	root := testsupport.OpenRoot(t, t.Context(), store, domain.RootInitializationStart{Route: dest, ExpectedContext: domain.ContextBinding{Root: domain.RootGuard(contextBinding.Root), Project: domain.ProjectGuard(contextBinding.Project)}, Credential: ref, Connection: initialConnection, Now: now})
	hub, err := transport.NewHub(t.Context(), transport.Config{GatewayID: generatedID, BootEpoch: "boot-one", Routing: store}, store, func() time.Time { return now })
	mustOK(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := httptest.NewUnstartedServer(hub)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(func() { mustOK(t, hub.Close()) })
	base, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected fixture transport")
	}
	owned := base.Clone()
	owned.TLSClientConfig = base.TLSClientConfig.Clone()
	owned.TLSClientConfig.Certificates = []tls.Certificate{cert}
	t.Cleanup(owned.CloseIdleConnections)
	caps := protocol.CapabilityReport{ObservedAt: now, Projects: []protocol.ProjectCapability{{Alias: "project-one", Context: contextBinding, AdmissionGeneration: string(root.Generation), AdmissionOpen: true, ContractVersion: protocol.Version, Features: []string{"namespace-admission-v1"}, Providers: []protocol.ProviderCapability{{Provider: "provider", Permissions: []string{"read-only"}, MaxBudgetSeconds: 300, Authentication: "unknown"}}, Ready: true}}}
	client, err := transport.Dial(t.Context(), transport.ClientConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https"), GatewayID: generatedID, Certificate: cert.Leaf, Capabilities: caps, Routing: censusPeer{}}, &http.Client{Transport: owned}, func() time.Time { return now })
	mustOK(t, err)
	t.Cleanup(func() { mustOK(t, client.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	mustOK(t, hub.WaitReady(ctx, "device-one"))
	link, err := wirelink.New(hub)
	mustOK(t, err)
	service, err := gateway.New(store, link, generatedID, rand.Reader, func() time.Time { return now })
	mustOK(t, err)
	return &bridgeFixture{gateway: generatedID, store: store, hub: hub, client: client, link: link, service: service, actor: actor, ref: ref, now: now}
}

func issueRoutingCredential(t *testing.T, store *registry.Store, now time.Time) (*x509.Certificate, tls.Certificate, domain.CredentialRef) {
	t.Helper()
	caKey := fixtureKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "routing device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, caErr := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if caErr != nil {
		t.Fatal(caErr)
	}
	caCertificate := fixtureCertificate(t, caDER)
	ca, authorityErr := identity.NewCertificateAuthority(caCertificate, caKey)
	if authorityErr != nil {
		t.Fatal(authorityErr)
	}
	key := fixtureKey(t)
	csr, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if csrErr != nil {
		t.Fatal(csrErr)
	}
	info, infoErr := identity.ParseCSR(csr)
	if infoErr != nil {
		t.Fatal(infoErr)
	}
	if _, registerErr := store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "device-one", Name: "routing fixture"}); registerErr != nil {
		t.Fatal(registerErr)
	}
	token := domain.Hash([]byte("owned routing enrollment"))
	serial := make([]byte, 16)
	serial[0] = 1
	if grantErr := store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: token, Device: "device-one", Mode: domain.Regular, Generation: 1, CreatedAt: now, ExpiresAt: now.Add(domain.EnrollmentTTL)}); grantErr != nil {
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
	leaf := fixtureCertificate(t, leafDER)
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key, Leaf: leaf}
	return caCertificate, certificate, intent.Credential
}
