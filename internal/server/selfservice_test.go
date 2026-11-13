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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

const managementScopes = "device:enroll device:manage"

type ownerFixtureAdmin struct{}

func (ownerFixtureAdmin) AuthorizeAdmin(ctx context.Context) error { return ctx.Err() }

func (f *fixture) owner(t *testing.T, subject string) domain.PrincipalID {
	t.Helper()
	if f.cfg.DeviceLogin == nil {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require(t, err)
		address := listener.Addr().String()
		require(t, listener.Close())
		_, port, err := net.SplitHostPort(address)
		require(t, err)
		f.cfg.DeviceAddress = address
		f.cfg.DeviceLogin = &config.DeviceLogin{NativeClientID: "public-native-client", DeviceWSSURL: "wss://localhost:" + port + "/device"}
	}
	s, err := registry.Open(t.Context(), f.cfg.Database, registry.Options{Gateway: domain.GatewayID(f.cfg.GatewayID), Admin: ownerFixtureAdmin{}})
	require(t, err)
	defer func() { require(t, s.Close()) }()
	p, err := s.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: f.cfg.Identity.Issuer, Subject: subject})
	require(t, err)
	require(t, s.PutOwnerPolicy(t.Context(), p.ID, domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 2}))
	return p.ID
}

func (f *fixture) scopedToken(t *testing.T, subject, scopes string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString(jsonBytes(t, jwtHeader{Algorithm: "RS256", Key: "key"}))
	body := base64.RawURLEncoding.EncodeToString(jsonBytes(t, jwtClaims{Issuer: f.cfg.Identity.Issuer, Audience: f.cfg.Identity.Audience, Subject: subject, Expires: time.Now().Add(time.Hour).Unix(), NotBefore: time.Now().Add(-time.Minute).Unix(), Scope: scopes}))
	unsigned := header + "." + body
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	require(t, err)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestSelfServiceDisabledRemainsAbsent(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	for _, path := range []string{contract.DescriptorPath, contract.EnrollmentPath, contract.RevocationPath} {
		status, _ := f.request(t, f.client, http.MethodPost, f.cfg.PublicURL+path, []byte(`{}`), "")
		if status != http.StatusNotFound {
			t.Fatal("disabled self-service route became public", status)
		}
	}
}

func TestPublicNativeDescriptorHasOnlyPublicConfiguredValues(t *testing.T) {
	f := configFixture(t)
	f.owner(t, "subject")
	f.start(t)
	status, data := f.request(t, f.client, http.MethodGet, f.cfg.PublicURL+contract.DescriptorPath, nil, "")
	if status != http.StatusOK {
		t.Fatalf("public descriptor status %d", status)
	}
	var descriptor contract.Descriptor
	require(t, protocol.DecodeStrict(data, &descriptor, contract.MaxBodyBytes))
	require(t, descriptor.Validate())
	if descriptor.GatewayID != f.cfg.GatewayID || descriptor.NativeClientID != "public-native-client" || descriptor.DeviceWSSURL != f.cfg.DeviceLogin.DeviceWSSURL || len(descriptor.SupportedWireVersions) != 2 || descriptor.SupportedWireVersions[0] != 1 || descriptor.SupportedWireVersions[1] != 2 || strings.Join(descriptor.Capabilities, ",") != "self-enrollment,owner-revocation,workspace-projects" {
		t.Fatal("descriptor disagreed with activated composition")
	}
	for _, private := range []string{f.cfg.Database, f.cfg.AdminSocket, f.cfg.TLS.PrivateKey, f.cfg.DeviceCA.PrivateKey, "PRIVATE KEY", "private-canary"} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatal("public descriptor exposed private material")
		}
	}
	status, data = f.request(t, f.client, http.MethodGet, f.cfg.PublicURL+"/.well-known/oauth-protected-resource", nil, "")
	if status != http.StatusOK {
		t.Fatal("MCP metadata unavailable")
	}
	var metadata struct {
		Scopes []string `json:"scopes_supported"`
	}
	require(t, json.Unmarshal(data, &metadata))
	if strings.Join(metadata.Scopes, " ") != "inventory:read task:dispatch task:read task:cancel" {
		t.Fatal("native management scopes changed MCP consent")
	}
}

func selfRequest(t *testing.T) (contract.EnrollmentRequest, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	require(t, err)
	return contract.EnrollmentRequest{RequestID: strings.Repeat("a", 32), Name: "private-canary-workstation", CSRDERBase64: base64.StdEncoding.EncodeToString(csr)}, key
}

func (f *fixture) selfEnroll(t *testing.T) (contract.EnrollmentResponse, tls.Certificate) {
	t.Helper()
	request, key := selfRequest(t)
	status, data := f.request(t, f.client, http.MethodPost, f.cfg.PublicURL+contract.EnrollmentPath, jsonBytes(t, request), f.scopedToken(t, "subject", managementScopes))
	if status != http.StatusOK {
		t.Fatalf("self enrollment: %d %s", status, data)
	}
	var response contract.EnrollmentResponse
	require(t, protocol.DecodeStrict(data, &response, contract.MaxBodyBytes))
	der, err := base64.StdEncoding.DecodeString(response.CertificateDERBase64)
	require(t, err)
	certificate, err := x509.ParseCertificate(der)
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(f.deviceCA.certificate)
	_, err = certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	require(t, err)
	return response, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: certificate}
}

func TestRealJWKSOwnerEnrollmentScopeIsolationAndReplay(t *testing.T) {
	f := configFixture(t)
	owner := f.owner(t, "subject")
	f.start(t)
	request, _ := selfRequest(t)
	endpoint := f.cfg.PublicURL + contract.EnrollmentPath
	for _, probe := range []struct {
		token  string
		status int
	}{
		{"private-canary", http.StatusUnauthorized},
		{f.token(t, f.cfg.Identity.Audience), http.StatusForbidden},
	} {
		status, data := f.request(t, f.client, http.MethodPost, endpoint, jsonBytes(t, request), probe.token)
		if status != probe.status {
			t.Fatalf("invalid/task-only token enrolled a device: %d", status)
		}
		assertNoCanary(t, data)
	}
	token := f.scopedToken(t, "subject", managementScopes)
	status, first := f.request(t, f.client, http.MethodPost, endpoint, jsonBytes(t, request), token)
	if status != http.StatusOK {
		t.Fatalf("management-only token failed enrollment: %d %s", status, first)
	}
	status, replay := f.request(t, f.client, http.MethodPost, endpoint, jsonBytes(t, request), token)
	if status != http.StatusOK || !bytes.Equal(first, replay) {
		t.Fatal("same request/CSR failed durable certificate replay", status)
	}
	var receipt contract.EnrollmentResponse
	require(t, json.Unmarshal(first, &receipt))
	if receipt.OwnerPrincipal != string(owner) || receipt.RequestID != request.RequestID || receipt.Generation != 1 {
		t.Fatal("issued owner identity was not derived from verified token")
	}
	changed, _ := selfRequest(t)
	status, _ = f.request(t, f.client, http.MethodPost, endpoint, jsonBytes(t, changed), token)
	if status != http.StatusConflict {
		t.Fatal("changed CSR reused an enrollment request", status)
	}
	for _, event := range routingAuditRecords(t, f) {
		encoded := jsonBytes(t, event)
		assertNoCanary(t, encoded)
		if bytes.Contains(encoded, []byte(token)) || bytes.Contains(encoded, []byte(request.CSRDERBase64)) {
			t.Fatal("audit captured token or CSR")
		}
	}
}

func TestRealOwnerRevocationDeniesOtherOwnerAndClosesDevice(t *testing.T) {
	f := configFixture(t)
	f.owner(t, "subject")
	f.owner(t, "other")
	f.start(t)
	receipt, certificate := f.selfEnroll(t)
	device := domain.DeviceID(receipt.DeviceID)
	endpoint := strings.Replace(f.deviceURL(t), "https://", "wss://", 1)
	connected := diagnosticDeviceDial(t, transport.ClientConfig{URL: endpoint, GatewayID: f.runtime.gatewayID, Certificate: certificate.Leaf, Capabilities: protocol.CapabilityReport{ObservedAt: time.Now()}, Routing: &emptyCensus{boot: strings.Repeat("a", 32)}}, f.deviceHTTP(t, &certificate))
	t.Cleanup(func() { require(t, connected.Close()) })
	ready, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	require(t, f.runtime.hub.WaitReady(ready, device))
	body := jsonBytes(t, contract.RevocationRequest{DeviceID: receipt.DeviceID})
	for _, probe := range []struct {
		token  string
		status int
	}{
		// Public denial deliberately hides owned-device existence.
		{f.scopedToken(t, "other", managementScopes), http.StatusForbidden},
		{f.token(t, f.cfg.Identity.Audience), http.StatusForbidden},
	} {
		status, _ := f.request(t, f.client, http.MethodPost, f.cfg.PublicURL+contract.RevocationPath, body, probe.token)
		if status != probe.status {
			t.Fatal("revocation authorization boundary", status)
		}
	}
	snapshot, err := f.runtime.hub.Snapshot(device)
	if got := checked(t, snapshot, err); !got.Online {
		t.Fatal("denied owner disconnected another device")
	}
	status, data := f.request(t, f.client, http.MethodPost, f.cfg.PublicURL+contract.RevocationPath, body, f.scopedToken(t, "subject", managementScopes))
	if status != http.StatusOK {
		t.Fatalf("owner revocation: %d %s", status, data)
	}
	var result contract.RevocationResponse
	require(t, json.Unmarshal(data, &result))
	if !result.Revoked || result.DeviceID != receipt.DeviceID {
		t.Fatal("revocation response lost device identity")
	}
	snapshot, err = f.runtime.hub.Snapshot(device)
	if err != nil && !errors.Is(err, transport.ErrOffline) {
		t.Fatal(err)
	}
	if err == nil && (snapshot.Online || snapshot.RoutingReady) {
		t.Fatal("committed self revocation retained an authorized session")
	}
	ref := domain.CredentialRef{Device: device, Epoch: domain.CredentialEpoch(receipt.Epoch), Generation: receipt.Generation}
	if _, err = f.runtime.store.CheckCredential(t.Context(), ref, time.Now()); err == nil {
		t.Fatal("revoked credential remained authorized")
	}
	if !f.runtime.Health().AuditHealthy || f.runtime.Health().MetricFailures != 0 {
		t.Fatal("self-service metadata failed sinks")
	}
}

type advertisedHostTransport struct {
	base http.RoundTripper
	host string
}

func (a advertisedHostTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Host = a.host
	return a.base.RoundTrip(copy)
}

func TestDeviceListenerUsesConfiguredPublicAuthorityAcrossPortMapping(t *testing.T) {
	f := configFixture(t)
	f.owner(t, "subject")
	f.cfg.DeviceLogin.DeviceWSSURL = "wss://localhost:443/device"
	f.start(t)
	receipt, certificate := f.selfEnroll(t)
	client := f.deviceHTTP(t, &certificate)
	status, _ := f.request(t, client, http.MethodGet, f.deviceURL(t), nil, "")
	if status != http.StatusForbidden {
		t.Fatal("private listener authority replaced configured public authority", status)
	}
	// Simulate port mapping without an external network: TLS still verifies the
	// same public hostname, and the HTTP Host preserves the advertised authority.
	mapped := *client
	mapped.Transport = advertisedHostTransport{base: client.Transport, host: "localhost:443"}
	connected := diagnosticDeviceDial(t, transport.ClientConfig{URL: strings.Replace(f.deviceURL(t), "https://", "wss://", 1), GatewayID: f.runtime.gatewayID, Certificate: certificate.Leaf, Capabilities: protocol.CapabilityReport{ObservedAt: time.Now()}, Routing: &emptyCensus{boot: strings.Repeat("a", 32)}}, &mapped)
	t.Cleanup(func() { require(t, connected.Close()) })
	ready, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	require(t, f.runtime.hub.WaitReady(ready, domain.DeviceID(receipt.DeviceID)))
}

type revokedStore struct {
	failure     error
	committed   bool
	afterCommit context.CancelFunc
}

func (s *revokedStore) RevokeOwnedDevice(context.Context, domain.Actor, domain.DeviceID) error {
	if s.failure != nil {
		return s.failure
	}
	s.committed = true
	if s.afterCommit != nil {
		s.afterCommit()
	}
	return nil
}

type cleanupSessions struct {
	store        *revokedStore
	calls        int
	beforeCommit bool
	cause        error
	wait         bool
}

func (s *cleanupSessions) DisconnectContext(ctx context.Context, _ domain.DeviceID) error {
	s.calls++
	s.beforeCommit = !s.store.committed
	if s.wait {
		<-ctx.Done()
		return ctx.Err()
	}
	return s.cause
}

func TestOwnerRevocationCommitSurvivesBoundedCleanupFailure(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	actor := domain.Actor{Principal: "principal", Scopes: domain.ScopeSet{domain.DeviceManage}}
	store := &revokedStore{}
	sessions := &cleanupSessions{store: store, wait: true}
	revoker := ownerRevoker{store: store, sessions: sessions, timeout: 20 * time.Millisecond, recorder: f.runtime.recorder}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	store.afterCommit = cancel // Simulate a lost caller immediately after commit.
	require(t, revoker.RevokeOwned(ctx, actor, "device"))
	if !store.committed || sessions.calls != 1 || sessions.beforeCommit {
		t.Fatal("socket cleanup preceded committed authorization invalidation")
	}
	var cleanup, revoked int
	for _, event := range routingAuditRecords(t, f) {
		if event.Code == observability.CredentialRevoked {
			revoked++
		}
		if event.Code == observability.RevocationCleanupUnavailable {
			cleanup++
			if event.Device != "device" || event.Principal != "principal" {
				t.Fatal("cleanup event lost bounded identity")
			}
		}
	}
	if cleanup != 1 || revoked != 1 {
		t.Fatal("committed mutation or bounded cleanup failure was hidden")
	}
	store.failure = domain.Reject(domain.NotFound)
	if err := revoker.RevokeOwned(t.Context(), actor, "device"); err == nil || sessions.calls != 1 {
		t.Fatal("denied revocation attempted cleanup")
	}
	store.failure = nil
	sessions.wait = false
	sessions.cause = transport.ErrNoSession
	require(t, revoker.RevokeOwned(t.Context(), actor, "device"))
	if countCleanupFailures(t, f) != 1 {
		t.Fatal("absent session fabricated a cleanup failure")
	}
}

func countCleanupFailures(t *testing.T, f *fixture) int {
	t.Helper()
	count := 0
	for _, event := range routingAuditRecords(t, f) {
		if event.Code == observability.RevocationCleanupUnavailable {
			count++
		}
	}
	return count
}
