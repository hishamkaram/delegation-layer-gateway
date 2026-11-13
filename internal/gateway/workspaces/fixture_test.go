package workspaces_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/devicehub"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
	"github.com/hishamkaram/delegation-layer-gateway/internal/wirelink"
)

func require(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type fixtureAdmin struct{}

func (fixtureAdmin) AuthorizeAdmin(ctx context.Context) error { return ctx.Err() }

type census struct{}

func (census) Inventory(ctx context.Context, g domain.ConnectionGeneration) (protocol.ControlInventory, error) {
	return protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: strings.Repeat("a", 32), BarrierID: strings.Repeat("b", 32), Generation: protocol.Generation{BootEpoch: string(g.BootEpoch), Counter: g.Counter}, Complete: true}, ctx.Err()
}

func (census) Acknowledge(ctx context.Context, _ protocol.ControlInventoryAck) error {
	return ctx.Err()
}

// The fixture uses real self-enrollment, SQLite, mTLS/WSS2, routing permits and
// the existing root initializer. Its peer models Native namespace/pin replies;
// it executes no Native binary, provider or task.
type fixture struct {
	store                     *registry.Store
	backend                   *workspaces.Service
	actor                     domain.Actor
	gateway                   domain.GatewayID
	root                      domain.RootGuard
	workspace                 protocol.WorkspaceBinding
	device                    domain.DeviceID
	hub                       *devicehub.Hub
	peer                      *transport.Client
	link                      *wirelink.Link
	controls                  *gateway.MetadataControls
	observations              observationLog
	registerFailures          atomic.Int32
	resolveCalls              atomic.Int32
	inspectCalls              atomic.Int32
	barrierCalls              atomic.Int32
	policyRevision            atomic.Uint64
	conflictingHistory        atomic.Bool
	removeDispatchBeforeReply atomic.Bool
	origin                    *protocol.OriginStateReport // peer worker owns this and pins
	pins                      map[string]protocol.ResolvedProject
}

func ownerPolicy() domain.OwnerPolicy {
	return domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 4}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{root: domain.RootGuard(protocol.WireContextGuard("fixture native root")), workspace: protocol.WorkspaceBinding{ID: "work", Guard: protocol.WireContextGuard("fixture approved workspace")}, pins: make(map[string]protocol.ResolvedProject)}
	f.policyRevision.Store(1)
	var err error
	f.store, err = registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.sqlite"), registry.CreateOptions{Admin: fixtureAdmin{}})
	require(t, err)
	t.Cleanup(func() { require(t, f.store.Close()) })
	f.gateway, err = f.store.Identity(t.Context())
	require(t, err)
	principal, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://fixture.example/", Subject: "owner"})
	require(t, err)
	f.actor = domain.Actor{Principal: principal.ID, Scopes: domain.ScopeSet{domain.DeviceEnroll, domain.DeviceManage, domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}}
	require(t, f.store.PutOwnerPolicy(t.Context(), principal.ID, ownerPolicy()))
	ca, certificate, ref := f.enroll(t)
	f.device = ref.Device
	f.connect(t, ca, certificate)
	f.backend = f.service(t, &failingRegistration{Store: f.store, f: f})
	return f
}

func fixtureKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require(t, err)
	return key
}

func (f *fixture) enroll(t *testing.T) (*x509.Certificate, tls.Certificate, domain.CredentialRef) {
	t.Helper()
	key := fixtureKey(t)
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "workspace fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require(t, err)
	ca, err := x509.ParseCertificate(der)
	require(t, err)
	signer, err := devicecert.NewCertificateAuthority(ca, key)
	require(t, err)
	deviceKey := fixtureKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, deviceKey)
	require(t, err)
	issuer, err := enrollment.NewSelf(f.store, signer, rand.Reader, time.Now)
	require(t, err)
	receipt, err := issuer.SelfEnroll(t.Context(), f.actor, domain.RequestID(strings.Repeat("c", 32)), "Workspace fixture device", csr, "", 0)
	require(t, err)
	leaf, err := x509.ParseCertificate(receipt.CertificateDER)
	require(t, err)
	return ca, tls.Certificate{Certificate: [][]byte{receipt.CertificateDER, der}, PrivateKey: deviceKey, Leaf: leaf}, receipt.Intent.Credential
}

func (f *fixture) connect(t *testing.T, ca *x509.Certificate, certificate tls.Certificate) {
	t.Helper()
	var err error
	f.hub, err = devicehub.NewHub(t.Context(), devicehub.Config{EnableWireV2: true, GatewayID: f.gateway, BootEpoch: "workspace-fixture-boot", Routing: f.store}, f.store, time.Now)
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := httptest.NewUnstartedServer(f.hub)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(func() { require(t, f.hub.Close()) })
	base, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected TLS fixture transport")
	}
	owned := base.Clone()
	owned.TLSClientConfig = base.TLSClientConfig.Clone()
	owned.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	t.Cleanup(owned.CloseIdleConnections)
	report := protocol.CapabilityReportV2{ObservedAt: time.Now(), Root: &protocol.RootCapability{Root: string(f.root), ContractVersion: 1, Features: []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease, protocol.WorkspaceFeature}}, Workspaces: []protocol.WorkspaceCapability{{WorkspaceBinding: f.workspace, Name: "code", PolicyRevision: 1}}, ProjectBudget: &protocol.ProjectBudget{Limit: 1024, ByteLimit: 4 << 20}}
	f.peer, err = transport.Dial(t.Context(), transport.ClientConfig{WireVersion: 2, URL: "wss" + strings.TrimPrefix(server.URL, "https"), GatewayID: f.gateway, Certificate: certificate.Leaf, CapabilitiesV2: &report, Routing: census{}}, &http.Client{Transport: owned}, time.Now)
	require(t, err)
	t.Cleanup(func() { require(t, f.peer.Close()) })
	ready, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	require(t, f.hub.WaitReady(ready, f.device))
	f.link, err = wirelink.New(f.hub)
	require(t, err)
	f.controls, err = gateway.NewMetadataControls(f.link, time.Now, gateway.RoutingObserverFunc(f.observations.record))
	require(t, err)
	lifetime, stop := context.WithCancel(t.Context())
	joined := make(chan error, 1)
	go func() { joined <- f.run(lifetime) }()
	t.Cleanup(func() {
		stop()
		require(t, f.peer.Close())
		select {
		case final := <-joined:
			if final != nil && !errors.Is(final, context.Canceled) && !errors.Is(final, transport.ErrOffline) {
				t.Error(final)
			}
		case <-time.After(10 * time.Second):
			t.Error("fixture peer did not join")
		}
	})
}

type observationLog struct {
	mu     sync.Mutex
	values []gateway.RoutingObservation
}

func (o *observationLog) record(value gateway.RoutingObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.values = append(o.values, value)
}

func (o *observationLog) snapshot() []gateway.RoutingObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]gateway.RoutingObservation(nil), o.values...)
}

func (f *fixture) service(t *testing.T, store workspaces.Store) *workspaces.Service {
	t.Helper()
	service, err := workspaces.New(workspaces.Options{Store: store, Presence: f.link, Controls: f.controls, GatewayID: f.gateway, Now: time.Now, Roots: func(ctx context.Context, binding domain.OwnedRootBinding) (workspaces.Initializer, error) {
		port, portErr := registry.NewOwnedRootPort(ctx, f.store, binding, time.Now)
		if portErr != nil {
			return nil, portErr
		}
		return recovery.NewOwnedInitializer(port, f.link, f.gateway, time.Now, gateway.RoutingObserverFunc(func(gateway.RoutingObservation) {}))
	}})
	require(t, err)
	return service
}

type failingRegistration struct {
	*registry.Store
	f *fixture
}

func (s *failingRegistration) RegisterResolvedProject(ctx context.Context, actor domain.Actor, input domain.ProjectResolutionCheck) (domain.ProjectResolution, error) {
	if s.f.registerFailures.CompareAndSwap(1, 0) {
		return domain.ProjectResolution{}, domain.Reject(domain.Pending)
	}
	return s.Store.RegisterResolvedProject(ctx, actor, input)
}

func (f *fixture) run(ctx context.Context) error {
	for {
		received, err := f.peer.Receive(ctx)
		if err != nil {
			return err
		}
		frame, err := received.Claim(ctx)
		if err != nil {
			return err
		}
		command, err := protocol.DecodeCommandVersion(frame, 2)
		if err != nil {
			return err
		}
		response, err := f.response(ctx, command)
		if err != nil {
			return err
		}
		body, err := protocol.Encode(response, protocol.MaxFrameBytes)
		if err != nil {
			return err
		}
		reply, stop := context.WithTimeout(ctx, 5*time.Second)
		err = received.ReplyControl(reply, protocol.Reply{Operation: command.Operation, Body: body}, protocol.ControlCompletion{ProcessBoot: f.peer.ProcessBoot(), Call: received.ControlCall(), Disposition: protocol.ControlSettled})
		stop()
		if err != nil {
			return err
		}
	}
}

func (f *fixture) response(ctx context.Context, command protocol.Command) (any, error) {
	switch command.Operation {
	case protocol.ContextInspect:
		return f.inspect(command)
	case protocol.OriginBarrier:
		return f.barrier(command)
	case protocol.OriginInventory:
		return f.inventory(command)
	case protocol.OriginReopen:
		return f.reopen(command)
	case protocol.ResolveProject:
		return f.resolve(ctx, command)
	case protocol.Admit, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel:
		return nil, errors.New("fixture unexpectedly received a task control")
	}
	return nil, errors.New("fixture received an unknown operation")
}

func (f *fixture) inspect(command protocol.Command) (any, error) {
	var request protocol.InspectRequest
	if protocol.DecodeStrict(command.Body, &request, 64<<10) != nil || request.GatewayID != string(f.gateway) {
		return nil, errors.New("fixture inspection namespace mismatch")
	}
	if request.RootOnly {
		if command.Root != string(f.root) || command.Project != "" {
			return nil, errors.New("fixture root inspection used a project")
		}
		report := protocol.RootCapability{Root: string(f.root), ContractVersion: 1, Features: []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease, protocol.WorkspaceFeature}}
		if f.origin != nil {
			value := *f.origin
			report.OriginRegistered = true
			report.Origin = &value
		}
		return report, nil
	}
	f.inspectCalls.Add(1)
	pin, found := f.pins[command.Project]
	if !found || f.origin == nil {
		return nil, errors.New("fixture targeted an unresolved pin")
	}
	capability := protocol.ProjectCapability{Alias: pin.Handle, Context: pin.Context, ContractVersion: 1, Features: []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease, protocol.WorkspaceFeature}, AdmissionGeneration: f.origin.Generation, AdmissionOpen: f.origin.AdmissionOpen, Ready: f.origin.AdmissionOpen, Providers: []protocol.ProviderCapability{{Provider: "provider", Permissions: []string{"read-only"}, MaxBudgetSeconds: 60, Authentication: "unknown"}}}
	return protocol.ProjectCapabilityV2{Project: pin, CurrentPolicyRevision: f.policyRevision.Load(), Capability: capability}, nil
}

func (f *fixture) barrier(command protocol.Command) (any, error) {
	var request protocol.OriginBarrierRequest
	if protocol.DecodeStrict(command.Body, &request, 64<<10) != nil || command.Root != string(f.root) || request.ExpectedRoot != string(f.root) || request.GatewayID != string(f.gateway) || request.ExpectedGeneration != "" {
		return nil, errors.New("fixture barrier changed its exact root")
	}
	f.barrierCalls.Add(1)
	f.origin = &protocol.OriginStateReport{GatewayID: request.GatewayID, RecoveryID: request.RecoveryID, Generation: request.Generation}
	return *f.origin, nil
}

func (f *fixture) inventory(command protocol.Command) (any, error) {
	var request protocol.OriginInventoryRequest
	if protocol.DecodeStrict(command.Body, &request, 64<<10) != nil || command.Root != string(f.root) || request.ExpectedRoot != string(f.root) || f.origin == nil || request.Generation != f.origin.Generation {
		return nil, errors.New("fixture inventory changed root or generation")
	}
	if f.conflictingHistory.Load() {
		id := strings.Repeat("d", 32)
		return protocol.OriginInventoryReport{Entries: []protocol.OriginInventoryEntry{{TaskID: id, Resolution: "permanently_refused"}}, NextCursor: id, MembershipSHA256: strings.Repeat("1", 64)}, nil
	}
	return protocol.OriginInventoryReport{Entries: []protocol.OriginInventoryEntry{}, Complete: true, MembershipSHA256: strings.Repeat("1", 64), CompletenessReceipt: strings.Repeat("2", 64)}, nil
}

func (f *fixture) reopen(command protocol.Command) (any, error) {
	var request protocol.OriginReopenRequest
	if protocol.DecodeStrict(command.Body, &request, 64<<10) != nil || command.Root != string(f.root) || request.ExpectedRoot != string(f.root) || f.origin == nil || request.Generation != f.origin.Generation || request.RecoveryID != f.origin.RecoveryID || request.CompletenessReceipt != strings.Repeat("2", 64) {
		return nil, errors.New("fixture reopened another namespace")
	}
	f.origin.AdmissionOpen = true
	return *f.origin, nil
}

func (f *fixture) resolve(ctx context.Context, command protocol.Command) (any, error) {
	var request protocol.ResolveProjectRequest
	if protocol.DecodeStrict(command.Body, &request, 64<<10) != nil || request.Validate() != nil || command.Root != string(f.root) || request.WorkspaceID != f.workspace.ID || f.origin == nil || !f.origin.AdmissionOpen {
		return nil, errors.New("fixture pin preceded namespace initialization")
	}
	f.resolveCalls.Add(1)
	pin, exists := f.pins[request.RequestID]
	if !exists {
		pin = protocol.ResolvedProject{Handle: request.RequestID, Workspace: f.workspace, Context: protocol.ContextBinding{Root: string(f.root), Project: protocol.WireContextGuard("project:" + request.RelativePath)}}
		f.pins[request.RequestID] = pin
	}
	if f.removeDispatchBeforeReply.CompareAndSwap(true, false) {
		policy := ownerPolicy()
		policy.Scopes = domain.ScopeSet{domain.InventoryRead}
		if err := f.store.PutOwnerPolicy(ctx, f.actor.Principal, policy); err != nil {
			return nil, err
		}
	}
	digest := domain.Hash([]byte(request.RelativePath))
	return protocol.ResolveProjectReply{RequestID: request.RequestID, RelativePathSHA256: hex.EncodeToString(digest[:]), Project: pin}, nil
}

func (f *fixture) input() workspaces.ResolveInput {
	return workspaces.ResolveInput{Device: f.device, Request: protocol.ResolveProjectRequest{RequestID: strings.Repeat("e", 32), WorkspaceID: f.workspace.ID, RelativePath: "private-canary-repository"}}
}

func requireCode(t *testing.T, err error, code domain.ErrorCode) {
	t.Helper()
	var failure *domain.Error
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func bounded(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

var (
	_ gateway.TargetedCapabilities = (*workspaces.Service)(nil)
	_ workspaces.Store             = (*registry.Store)(nil)
)
