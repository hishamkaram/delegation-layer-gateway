package workspaces_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicehub"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
	"github.com/hishamkaram/delegation-layer-gateway/internal/wirelink"
)

func (f *fixture) selectProject(command protocol.Command) (any, error) {
	var request protocol.SelectionRequest
	if protocol.DecodeStrict(command.Body, &request, 64<<10) != nil || request.Validate() != nil || command.Root != string(f.root) || request.Selection.ScopeID != f.workspace.ID {
		return nil, errors.New("fixture selection changed its root or scope")
	}
	f.metadataCalls.Add(1)
	result := protocol.SelectionObservation{Selection: request.Selection, Context: protocol.ContextBinding{Root: string(f.root), Project: protocol.WireContextGuard("selected:" + request.Selection.RelativePath)}, WorkspaceGuard: f.workspace.Guard, Features: f.features, Providers: []protocol.NativeProviderCapability{}, ObservedAt: time.Now()}
	if f.origin != nil {
		result.AdmissionGeneration = f.origin.Generation
		result.AdmissionOpen = f.origin.AdmissionOpen
	}
	return result, nil
}

func (f *fixture) readFile(ctx context.Context, command protocol.Command) (any, error) {
	var request protocol.FilesystemRequest
	if protocol.DecodeStrict(command.Body, &request, 64<<10) != nil || request.ValidateFor(protocol.ReadFile) != nil || command.Root != string(f.root) {
		return nil, errors.New("fixture file request changed its root")
	}
	f.metadataCalls.Add(1)
	if f.removeReadBeforeReply.CompareAndSwap(true, false) {
		policy := ownerPolicy()
		policy.Scopes = domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch}
		if err := f.store.PutOwnerPolicy(ctx, f.actor.Principal, policy); err != nil {
			return nil, err
		}
	}
	return protocol.FilesystemResponse{SchemaVersion: 1, Operation: "read", ObservedAt: time.Now(), Read: &protocol.FileRange{DataBase64: base64.StdEncoding.EncodeToString([]byte{0, 0xff, 1}), Offset: 0, NextOffset: 3, EOF: true, Version: "fixture-version"}}, nil
}

func TestFilesystemMetadataUsesRealRoutingWithoutInitializingAdmission(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	request := protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID, RelativePath: ".hidden-file"}, Limit: 3}
	result, err := f.backend.ReadFilesystem(bounded(t), f.actor, f.device, protocol.ReadFile, request)
	require(t, err)
	if result.Read == nil || result.Read.DataBase64 != "AP8B" || result.Read.NextOffset != 3 || f.barrierCalls.Load() != 0 || f.resolveCalls.Load() != 0 || f.metadataCalls.Load() != 1 {
		t.Fatal("read altered bytes, initialized a task namespace or retained a project")
	}
	operations, err := f.store.ListOperations(t.Context(), f.actor, domain.OperationPageRequest{})
	require(t, err)
	projects, err := f.store.ListProjects(t.Context(), f.actor, f.device, domain.ProjectPageRequest{})
	require(t, err)
	if len(operations.Items) != 0 || len(projects.Items) != 0 {
		t.Fatal("filesystem read manufactured task or project state")
	}
	for _, scopes := range []domain.ScopeSet{{domain.TaskRead}, {domain.TaskDispatch}} {
		actor := f.actor
		actor.Scopes = scopes
		_, err = f.backend.ReadFilesystem(bounded(t), actor, f.device, protocol.ReadFile, request)
		if err == nil || f.metadataCalls.Load() != 1 {
			t.Fatal("single-scope token reached Native filesystem")
		}
	}
}

func TestFilesystemMetadataRechecksRevocationBeforeReleasingBytes(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	f.removeReadBeforeReply.Store(true)
	result, err := f.backend.ReadFilesystem(bounded(t), f.actor, f.device, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}, Limit: 3})
	if err == nil || result != (protocol.FilesystemResponse{}) || f.metadataCalls.Load() != 1 {
		t.Fatal("filesystem bytes escaped after current read access was revoked")
	}
}

func TestFilesystemMetadataRechecksGenerationAfterRoutingObserver(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	original, err := f.link.Snapshot(f.device)
	require(t, err)
	observed := false
	f.controls, err = gateway.NewMetadataControls(f.link, time.Now, gateway.RoutingObserverFunc(func(event gateway.RoutingObservation) {
		if event.Failed {
			return
		}
		observed = true
		_, replaceErr := f.store.NextConnectionGeneration(t.Context(), original.Credential, "replacement", time.Now())
		require(t, replaceErr)
	}))
	require(t, err)
	f.backend = f.service(t, f.store)
	result, err := f.backend.ReadFilesystem(bounded(t), f.actor, f.device, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}, Limit: 3})
	if !observed {
		t.Fatal("routing observer boundary was not exercised")
	}
	_, stale := f.store.CheckConnection(t.Context(), original.Credential, original.Connection, time.Now())
	if stale == nil {
		t.Fatal("fixture did not invalidate the original connection")
	}
	_, currentOwner := f.store.AuthorizeOwnedDevice(t.Context(), domain.OwnedDeviceRequest{Actor: f.actor, Device: f.device, Scope: domain.TaskDispatch})
	require(t, currentOwner)
	if err == nil || result != (protocol.FilesystemResponse{}) {
		t.Fatal("old-generation data escaped after the routing observer")
	}
}

func TestFilesystemMetadataRechecksLiveRootBeforeAnyAdmissionExists(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	ctx := bounded(t)
	route := domain.RootRoute{Device: f.device, Root: f.root}
	_, err := f.store.ReadRootInitializationProgress(t.Context(), domain.RootInitializationLookup{RootRoute: &route})
	requireCode(t, err, domain.NotFound)
	replaced := false
	f.controls, err = gateway.NewMetadataControls(f.link, time.Now, gateway.RoutingObserverFunc(func(event gateway.RoutingObservation) {
		if !event.Failed {
			replaced = true
			reportMetadataRoot(ctx, t, f, domain.RootGuard(protocol.WireContextGuard("replacement root")))
		}
	}))
	require(t, err)
	f.backend = f.service(t, f.store)
	result, err := f.backend.ReadFilesystem(ctx, f.actor, f.device, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}, Limit: 3})
	if !replaced || err == nil || result != (protocol.FilesystemResponse{}) {
		t.Fatal("metadata escaped after the live root changed without root-admission state")
	}
	_, err = f.store.ReadRootInitializationProgress(t.Context(), domain.RootInitializationLookup{RootRoute: &route})
	requireCode(t, err, domain.NotFound)
}

func reportMetadataRoot(ctx context.Context, t *testing.T, f *fixture, root domain.RootGuard) {
	t.Helper()
	snapshot, err := f.link.Snapshot(f.device)
	require(t, err)
	report := *snapshot.CapabilitiesV2
	selected := *report.Root
	selected.Root = string(root)
	report.Root = &selected
	report.ObservedAt = time.Now()
	require(t, f.peer.ReportCapabilitiesV2(ctx, report))
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		current, readErr := f.link.Snapshot(f.device)
		require(t, readErr)
		if current.CapabilitiesV2.Root.Root == string(root) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("peer root capability update was not observed")
		case <-tick.C:
		}
	}
}

func TestMetadataObservationRetainsOriginalSourceAndCurrentOperationScopes(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem, protocol.FeatureNativeOptions)
	file, err := f.backend.ObserveFilesystem(bounded(t), f.actor, f.device, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}, Limit: 3})
	require(t, err)
	selected, err := f.backend.ObserveSelection(bounded(t), f.actor, f.device, protocol.SelectionRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}})
	require(t, err)
	original, err := f.link.Snapshot(f.device)
	require(t, err)
	if file.Value.Read.DataBase64 != "AP8B" || file.Source.Binding.Credential != original.Credential || file.Source.Binding.Connection != original.Connection || file.Source.Binding.Route.Root != f.root || file.Source.Operation != protocol.ReadFile || selected.Source.Operation != protocol.SelectProject {
		t.Fatal("metadata observation changed bytes, operation or source identity")
	}
	policy := ownerPolicy()
	policy.Scopes = domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch}
	require(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	// Registry deliberately hides a device when its owner policy lacks a scope.
	requireCode(t, f.backend.CheckMetadataObservation(bounded(t), f.actor, file.Source, nil), domain.NotFound)
	require(t, f.backend.CheckMetadataObservation(bounded(t), f.actor, selected.Source, nil))
	policy.Scopes = domain.ScopeSet{domain.InventoryRead, domain.TaskRead}
	require(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	requireCode(t, f.backend.CheckMetadataObservation(bounded(t), f.actor, file.Source, nil), domain.NotFound)
	requireCode(t, f.backend.CheckMetadataObservation(bounded(t), f.actor, selected.Source, nil), domain.NotFound)
	require(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, ownerPolicy()))
	_, err = f.store.NextConnectionGeneration(t.Context(), original.Credential, "replacement", time.Now())
	require(t, err)
	if f.backend.CheckMetadataObservation(bounded(t), f.actor, selected.Source, nil) == nil {
		t.Fatal("retained observation rebased onto a replacement generation")
	}
}

func TestMetadataObservationRechecksCredentialValidity(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	observed, err := f.backend.ObserveFilesystem(bounded(t), f.actor, f.device, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}, Limit: 3})
	require(t, err)
	credential, err := f.store.CheckCredential(t.Context(), observed.Source.Binding.Credential, time.Now())
	require(t, err)
	checker, err := workspaces.New(workspaces.Options{Store: f.store, Presence: f.link, Controls: f.controls, GatewayID: f.gateway, Now: func() time.Time { return credential.NotAfter }, Roots: func(context.Context, domain.OwnedRootBinding) (workspaces.Initializer, error) {
		return nil, errors.New("passive metadata must not initialize a root")
	}})
	require(t, err)
	requireCode(t, checker.CheckMetadataObservation(t.Context(), f.actor, observed.Source, nil), domain.Expired)
}

type metadataTransactionStore struct {
	workspaces.Store
	before func(context.Context, domain.ScopeSet, domain.OwnedRootBinding) error
	after  func(context.Context, domain.ScopeSet, domain.OwnedRootBinding) error
}

func (s metadataTransactionStore) CheckWorkspaceMetadata(ctx context.Context, actor domain.Actor, scopes domain.ScopeSet, binding domain.OwnedRootBinding, now time.Time) error {
	if s.before != nil {
		if err := s.before(ctx, scopes, binding); err != nil {
			return err
		}
	}
	if err := s.Store.CheckWorkspaceMetadata(ctx, actor, scopes, binding, now); err != nil {
		return err
	}
	if s.after != nil {
		return s.after(ctx, scopes, binding)
	}
	return nil
}

func TestMetadataObservationChecksEndpointScopeAndBindingTogether(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	observed, err := f.backend.ObserveFilesystem(bounded(t), f.actor, f.device, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}, Limit: 3})
	require(t, err)
	calls := 0
	store := metadataTransactionStore{Store: f.store, before: func(ctx context.Context, scopes domain.ScopeSet, binding domain.OwnedRootBinding) error {
		calls++
		if len(scopes) != 3 || scopes.Validate() != nil || !scopes.Has(domain.TaskDispatch) || !scopes.Has(domain.TaskRead) || !scopes.Has(domain.InventoryRead) || binding != observed.Source.Binding {
			return errors.New("combined metadata transaction lost required scopes or original binding")
		}
		_, changeErr := f.store.NextConnectionGeneration(ctx, binding.Credential, "during-endpoint-check", time.Now())
		return changeErr
	}}
	checker := f.service(t, store)
	err = checker.CheckMetadataObservation(bounded(t), f.actor, observed.Source, domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch})
	requireCode(t, err, domain.Conflict)
	if calls != 1 {
		t.Fatal("endpoint scope and original binding did not share one Registry check")
	}
}

func TestMetadataObservationRechecksPresenceAfterCombinedTransaction(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	observed, err := f.backend.ObserveFilesystem(bounded(t), f.actor, f.device, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}, Limit: 3})
	require(t, err)
	calls := 0
	store := metadataTransactionStore{Store: f.store, after: func(ctx context.Context, scopes domain.ScopeSet, _ domain.OwnedRootBinding) error {
		calls++
		if !scopes.Has(domain.InventoryRead) {
			return errors.New("endpoint scope was split from the source transaction")
		}
		reportMetadataRoot(ctx, t, f, domain.RootGuard(protocol.WireContextGuard("root-changed-after-transaction")))
		return nil
	}}
	checker := f.service(t, store)
	requireCode(t, checker.CheckMetadataObservation(bounded(t), f.actor, observed.Source, domain.ScopeSet{domain.InventoryRead}), domain.Conflict)
	if calls != 1 {
		t.Fatal("final presence check retried Registry authority or skipped its transaction")
	}
}

func TestMetadataObservationAdditionalScopesCannotLowerBaseScopes(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem, protocol.FeatureNativeOptions)
	file, err := f.backend.ObserveFilesystem(bounded(t), f.actor, f.device, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}, Limit: 3})
	require(t, err)
	selection, err := f.backend.ObserveSelection(bounded(t), f.actor, f.device, protocol.SelectionRequest{Selection: protocol.FileSelection{ScopeID: f.workspace.ID}})
	require(t, err)
	required := domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead}
	for _, removed := range required {
		policy := ownerPolicy()
		policy.Scopes = nil
		for _, scope := range required {
			if scope != removed {
				policy.Scopes = append(policy.Scopes, scope)
			}
		}
		require(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
		requireCode(t, f.backend.CheckMetadataObservation(bounded(t), f.actor, file.Source, domain.ScopeSet{domain.InventoryRead}), domain.NotFound)
		if removed == domain.InventoryRead {
			require(t, f.backend.CheckMetadataObservation(bounded(t), f.actor, selection.Source, nil))
		}
	}
	for _, invalid := range []domain.ScopeSet{{domain.DeviceEnroll}, {domain.DeviceManage}, {domain.InventoryRead, domain.InventoryRead}, {domain.Scope("unknown")}} {
		if err := f.backend.CheckMetadataObservation(bounded(t), f.actor, file.Source, invalid); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("invalid additional metadata scopes were accepted: %v", err)
		}
	}
}

type temporaryDiscoveryFailure struct {
	workspaces.Controls
	failure error
	before  func(context.Context) error
}

func (c temporaryDiscoveryFailure) Exchange(ctx context.Context, call gateway.MetadataCall) (protocol.Reply, domain.Transmission, error) {
	if call.Command.Operation != protocol.FilesystemScopes {
		return c.Controls.Exchange(ctx, call)
	}
	if c.before != nil {
		if err := c.before(ctx); err != nil {
			return protocol.Reply{}, domain.Transmission{}, err
		}
	}
	return protocol.Reply{}, domain.Transmission{}, c.failure
}

func workspaceServiceWithControls(t *testing.T, f *fixture, store workspaces.Store, controls workspaces.Controls) *workspaces.Service {
	t.Helper()
	service, err := workspaces.New(workspaces.Options{Store: store, Presence: f.link, Controls: controls, GatewayID: f.gateway, Now: time.Now, Roots: func(context.Context, domain.OwnedRootBinding) (workspaces.Initializer, error) {
		return nil, errors.New("workspace inventory must not initialize a task namespace")
	}})
	require(t, err)
	return service
}

func TestWorkspaceInventoryPreservesSnapshotWhenTemporaryDiscoveryFails(t *testing.T) {
	for _, mode := range []string{"resource-busy", "dispatch-revoked", "generation-replaced", "unknown-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, protocol.FeatureFilesystem)
			controls := temporaryDiscoveryFailure{Controls: f.controls, failure: &gateway.RemoteError{Failure: protocol.Failure{Stage: "filesystem", Code: "resource_limit", Retryable: true}}}
			code := "resource_limit"
			switch mode {
			case "resource-busy":
			case "dispatch-revoked":
				code, controls.failure = "not_found", domain.Reject(domain.NotFound)
				controls.before = func(ctx context.Context) error {
					policy := ownerPolicy()
					policy.Scopes = domain.ScopeSet{domain.InventoryRead, domain.TaskRead, domain.TaskCancel}
					return f.store.PutOwnerPolicy(ctx, f.actor.Principal, policy)
				}
			case "generation-replaced":
				code, controls.failure = "conflict", domain.Reject(domain.Conflict)
				controls.before = func(ctx context.Context) error {
					snapshot, err := f.link.Snapshot(f.device)
					if err != nil {
						return err
					}
					_, err = f.store.NextConnectionGeneration(ctx, snapshot.Credential, "temporary-discovery-replaced", time.Now())
					return err
				}
			case "unknown-failure":
				code, controls.failure = "scope_discovery_failed", errors.New("private-scope-error-canary")
			}
			service := workspaceServiceWithControls(t, f, f.store, controls)
			result, err := service.ObserveWorkspaces(bounded(t), f.actor, f.device)
			require(t, err)
			if result.Source != nil || result.Value.ScopeDiscoveryError != code || len(result.Value.Workspaces) != 1 || len(result.Value.Scopes) != 1 || result.Value.Scopes[0].Kind != "workspace" || result.Value.Device != f.device {
				t.Fatal("optional temporary discovery suppressed or contaminated authorized workspace inventory")
			}
		})
	}
}

func TestWorkspaceInventoryDiscoveryFallbackRetainsParentAuthority(t *testing.T) {
	for _, mode := range []string{"inventory-revoked", "parent-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, protocol.FeatureFilesystem)
			ctx, cancel := context.WithCancel(bounded(t))
			defer cancel()
			controls := temporaryDiscoveryFailure{Controls: f.controls, failure: domain.Reject(domain.ResourceLimit), before: func(call context.Context) error {
				if mode == "parent-cancelled" {
					cancel()
					return nil
				}
				policy := ownerPolicy()
				policy.Scopes = domain.ScopeSet{domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}
				return f.store.PutOwnerPolicy(call, f.actor.Principal, policy)
			}}
			service := workspaceServiceWithControls(t, f, f.store, controls)
			result, err := service.ObserveWorkspaces(ctx, f.actor, f.device)
			if mode == "parent-cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expired parent observation returned inventory: %v", err)
				}
			} else {
				requireCode(t, err, domain.NotFound)
			}
			if result.Source != nil || result.Value.Device != "" || len(result.Value.Scopes) != 0 || len(result.Value.Workspaces) != 0 {
				t.Fatal("fallback released inventory after parent authority was lost")
			}
		})
	}
}

type inventoryAuthorityFailure struct {
	workspaces.Store
	calls   int
	failure error
}

func (s *inventoryAuthorityFailure) AuthorizeOwnedDevice(ctx context.Context, input domain.OwnedDeviceRequest) (domain.OwnedDeviceAuthorization, error) {
	if input.Scope == domain.InventoryRead {
		s.calls++
		if s.calls > 1 {
			return domain.OwnedDeviceAuthorization{}, s.failure
		}
	}
	return s.Store.AuthorizeOwnedDevice(ctx, input)
}

func TestWorkspaceInventoryFallbackDoesNotMaskFinalAuthorityStorageFailure(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	unavailable := errors.New("fixture final inventory authority unavailable")
	store := &inventoryAuthorityFailure{Store: f.store, failure: unavailable}
	controls := temporaryDiscoveryFailure{Controls: f.controls, failure: domain.Reject(domain.ResourceLimit)}
	service := workspaceServiceWithControls(t, f, store, controls)
	result, err := service.ObserveWorkspaces(bounded(t), f.actor, f.device)
	if !errors.Is(err, unavailable) || result.Value.Device != "" || len(result.Value.Workspaces) != 0 || len(result.Value.Scopes) != 0 || result.Source != nil {
		t.Fatal("optional discovery fallback masked the final inventory authority failure")
	}
}

func TestWorkspaceInventoryDoesNotRequireOwnerFilesystemAccess(t *testing.T) {
	f := newFixture(t, protocol.FeatureFilesystem)
	policy := ownerPolicy()
	policy.Scopes = domain.ScopeSet{domain.InventoryRead}
	require(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	result, err := f.backend.ListWorkspaces(bounded(t), f.actor, f.device)
	require(t, err)
	if !result.Online || len(result.Workspaces) != 1 || len(result.Scopes) != 1 || result.Scopes[0].Kind != "workspace" || f.metadataCalls.Load() != 0 {
		t.Fatal("inventory required filesystem access or invoked an unauthorized Native read")
	}
}

type inventorySnapshotTransition struct {
	workspaces.Presence
	afterFirst func(gateway.LinkSnapshot)
}

func (p *inventorySnapshotTransition) Snapshot(device domain.DeviceID) (gateway.LinkSnapshot, error) {
	snapshot, err := p.Presence.Snapshot(device)
	if err == nil && p.afterFirst != nil {
		transition := p.afterFirst
		p.afterFirst = nil
		transition(snapshot)
	}
	return snapshot, err
}

type inventoryScopePeer struct {
	client *transport.Client
	stop   context.CancelFunc
	joined <-chan error
}

func (p inventoryScopePeer) close(ctx context.Context) error {
	p.stop()
	closeErr := p.client.Close()
	select {
	case err := <-p.joined:
		if errors.Is(err, context.Canceled) || errors.Is(err, transport.ErrOffline) {
			err = nil
		}
		return errors.Join(closeErr, err)
	case <-ctx.Done():
		return errors.Join(closeErr, ctx.Err())
	}
}

func runInventoryScopes(ctx context.Context, client *transport.Client) error {
	for {
		received, err := client.Receive(ctx)
		if err != nil {
			return err
		}
		frame, err := received.Claim(ctx)
		if err != nil {
			return err
		}
		command, err := protocol.DecodeCommandVersion(frame, protocol.WireVersion2)
		if err != nil || command.Operation != protocol.FilesystemScopes {
			return errors.Join(err, errors.New("inventory fixture received an unexpected control"))
		}
		var request protocol.FilesystemRequest
		if protocol.DecodeStrict(command.Body, &request, 64<<10) != nil || request.ValidateFor(command.Operation) != nil {
			return errors.New("inventory fixture received an invalid scope request")
		}
		body, err := protocol.Encode(protocol.FilesystemResponse{SchemaVersion: 1, Operation: "scopes", ObservedAt: time.Now(), Scopes: &protocol.FilesystemScopesResult{Scopes: []protocol.FilesystemScope{{ID: protocol.SharedTempScope, Kind: "shared_temp", Name: "new-session-temp-canary"}}}}, protocol.MaxFrameBytes)
		if err != nil {
			return err
		}
		if err = received.ReplyControl(ctx, protocol.Reply{Operation: command.Operation, Body: body}, protocol.ControlCompletion{ProcessBoot: client.ProcessBoot(), Call: received.ControlCall(), Disposition: protocol.ControlSettled}); err != nil {
			return err
		}
	}
}

// The dedicated peer accepts only scope reads and owns each connection worker.
// Reconnect closes and joins the previous worker before selecting the next one.
func inventoryReconnect(t *testing.T, f *fixture, ca *x509.Certificate, certificate tls.Certificate) func(context.Context) {
	t.Helper()
	var err error
	f.hub, err = devicehub.NewHub(t.Context(), devicehub.Config{EnableWireV2: true, GatewayID: f.gateway, BootEpoch: "inventory-fixture-boot", Routing: f.store}, f.store, time.Now)
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
		t.Fatal("unexpected inventory fixture TLS transport")
	}
	owned := base.Clone()
	owned.TLSClientConfig = base.TLSClientConfig.Clone()
	owned.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	t.Cleanup(owned.CloseIdleConnections)
	var current *inventoryScopePeer
	t.Cleanup(func() {
		if current != nil {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
			defer cancel()
			require(t, current.close(ctx))
		}
	})
	return func(ctx context.Context) {
		if current != nil {
			require(t, current.close(ctx))
			current = nil
		}
		report := protocol.CapabilityReportV2{ObservedAt: time.Now(), Root: &protocol.RootCapability{Root: string(f.root), ContractVersion: 1, Features: f.features}, Workspaces: []protocol.WorkspaceCapability{{WorkspaceBinding: f.workspace, Name: "initial-workspace", PolicyRevision: 1}}}
		require(t, report.Validate())
		client, dialErr := transport.Dial(ctx, transport.ClientConfig{WireVersion: protocol.WireVersion2, URL: "wss" + strings.TrimPrefix(server.URL, "https"), GatewayID: f.gateway, Certificate: certificate.Leaf, CapabilitiesV2: &report, Routing: census{}}, &http.Client{Transport: owned}, time.Now)
		require(t, dialErr)
		worker, stop := context.WithCancel(ctx)
		joined := make(chan error, 1)
		current = &inventoryScopePeer{client: client, stop: stop, joined: joined}
		go func() { joined <- runInventoryScopes(worker, client) }()
		f.peer = client
		require(t, f.hub.WaitReady(ctx, f.device))
	}
}

func newInventorySourceFixture(t *testing.T) (*fixture, func(context.Context)) {
	t.Helper()
	f := &fixture{root: domain.RootGuard(protocol.WireContextGuard("inventory source root")), workspace: protocol.WorkspaceBinding{ID: "work", Guard: protocol.WireContextGuard("inventory workspace")}, features: []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease, protocol.WorkspaceFeature, protocol.FeatureFilesystem}}
	var err error
	f.store, err = registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.sqlite"), registry.CreateOptions{Admin: fixtureAdmin{}})
	require(t, err)
	t.Cleanup(func() { require(t, f.store.Close()) })
	f.gateway, err = f.store.Identity(t.Context())
	require(t, err)
	principal, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://fixture.example/", Subject: "inventory-owner"})
	require(t, err)
	f.actor = domain.Actor{Principal: principal.ID, Scopes: domain.ScopeSet{domain.DeviceEnroll, domain.InventoryRead, domain.TaskDispatch, domain.TaskRead}}
	require(t, f.store.PutOwnerPolicy(t.Context(), principal.ID, ownerPolicy()))
	ca, certificate, ref := f.enroll(t)
	f.device = ref.Device
	reconnect := inventoryReconnect(t, f, ca, certificate)
	reconnect(bounded(t))
	f.link, err = wirelink.New(f.hub)
	require(t, err)
	f.controls, err = gateway.NewMetadataControls(f.link, time.Now, gateway.RoutingObserverFunc(f.observations.record))
	require(t, err)
	return f, reconnect
}

func TestWorkspaceInventoryDoesNotMixObservationSources(t *testing.T) {
	for _, transition := range []string{"unchanged", "root-replaced", "same-root-reconnected"} {
		t.Run(transition, func(t *testing.T) {
			f, reconnect := newInventorySourceFixture(t)
			ctx := bounded(t)
			var initial gateway.LinkSnapshot
			presence := &inventorySnapshotTransition{Presence: f.link, afterFirst: func(snapshot gateway.LinkSnapshot) {
				initial = snapshot
				switch transition {
				case "root-replaced":
					reportMetadataRoot(ctx, t, f, domain.RootGuard(protocol.WireContextGuard("replacement inventory root")))
				case "same-root-reconnected":
					reconnect(ctx)
				}
			}}
			service, err := workspaces.New(workspaces.Options{Store: f.store, Presence: presence, Controls: f.controls, GatewayID: f.gateway, Now: time.Now, Roots: func(context.Context, domain.OwnedRootBinding) (workspaces.Initializer, error) {
				return nil, errors.New("inventory must not initialize a task namespace")
			}})
			require(t, err)
			result, err := service.ObserveWorkspaces(ctx, f.actor, f.device)
			require(t, err)
			current, err := f.link.Snapshot(f.device)
			require(t, err)
			assertInventorySource(t, result, initial, current, transition)
		})
	}
}

func assertInventorySource(t *testing.T, result workspaces.InventoryObservation, initial, current gateway.LinkSnapshot, transition string) {
	t.Helper()
	if len(result.Value.Workspaces) != 1 || result.Value.Workspaces[0].Name != "initial-workspace" || !result.Value.ObservedAt.Equal(initial.ObservedAt) {
		t.Fatal("temporary discovery replaced the dated workspace snapshot")
	}
	if transition == "unchanged" {
		if result.Source == nil || len(result.Value.Scopes) != 2 || result.Value.ScopeDiscoveryError != "" {
			t.Fatal("same-source temporary discovery did not retain its observation")
		}
		return
	}
	if current.Connection == initial.Connection && current.CapabilitiesV2.Root.Root == initial.CapabilitiesV2.Root.Root {
		t.Fatal("fixture did not replace the actual inventory source")
	}
	if result.Source != nil || len(result.Value.Scopes) != 1 || result.Value.Scopes[0].Kind != "workspace" || result.Value.ScopeDiscoveryError != "conflict" {
		t.Fatal("inventory mixed temporary data from a different root or connection")
	}
}

func TestSelectedPreparationReplaysBeforeLiveDeviceLookup(t *testing.T) {
	f := newFixture(t, protocol.FeatureNativeOptions, protocol.FeatureProjectHashGuard, protocol.FeatureOriginBinding)
	service, err := gateway.New(f.store, f.link, f.gateway, rand.Reader, time.Now, gateway.RoutingObserverFunc(f.observations.record), f.backend)
	require(t, err)
	input := gateway.SelectedPreparation{RequestID: domain.RequestID(strings.Repeat("1", 32)), Device: f.device, Selection: protocol.FileSelection{ScopeID: f.workspace.ID, RelativePath: "new-project"}, Request: domain.FrozenRequest{Native: domain.NativeOptions{Version: 1, Provider: "future-native-provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: "future-native-permission", Budget: "1250ms"}, Brief: "private-canary-brief"}}
	prepared, err := service.PrepareSelected(bounded(t), f.actor, input)
	require(t, err)
	if prepared.Correlation.Route.RequestID != input.RequestID || prepared.Correlation.Route.RelativePath != input.Selection.RelativePath || f.resolveCalls.Load() != 0 || f.metadataCalls.Load() != 1 {
		t.Fatal("operation route retained an alias or changed caller intent")
	}
	require(t, f.peer.Close())
	replayed, err := service.PrepareSelected(bounded(t), f.actor, input)
	require(t, err)
	if replayed.Correlation != prepared.Correlation || !replayed.ExpiresAt.Equal(prepared.ExpiresAt) || f.metadataCalls.Load() != 1 {
		t.Fatal("lost acknowledgement allocated replacement work or re-inspected an offline device")
	}
	input.Request.Native.Budget = "1251ms"
	_, err = service.PrepareSelected(bounded(t), f.actor, input)
	requireCode(t, err, domain.Conflict)
	page, err := f.store.ListOperations(t.Context(), f.actor, domain.OperationPageRequest{})
	require(t, err)
	if len(page.Items) != 1 {
		t.Fatal("one caller key retained multiple operations")
	}
}
