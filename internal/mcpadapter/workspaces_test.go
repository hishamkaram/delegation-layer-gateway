package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Backend persistence/authorization is exercised with SQLite and WSS in its
// package. This consumer fixture checks the official MCP SDK schemas/scopes and
// that metadata tools cannot invoke a different backend responsibility.
type workspaceBackend struct {
	listCalls, resolveCalls, inspectCalls int
	inspectScope                          domain.Scope
	observation                           gateway.TargetedProjectObservation
	failure                               error
}

func (s *workspaceBackend) ListWorkspaces(_ context.Context, _ domain.Actor, device domain.DeviceID) (workspaces.Inventory, error) {
	s.listCalls++
	return workspaces.Inventory{Device: device, Workspaces: []protocol.WorkspaceCapability{{WorkspaceBinding: protocol.WorkspaceBinding{ID: "code", Guard: protocol.WireContextGuard("workspace")}, Name: "code", PolicyRevision: 2}}}, nil
}

func (s *workspaceBackend) ResolveProject(_ context.Context, _ domain.Actor, input workspaces.ResolveInput) (workspaces.Resolution, error) {
	s.resolveCalls++
	if input.Request.Validate() != nil {
		return workspaces.Resolution{}, domain.ErrInvalid
	}
	if s.failure != nil {
		return workspaces.Resolution{}, s.failure
	}
	return workspaces.Resolution{Device: input.Device, Request: domain.ResolutionID(input.Request.RequestID), Project: domain.ProjectPin{Handle: domain.ProjectAlias(input.Request.RequestID), Workspace: domain.WorkspaceBinding{ID: input.Request.WorkspaceID, Guard: protocol.WireContextGuard("workspace")}, Context: domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard("root")), Project: domain.ProjectGuard(protocol.WireContextGuard("project"))}}}, nil
}

func (s *workspaceBackend) InspectProject(_ context.Context, _ domain.Actor, _ domain.Destination, scope domain.Scope) (gateway.TargetedProjectObservation, error) {
	s.inspectCalls++
	s.inspectScope = scope
	return s.observation, nil
}

func TestSDKWorkspaceToolsAdvertiseClosedSchemasAndIndependentScopes(t *testing.T) {
	backend := &workspaceBackend{}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Workspaces = backend })
	listed, err := f.session(t, "alice").ListTools(t.Context(), nil)
	check(t, err)
	if len(listed.Tools) != 14 {
		t.Fatalf("configured workspace catalog has %d tools, want14", len(listed.Tools))
	}
	want := map[string]toolExpectation{"list_workspaces": {true, false, true, []string{"inventory:read"}}, "resolve_project": {false, false, true, []string{"task:dispatch"}}}
	for _, tool := range listed.Tools {
		expected, found := want[tool.Name]
		if !found {
			continue
		}
		wire := sdkValue[toolWire](t, tool)
		assertClosed(t, wire.Input)
		assertClosed(t, wire.Output)
		assertToolHints(t, wire, expected)
		assertToolOAuth(t, wire, expected.scopes)
		delete(want, tool.Name)
	}
	if len(want) != 0 {
		t.Fatal("workspace tool missing")
	}
	request := ResolveProjectInput{DeviceID: "device-one", RequestID: strings.Repeat("e", 32), WorkspaceID: "code", RelativePath: privateCanary}
	inventory := f.session(t, "inventory")
	dispatch := f.session(t, "dispatch")
	expectError[ResolvedProject](t, f.call(t, inventory, "resolve_project", args(t, request)), "forbidden")
	expectError[WorkspaceInventory](t, f.call(t, dispatch, "list_workspaces", args(t, WorkspacesInput{DeviceID: request.DeviceID})), "forbidden")
	result := f.call(t, dispatch, "resolve_project", args(t, request))
	envelope := decodeResult[ResolvedProject](t, result)
	if envelope.Error != nil || envelope.Data == nil || envelope.Data.ProjectAlias != request.RequestID || envelope.Data.RequestID != request.RequestID || envelope.Data.Workspace.ID != request.WorkspaceID {
		t.Fatal("dispatch-only workspace resolution lost immutable identity")
	}
	assertWorkspaceIdentityOnly(t, result)
	listedResult := decodeResult[WorkspaceInventory](t, f.call(t, inventory, "list_workspaces", args(t, WorkspacesInput{DeviceID: request.DeviceID})))
	if listedResult.Error != nil || listedResult.Data == nil || len(listedResult.Data.Workspaces) != 1 || backend.resolveCalls != 1 || backend.listCalls != 1 {
		t.Fatal("scope denial reached backend or inventory failed")
	}
}

// Dynamic resolution intentionally returns opaque guards as immutable replay
// identity. The legacy inventory helper forbids those guards altogether; this
// contract instead forbids raw selectors, paths and inferred readiness.
func assertWorkspaceIdentityOnly(t *testing.T, result *mcp.CallToolResult) {
	t.Helper()
	encoded, err := json.Marshal(result)
	check(t, err)
	for _, private := range []string{privateCanary, "relative_path", "execution_readiness", "providers", "root_guard", "project_guard"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("workspace identity response disclosed %s", private)
		}
	}
}

func TestSDKWorkspaceInputsRejectSpoofedUnknownAndMalformedIdentity(t *testing.T) {
	backend := &workspaceBackend{}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Workspaces = backend })
	session := f.session(t, "dispatch")
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"device_id":"device-one","request_id":"bad","workspace_id":"code","relative_path":"repo"}`),
		json.RawMessage(`{"device_id":"device-one","request_id":"` + strings.Repeat("e", 32) + `","workspace_id":"code","relative_path":"repo","principal":"` + privateCanary + `"}`),
		json.RawMessage(`{"device_id":"device-one","device_id":"other","request_id":"` + strings.Repeat("e", 32) + `","workspace_id":"code","relative_path":"repo"}`),
		json.RawMessage(`{"device_id":"device-one","request_id":"` + strings.Repeat("e", 32) + `","workspace_id":"code","relative_path":"../outside"}`),
	} {
		result := f.call(t, session, "resolve_project", raw)
		expectError[ResolvedProject](t, result, "invalid_request")
		assertPublic(t, result)
		if decodeResult[ResolvedProject](t, result).Error.RequestID != "" {
			t.Fatal("invalid input decorated an error with a retained request identity")
		}
	}
	if backend.resolveCalls != 0 {
		t.Fatal("invalid JSON/schema identity reached backend")
	}
}

func TestSDKWorkspaceFailuresRetainValidatedCallerIdentityWithoutChangingCause(t *testing.T) {
	backend := &workspaceBackend{}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Workspaces = backend })
	session := f.session(t, "dispatch")
	input := ResolveProjectInput{DeviceID: "device-one", RequestID: strings.Repeat("e", 32), WorkspaceID: "code", RelativePath: "repo"}
	for _, test := range []struct {
		name      string
		cause     error
		code      string
		retryable bool
	}{
		{name: "owner-denied", cause: domain.Reject(domain.NotFound), code: "not_found"},
		{name: "same-request-pending", cause: domain.Reject(domain.Pending), code: "pending", retryable: true},
		{name: "mixed-storage-fault", cause: errors.Join(domain.Reject(domain.NotFound), errors.New(privateCanary)), code: "internal_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend.failure = test.cause
			result := f.call(t, session, "resolve_project", args(t, input))
			expectError[ResolvedProject](t, result, test.code)
			failure := decodeResult[ResolvedProject](t, result).Error
			if failure.RequestID != input.RequestID || failure.Retryable != test.retryable {
				t.Fatalf("caller identity or failure semantics changed: %+v", failure)
			}
			assertPublic(t, result)
		})
	}
}

func TestSDKWorkspaceCapabilityQueriesTargetSavedHandleWithoutResolve(t *testing.T) {
	backend := &workspaceBackend{}
	f := newConfiguredFixture(t, 1, nil, func(options *Options) { options.Workspaces = backend })
	handle := strings.Repeat("e", 32)
	source := f.link.snapshot.Capabilities.Projects[0]
	source.Alias = handle
	source.Features = append(source.Features, protocol.WorkspaceFeature)
	source.Ready = false
	pin := protocol.ResolvedProject{Handle: handle, Workspace: protocol.WorkspaceBinding{ID: "code", Guard: protocol.WireContextGuard("workspace")}, Context: source.Context}
	destination := domain.Destination{Device: deviceID(0), Project: domain.ProjectAlias(handle)}
	check(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: destination, Context: domain.ContextBinding{Root: domain.RootGuard(source.Context.Root), Project: domain.ProjectGuard(source.Context.Project)}}))
	check(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.alice.Principal, Destination: destination}, Scopes: f.alice.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}}))
	backend.observation = gateway.TargetedProjectObservation{Capability: protocol.ProjectCapabilityV2{Project: pin, CurrentPolicyRevision: 3, Capability: source}, Credential: f.link.snapshot.Credential, Connection: f.link.snapshot.Connection, ObservedAt: f.clock.now()}
	f.link.snapshot.WireVersion = protocol.WireVersion2
	f.link.snapshot.CapabilitiesV2 = &protocol.CapabilityReportV2{ObservedAt: f.clock.now(), Root: &protocol.RootCapability{Root: source.Context.Root, ContractVersion: 1, Features: source.Features}, Workspaces: []protocol.WorkspaceCapability{}}
	result := decodeResult[Capabilities](t, f.call(t, f.session(t, "inventory"), "get_capabilities", args(t, CapabilitiesInput{DeviceID: string(destination.Device), ProjectAlias: handle})))
	if result.Error != nil || result.Data == nil || result.Data.Workspace == nil || result.Data.CurrentPolicyRevision == nil || *result.Data.CurrentPolicyRevision != 3 || backend.inspectScope != domain.InventoryRead || backend.inspectCalls != 1 || backend.resolveCalls != 0 {
		t.Fatal("capability tool did not use independent targeted inventory metadata")
	}
}
