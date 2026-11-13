package mcpadapter

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Presence supplies a dated observation only. The owner gate lets the test
// commit a real Registry revocation after SQL inventory and before projection.
type snapshotAuthorizationGate struct {
	snapshot gateway.LinkSnapshot
	entered  chan struct{}
	released chan struct{}
	once     sync.Once
}

func (g *snapshotAuthorizationGate) Snapshot(domain.DeviceID) (gateway.LinkSnapshot, error) {
	g.once.Do(func() { close(g.entered) })
	<-g.released
	return g.snapshot, nil
}

func TestV2InventoryRechecksCurrentRegistryAuthorityAfterSnapshot(t *testing.T) {
	for _, name := range []string{"list_devices", "list_projects"} {
		t.Run(name, func(t *testing.T) {
			for _, mutation := range []string{"owner-policy", "principal", "device"} {
				t.Run(mutation, func(t *testing.T) {
					assertV2InventoryRevocation(t, name, mutation)
				})
			}
		})
	}
}

func TestV2InventoryCurrentAuthorityReturnsDatedMetadata(t *testing.T) {
	for _, tool := range []string{"list_devices", "list_projects"} {
		t.Run(tool, func(t *testing.T) { assertCurrentV2Inventory(t, tool) })
	}
}

func assertCurrentV2Inventory(t *testing.T, tool string) {
	t.Helper()
	f, device, gate := newV2InventoryRecheckFixture(t, tool == "list_projects")
	close(gate.released)
	session := f.session(t, "inventory")
	var entry Device
	if tool == "list_devices" {
		envelope := decodeResult[DevicePage](t, f.call(t, session, tool, json.RawMessage(`{}`)))
		if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Devices) != 1 {
			t.Fatal("current zero-project device owner was denied")
		}
		entry = envelope.Data.Devices[0]
	} else {
		envelope := decodeResult[ProjectPage](t, f.call(t, session, tool, args(t, ProjectsInput{DeviceID: string(device)})))
		if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Projects) != 1 {
			t.Fatal("current exact-project owner was denied")
		}
		project := envelope.Data.Projects[0]
		if project.Alias != "public" {
			t.Fatal("inventory returned a different project")
		}
		entry = Device{Online: project.Online, DelegateReady: project.DelegateReady, ExecutionReadiness: project.ExecutionReadiness, ObservedAt: project.ObservedAt}
	}
	if !entry.Online || !entry.DelegateReady || entry.ExecutionReadiness != "unknown" || entry.ObservedAt == nil || !entry.ObservedAt.Equal(gate.snapshot.ObservedAt) {
		t.Fatal("current authority lost dated v2 observation")
	}
	f.assertEvents(t, observability.MCPToolResponseReady)
}

func assertV2InventoryRevocation(t *testing.T, tool, mutation string) {
	t.Helper()
	f, device, gate := newV2InventoryRecheckFixture(t, tool == "list_projects")
	var once sync.Once
	release := func() { once.Do(func() { close(gate.released) }) }
	input := json.RawMessage(`{}`)
	if tool == "list_projects" {
		input = args(t, ProjectsInput{DeviceID: string(device)})
	}
	results := beginBoundaryToolCall(t, f.fixture, f.session(t, "inventory"), tool, input)
	t.Cleanup(release)
	awaitBoundaryGate(t, gate.entered, results)
	code := revokeInventoryAuthority(t, f.fixture, device, mutation)
	release()
	result := <-results
	check(t, result.err)
	expectError[json.RawMessage](t, result.result, code)
	assertPublic(t, result.result)
	f.assertEvents(t, observability.AuthorizationDenied, observability.MCPToolErrorReady)
}

func revokeInventoryAuthority(t *testing.T, f *fixture, device domain.DeviceID, mutation string) string {
	t.Helper()
	switch mutation {
	case "owner-policy":
		check(t, f.store.DisableOwnerPolicy(t.Context(), f.alice.Principal))
		return "forbidden"
	case "principal":
		check(t, f.store.SetPrincipalRevoked(t.Context(), f.alice.Principal, true))
		return "forbidden"
	case "device":
		check(t, f.store.SetDeviceRevoked(t.Context(), device, true))
		return "not_found"
	default:
		t.Fatal("unknown fixture revocation")
		return ""
	}
}

func newV2InventoryRecheckFixture(t *testing.T, withProject bool) (*inventoryObservationFixture, domain.DeviceID, *snapshotAuthorizationGate) {
	t.Helper()
	directory := t.TempDir()
	check(t, os.Chmod(directory, 0o700))
	audit, err := observability.Open(directory, time.Now)
	check(t, err)
	t.Cleanup(func() { check(t, audit.Close()) })
	metrics := &observability.Metrics{}
	recorder, err := observability.NewRecorder(audit, metrics)
	check(t, err)
	f := &inventoryObservationFixture{fixture: newConfiguredFixture(t, 0, recorder, nil), directory: directory, recorder: recorder, metrics: metrics}
	policy := domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 1}
	check(t, f.store.PutOwnerPolicy(t.Context(), f.alice.Principal, policy))
	device, err := f.store.CreateOwnedEnrollment(t.Context(), f.alice.Principal, privateCanary, domain.Hash([]byte("fixture-bootstrap-token")), f.clock.now())
	check(t, err)
	if withProject {
		check(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: domain.Destination{Device: device.ID, Project: "public"}, Context: domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard("root")), Project: domain.ProjectGuard(protocol.WireContextGuard("project"))}}))
	}
	projects, err := f.store.ListProjects(t.Context(), f.alice, device.ID, domain.ProjectPageRequest{Limit: 10})
	check(t, err)
	if (len(projects.Items) != 0) != withProject {
		t.Fatal("fixture did not preserve the zero-project device partition")
	}
	// Credential and capability values are controlled presence fixtures. The
	// authorization mutations and rechecks use the actual SQLite Registry.
	now := f.clock.now()
	report := &protocol.CapabilityReportV2{
		ObservedAt: now,
		Root: &protocol.RootCapability{
			Root: protocol.WireContextGuard("root"), ContractVersion: protocol.NativeContractVersion,
			Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1", protocol.WorkspaceFeature},
		},
		Workspaces: []protocol.WorkspaceCapability{},
	}
	gate := &snapshotAuthorizationGate{
		entered: make(chan struct{}), released: make(chan struct{}),
		snapshot: gateway.LinkSnapshot{
			Credential: domain.CredentialRef{Device: device.ID, Epoch: "fixture-epoch", Generation: 1},
			Connection: domain.ConnectionGeneration{BootEpoch: "fixture-boot", Counter: 1},
			ObservedAt: now, WireVersion: protocol.WireVersion2, CapabilitiesV2: report,
		},
	}
	check(t, gate.snapshot.CapabilitiesV2.Validate())
	f.adapter.options.Presence = gate
	return f, device.ID, gate
}
