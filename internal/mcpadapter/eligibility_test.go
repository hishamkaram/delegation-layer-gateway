package mcpadapter

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestAdvertisedDelegateReadyDoesNotOpenPendingRegistryRoot(t *testing.T) {
	f := newFixture(t, 1)
	route := domain.Destination{Device: deviceID(0), Project: "pending-root"}
	binding := domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard("pending-root")), Project: domain.ProjectGuard(protocol.WireContextGuard("pending-project"))}
	check(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: route, Context: binding}))
	check(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.alice.Principal, Destination: route}, Scopes: f.alice.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 120}}))
	advertised := f.link.snapshot.Capabilities.Projects[0]
	advertised.Alias = string(route.Project)
	advertised.Context = protocol.ContextBinding{Root: string(binding.Root), Project: string(binding.Project)}
	advertised.AdmissionGeneration = "delegate-open-unconfirmed-generation"
	advertised.Providers[0].Authentication = "verified"
	f.link.snapshot.Capabilities.Projects = []protocol.ProjectCapability{advertised}
	session := f.session(t, "alice")
	assertPendingCapabilities(t, f, session, route)
	assertPendingInventory(t, f, session, route)
}

func assertPendingCapabilities(t *testing.T, f *fixture, session *mcp.ClientSession, route domain.Destination) {
	t.Helper()
	capabilities := decodeResult[Capabilities](t, f.call(t, session, "get_capabilities", args(t, CapabilitiesInput{DeviceID: string(route.Device), ProjectAlias: string(route.Project)})))
	if capabilities.Error != nil || capabilities.Data == nil {
		t.Fatal("authorized online capability became unobservable")
	}
	if !capabilities.Data.Online || !capabilities.Data.DelegateReady || capabilities.Data.ExecutionReadiness != "not_ready" {
		t.Errorf("pending root advertised executable: %+v", capabilities.Data)
	}
}

func assertPendingInventory(t *testing.T, f *fixture, session *mcp.ClientSession, route domain.Destination) {
	t.Helper()

	devices := decodeResult[DevicePage](t, f.call(t, session, "list_devices", json.RawMessage(`{}`)))
	if devices.Error != nil || devices.Data == nil || len(devices.Data.Devices) != 1 {
		t.Fatal("device inventory failed")
	}
	if !devices.Data.Devices[0].Online || devices.Data.Devices[0].ExecutionReadiness != "not_ready" {
		t.Error("device summary bypassed root eligibility")
	}
	projects := decodeResult[ProjectPage](t, f.call(t, session, "list_projects", args(t, ProjectsInput{DeviceID: string(route.Device)})))
	if projects.Error != nil || projects.Data == nil {
		t.Fatal("project inventory failed")
	}
	found := false
	for _, project := range projects.Data.Projects {
		if project.Alias == string(route.Project) {
			found = true
			if !project.Online || !project.DelegateReady || project.ExecutionReadiness != "not_ready" {
				t.Error("project summary bypassed root eligibility")
			}
		}
	}
	if !found {
		t.Fatal("authorized pending project hidden")
	}
}
