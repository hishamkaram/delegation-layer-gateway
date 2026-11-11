package mcpadapter

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func args[T any](t *testing.T, value T) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	return checked(t, encoded, err)
}

func assertPublic(t *testing.T, result *mcp.CallToolResult) {
	t.Helper()
	encoded, err := json.Marshal(result)
	data := string(checked(t, encoded, err))
	for _, private := range []string{privateCanary, "hidden-alias-canary", "ctx1_", "private project path", "root_guard", "project_guard"} {
		if strings.Contains(data, private) {
			t.Fatalf("public tool response leaked private marker %s", private)
		}
	}
}

func TestAuthorizedDeviceInventoryPaginationZeroOneAndTwoHundred(t *testing.T) {
	for _, count := range []int{0, 1, 200} {
		t.Run(fmt.Sprintf("devices-%d", count), func(t *testing.T) {
			f := newFixture(t, count)
			session := f.session(t, "alice")
			assertDevicePages(t, f, session, count)
			expectError[DevicePage](t, f.call(t, session, "list_devices", json.RawMessage(`{"limit":101}`)), "invalid_request")
			bob := f.session(t, "bob")
			denied := decodeResult[DevicePage](t, f.call(t, bob, "list_devices", json.RawMessage(`{}`)))
			if denied.Error != nil || denied.Data == nil || len(denied.Data.Devices) != 0 {
				t.Fatal("device inventory disclosed another principal's grants")
			}
		})
	}
}

func (f *fixture) project(t *testing.T, alias string, grant bool) {
	t.Helper()
	destination := domain.Destination{Device: deviceID(0), Project: domain.ProjectAlias(alias)}
	check(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: destination, Context: domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard(privateCanary)), Project: domain.ProjectGuard(protocol.WireContextGuard("local " + alias))}}))
	if grant {
		check(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.alice.Principal, Destination: destination}, Scopes: f.alice.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 120}}))
	}
}

func TestProjectPaginationAndDeviceReadinessIncludeAuthorizedSecondPage(t *testing.T) {
	f := newFixture(t, 1)
	for i := range 199 {
		f.project(t, fmt.Sprintf("project-%03d", i), true)
	}
	f.project(t, "hidden-alias-canary", false)
	session := f.session(t, "alice")
	assertProjectPages(t, f, session)
	devices := decodeResult[DevicePage](t, f.call(t, session, "list_devices", json.RawMessage(`{}`)))
	if devices.Error != nil || devices.Data == nil || len(devices.Data.Devices) != 1 || !devices.Data.Devices[0].DelegateReady {
		t.Fatal("device readiness ignored its authorized ready project on the second page")
	}
	expectError[Capabilities](t, f.call(t, session, "get_capabilities", args(t, CapabilitiesInput{DeviceID: string(deviceID(0)), ProjectAlias: "hidden-alias-canary"})), "not_found")
}

func TestOnlineCompatibilityAndProviderAuthenticationRemainDistinct(t *testing.T) {
	cases := []struct {
		name          string
		change        func(*fixture)
		online, ready bool
		execution     string
	}{
		{"auth unknown", func(*fixture) {}, true, true, "unknown"},
		{"offline", func(f *fixture) {
			f.link.err = &gateway.RemoteError{Failure: protocol.Failure{Code: "device_offline", Retryable: true}}
		}, false, false, "not_ready"},
		{"compatible false", func(f *fixture) { f.link.snapshot.Capabilities.Projects[0].Ready = false }, true, false, "not_ready"},
		{"auth unavailable", func(f *fixture) { f.link.snapshot.Capabilities.Projects[0].Providers[0].Authentication = "unavailable" }, true, true, "not_ready"},
		{"auth verified", func(f *fixture) { f.link.snapshot.Capabilities.Projects[0].Providers[0].Authentication = "verified" }, true, true, "ready"},
		{"online before capabilities", func(f *fixture) {
			f.link.snapshot.Capabilities.ObservedAt = time.Time{}
			f.link.snapshot.Capabilities.Projects = nil
			f.link.snapshot.ObservedAt = time.Time{}
		}, true, false, "not_ready"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, 1)
			test.change(f)
			session := f.session(t, "alice")
			envelope := decodeResult[DevicePage](t, f.call(t, session, "list_devices", json.RawMessage(`{}`)))
			if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Devices) != 1 {
				t.Fatal("dated device presence was not observable")
			}
			device := envelope.Data.Devices[0]
			if device.Online != test.online || device.DelegateReady != test.ready || device.ExecutionReadiness != test.execution {
				t.Fatalf("presence/compatibility/authentication conflated: %+v", device)
			}
			if test.name == "online before capabilities" && device.ObservedAt != nil {
				t.Fatal("unobserved capabilities acquired a fabricated freshness timestamp")
			}
		})
	}
}

func TestHiddenProjectReadinessDoesNotLeakThroughDeviceSummary(t *testing.T) {
	f := newFixture(t, 1)
	f.project(t, "hidden-alias-canary", false)
	f.link.snapshot.Capabilities.Projects[0].Ready = false
	hidden := f.link.snapshot.Capabilities.Projects[0]
	hidden.Alias = "hidden-alias-canary"
	hidden.Ready = true
	hidden.Context.Project = protocol.WireContextGuard("hidden private path")
	hidden.Providers = []protocol.ProviderCapability{{Provider: "provider", Permissions: []string{"read-only"}, MaxBudgetSeconds: 300, Authentication: "verified"}}
	f.link.snapshot.Capabilities.Projects = append(f.link.snapshot.Capabilities.Projects, hidden)
	session := f.session(t, "alice")
	result := f.call(t, session, "list_devices", json.RawMessage(`{}`))
	assertPublic(t, result)
	envelope := decodeResult[DevicePage](t, result)
	if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Devices) != 1 || envelope.Data.Devices[0].DelegateReady || envelope.Data.Devices[0].ExecutionReadiness != "not_ready" {
		t.Fatal("hidden project capabilities affected authorized device readiness")
	}
}

func TestCapabilitiesExposeEffectiveCurrentActorCeiling(t *testing.T) {
	f := newFixture(t, 1)
	session := f.session(t, "alice")
	input := args(t, CapabilitiesInput{DeviceID: string(deviceID(0)), ProjectAlias: "public"})
	result := f.call(t, session, "get_capabilities", input)
	assertPublic(t, result)
	envelope := decodeResult[Capabilities](t, result)
	if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Providers) != 1 {
		t.Fatal("authorized capabilities missing")
	}
	provider := envelope.Data.Providers[0]
	if !provider.DispatchAllowed || provider.MaxBudgetSeconds != 120 || len(provider.Permissions) != 1 || provider.Permissions[0] != "read-only" || provider.Authentication != "unknown" {
		t.Fatalf("ceiling was not intersected with actor grant: %+v", provider)
	}
	inventory := f.session(t, "inventory")
	envelope = decodeResult[Capabilities](t, f.call(t, inventory, "get_capabilities", input))
	if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Providers) != 1 || envelope.Data.Providers[0].DispatchAllowed || envelope.Data.Providers[0].MaxBudgetSeconds != 0 || len(envelope.Data.Providers[0].Permissions) != 0 {
		t.Fatal("inventory-only token gained dispatch authority")
	}
}

func TestProjectInventoryZeroAndOneAuthorizedAlias(t *testing.T) {
	for _, test := range []struct {
		token string
		count int
	}{{"bob", 0}, {"alice", 1}} {
		t.Run(test.token, func(t *testing.T) {
			f := newFixture(t, 1)
			session := f.session(t, test.token)
			result := f.call(t, session, "list_projects", args(t, ProjectsInput{DeviceID: string(deviceID(0)), Limit: 100}))
			assertPublic(t, result)
			envelope := decodeResult[ProjectPage](t, result)
			if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Projects) != test.count {
				t.Fatal("project inventory ignored the current actor's effective grants")
			}
		})
	}
}

func assertDevicePages(t *testing.T, f *fixture, session *mcp.ClientSession, count int) {
	t.Helper()
	request := PageInput{Limit: 100}
	seen := make(map[string]bool)
	for {
		result := f.call(t, session, "list_devices", args(t, request))
		assertPublic(t, result)
		envelope := decodeResult[DevicePage](t, result)
		if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Devices) > 100 {
			t.Fatal("inventory failed or exceeded page bound")
		}
		for _, device := range envelope.Data.Devices {
			if seen[device.DeviceID] {
				t.Fatal("pagination repeated a device")
			}
			seen[device.DeviceID] = true
		}
		if envelope.Data.NextCursor == "" {
			break
		}
		request.Cursor = envelope.Data.NextCursor
	}
	if len(seen) != count {
		t.Fatalf("got %d authorized fixtures, want %d", len(seen), count)
	}
}

func assertProjectPages(t *testing.T, f *fixture, session *mcp.ClientSession) {
	t.Helper()
	request := ProjectsInput{DeviceID: string(deviceID(0)), Limit: 100}
	seen := make(map[string]bool)
	for {
		result := f.call(t, session, "list_projects", args(t, request))
		assertPublic(t, result)
		envelope := decodeResult[ProjectPage](t, result)
		if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Projects) > 100 {
			t.Fatal("project inventory exceeded its authorized page bound")
		}
		for _, project := range envelope.Data.Projects {
			if seen[project.Alias] || project.Alias == "hidden-alias-canary" {
				t.Fatal("project inventory repeated or exposed a hidden alias")
			}
			seen[project.Alias] = true
		}
		if envelope.Data.NextCursor == "" {
			break
		}
		request.Cursor = envelope.Data.NextCursor
	}
	if len(seen) != 200 || !seen["public"] {
		t.Fatal("project pagination omitted authorized aliases")
	}
}
