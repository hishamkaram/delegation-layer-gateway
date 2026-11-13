package connector

import (
	"slices"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestProbeRequiresNamespaceMutationLeaseForReadiness(t *testing.T) {
	for _, supported := range []bool{false, true} {
		name := "admission-only"
		if supported {
			name = "admission-and-mutation-lease"
		}
		t.Run(name, func(t *testing.T) {
			f := nativeFeaturesFixture(t, supported)
			report := f.adapter.Probe(t.Context())
			if len(report.Projects) != 1 || report.Validate() != nil {
				t.Fatal("probe did not produce a valid project observation")
			}
			if report.Projects[0].Ready != supported || f.adapter.Status().Ready != supported {
				t.Errorf("project ready = %t, adapter ready = %t; want %t", report.Projects[0].Ready, f.adapter.Status().Ready, supported)
			}
			if supported && !slices.Contains(report.Projects[0].Features, "namespace-mutation-lease-v1") {
				t.Error("project observation discarded required mutation-lease proof")
			}
			assertNativeFeaturesSettled(t, f)
		})
	}
}

func TestAdmissionRequiresNamespaceMutationLeaseBeforeDispatch(t *testing.T) {
	for _, supported := range []bool{false, true} {
		name := "admission-only"
		if supported {
			name = "admission-and-mutation-lease"
		}
		t.Run(name, func(t *testing.T) {
			f := nativeFeaturesFixture(t, supported)
			task := f.task()
			task.SpecSHA256 = ""
			admission := protocol.Admission{Task: task, Provider: "fixture", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}, Permission: "read-only", BudgetSeconds: 120, Brief: f.state.Brief}
			reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.Admit, Project: "project-one", Body: encoded(t, admission)})
			assertFeatureAdmission(t, f, reply, task, supported)
			assertNativeFeaturesSettled(t, f)
		})
	}
}

func TestCapabilityReportsProjectRecognizedActualFeatures(t *testing.T) {
	for _, rootOnly := range []bool{false, true} {
		name := "project"
		if rootOnly {
			name = "root"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.state.Features = []string{"future-feature", "namespace-mutation-lease-v1", "namespace-admission-v1", "namespace-mutation-lease-v1"}
			f.writeState()
			reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: encoded(t, protocol.InspectRequest{GatewayID: "gateway-one", RootOnly: rootOnly})})
			if reply.Error != nil {
				t.Fatal(reply.Error.Code)
			}
			features := capabilityReportFeatures(t, reply, rootOnly)
			if !slices.Equal(features, []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}) {
				t.Errorf("report features = %v, want canonical recognized evidence", features)
			}
		})
	}
}

func TestOriginProofRequiresBothNativeFeatures(t *testing.T) {
	for _, features := range [][]string{{"namespace-admission-v1"}, {"namespace-mutation-lease-v1"}} {
		t.Run(features[0], func(t *testing.T) {
			r := inventoryRequestFixture()
			response := cliResponse{Connector: &cliConnector{ContractVersion: 1, RootToken: r.project.RootToken, Features: features, Inventory: localInventory()}}
			assertCode(t, r.translateOrigin(response), "evidence_invalid")
		})
	}
}

func nativeFeaturesFixture(t *testing.T, supported bool) *fixture {
	t.Helper()
	f := newFixture(t)
	f.state.Features = []string{"namespace-admission-v1"}
	if supported {
		f.state.Features = append(f.state.Features, "namespace-mutation-lease-v1")
	}
	f.writeState()
	return f
}

func assertNativeFeaturesSettled(t *testing.T, f *fixture) {
	t.Helper()
	if status := f.adapter.Status(); status.Active != 0 || status.CleanupPending != 0 {
		t.Errorf("feature check retained process ownership: %+v", status)
	}
}

func assertFeatureAdmission(t *testing.T, f *fixture, reply protocol.Reply, task protocol.TaskBinding, supported bool) {
	t.Helper()
	dispatches := 0
	for _, call := range f.calls() {
		if call.Command == "dispatch" {
			dispatches++
		}
	}
	if !supported {
		if dispatches != 0 {
			t.Errorf("unsupported Delegate reached dispatch %d times", dispatches)
		}
		assertCode(t, reply, "incompatible_delegate")
		return
	}
	if dispatches != 1 {
		t.Errorf("dispatch count = %d, want 1", dispatches)
	}
	if result := observation(t, reply); result.Task.TaskID != task.TaskID {
		t.Error("admission changed task identity")
	}
}

func capabilityReportFeatures(t *testing.T, reply protocol.Reply, rootOnly bool) []string {
	t.Helper()
	if rootOnly {
		var report protocol.RootCapability
		if err := protocol.DecodeStrict(reply.Body, &report, protocol.MaxFrameBytes); err != nil || report.Validate() != nil {
			t.Fatal("invalid root report")
		}
		return report.Features
	}
	var report protocol.ProjectCapability
	if err := protocol.DecodeStrict(reply.Body, &report, protocol.MaxFrameBytes); err != nil || report.Validate() != nil {
		t.Fatal("invalid project report")
	}
	return report.Features
}
