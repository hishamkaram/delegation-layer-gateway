package cli

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestRootProgressRejectsWrongRouteAndIncoherentPhase(t *testing.T) {
	input := adminapi.RootInput{DeviceID: "device", ProjectAlias: "project"}
	valid := adminapi.RootProgress{GatewayID: "gateway", DeviceID: "device", ProjectAlias: "project", RecoveryID: "recovery", Generation: "generation", Stage: domain.RootNeedsReopen}
	if !validRootProgress(input, valid) {
		t.Fatal("valid progress refused")
	}
	for _, mutate := range []func(*adminapi.RootProgress){
		func(p *adminapi.RootProgress) { p.DeviceID = "other" },
		func(p *adminapi.RootProgress) { p.ProjectAlias = "other" },
		func(p *adminapi.RootProgress) { p.Generation = "" },
		func(p *adminapi.RootProgress) { p.RecoveryID = "" },
		func(p *adminapi.RootProgress) { p.Stage = "unknown" },
	} {
		bad := valid
		mutate(&bad)
		if validRootProgress(input, bad) {
			t.Fatal("unbound or incoherent progress accepted")
		}
	}
	initial := valid
	initial.Stage = domain.RootNeedsBarrier
	initial.RecoveryID = ""
	initial.Generation = ""
	if !validRootProgress(input, initial) {
		t.Fatal("registered pending root refused")
	}
	initial.Generation = "unproven"
	if validRootProgress(input, initial) {
		t.Fatal("generation without durable session accepted")
	}
}
