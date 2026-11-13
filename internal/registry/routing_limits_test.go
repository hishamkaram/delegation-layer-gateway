package registry

import (
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func TestRoutingOrdinaryAndProtectedPoolsDoNotBorrow(t *testing.T) {
	f := newFixture(t)
	for number := 1; number <= 32; number++ {
		requireOK(t, f.store.AcquireRouting(t.Context(), routingRequest(t, f, protocol.ContextInspect, number)))
	}
	requireCode(t, f.store.AcquireRouting(t.Context(), routingRequest(t, f, protocol.OriginInventory, 33)), domain.ResourceLimit)
	protected := routingRequest(t, f, protocol.Cancel, 34)
	requireOK(t, f.store.AcquireRouting(t.Context(), protected))
	requireCode(t, f.store.AcquireRouting(t.Context(), routingRequest(t, f, protocol.FenceAbsent, 35)), domain.ResourceLimit)
	completeRouting(t, f, protected, protocol.ControlNotClaimed)
	requireCode(t, f.store.AcquireRouting(t.Context(), routingRequest(t, f, protocol.ContextInspect, 36)), domain.ResourceLimit)
	if routingOutstanding(t, f) != 32 {
		t.Fatal("protected completion altered ordinary pool")
	}
}

func TestRoutingRestoreImportsActiveCallsConservatively(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "routing-restore", Epoch: "restored-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "routing-restore", []domain.DeviceID{"device"}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "restored-gateway", f.now)
	f.connection = must(t, generation, err)
	var active []protocol.ControlCall
	for number := 1; number <= 6; number++ {
		request := routingRequest(t, f, protocol.Status, number)
		request.Call.Generation = protocol.Generation{BootEpoch: "lost-gateway", Counter: 1}
		active = append(active, request.Call)
	}
	status := f.reconcileRouting(t, active)
	if status.Ready || status.Reason != routing.CapacityExceeded || status.Outstanding != 6 {
		t.Fatal("restore discarded active overflow controls")
	}
	requireCode(t, f.store.AcquireRouting(t.Context(), routingRequest(t, f, protocol.ContextInspect, 7)), domain.Pending)
	f.restart(t)
	if routingOutstanding(t, f) != 6 {
		t.Fatal("restart freed imported controls")
	}
	for _, call := range active {
		requireOK(t, f.store.CompleteRouting(t.Context(), f.credential, f.connection, protocol.ControlCompletion{ProcessBoot: fixtureProcessBoot, Call: call, Disposition: protocol.ControlSettled}, f.now))
	}
	statusResult, err := f.store.CheckRoutingReadiness(t.Context(), f.credential, f.connection, f.now)
	if status := must(t, statusResult, err); !status.Ready || status.Outstanding != 0 {
		t.Fatal("conclusive imported controls did not drain")
	}
}

func TestRoutingRestoreRequiresExplicitCompletePriorRoster(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "routing-roster", Epoch: "new-epoch", Now: f.now})
	requireOK(t, err)
	requireCode(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "wrong", []domain.DeviceID{"device"}), domain.Conflict)
	requireCode(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "routing-roster", nil), domain.EvidenceInvalid)
	prior := []domain.DeviceID{"missing-after-snapshot", "device"}
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "routing-roster", prior))
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "routing-roster", []domain.DeviceID{"device", "missing-after-snapshot"}))
	requireCode(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "routing-roster", []domain.DeviceID{"device"}), domain.Conflict)
	f.credential = f.enroll(t, domain.RecoveryOnly)
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "recovery-gateway", f.now)
	f.connection = must(t, generation, err)
	status := f.reconcileRouting(t, nil)
	if status.Ready || status.Reason != routing.RecoveryPending {
		t.Fatal("present snapshot device implied complete fleet coverage")
	}
	f.restart(t)
	f.store.admin = nil // Incomplete fleet coverage blocks every routed CLI control.
	requireCode(t, f.store.AcquireRouting(t.Context(), routingRequest(t, f, protocol.ContextInspect, 1)), domain.Pending)
}

func TestRoutingMalformedInventoriesNeverRelease(t *testing.T) {
	f := newFixture(t)
	request := routingRequest(t, f, protocol.Status, 1)
	requireOK(t, f.store.AcquireRouting(t.Context(), request))
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "next-gateway", f.now)
	f.connection = must(t, generation, err)
	base := protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: fixtureProcessBoot, BarrierID: strings.Repeat("a", 32), Generation: protocol.Generation{BootEpoch: string(f.connection.BootEpoch), Counter: f.connection.Counter}, Complete: true, Active: []protocol.ControlCall{request.Call}}
	cases := []struct {
		name   string
		change func(*protocol.ControlInventory)
	}{
		{"incomplete", func(r *protocol.ControlInventory) { r.Complete = false }},
		{"duplicate", func(r *protocol.ControlInventory) { r.Active = append(r.Active, r.Active[0]) }},
		{"oversize", func(r *protocol.ControlInventory) {
			for range 7 {
				r.Active = append(r.Active, r.Active[0])
			}
		}},
		{"conflicting-digest", func(r *protocol.ControlInventory) { r.Active[0].RequestSHA256 = strings.Repeat("f", 64) }},
		{"future-generation", func(r *protocol.ControlInventory) {
			r.Active[0].Generation = r.Generation
			r.Active[0].Generation.Counter++
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report := base
			report.Active = append([]protocol.ControlCall(nil), base.Active...)
			test.change(&report)
			if _, err := f.store.ReconcileRouting(t.Context(), f.credential, report, f.now); err == nil {
				t.Fatal("malformed inventory accepted")
			}
			if routingOutstanding(t, f) != 1 {
				t.Fatal("malformed inventory released capacity")
			}
		})
	}
	status := f.reconcileRouting(t, []protocol.ControlCall{request.Call})
	if !status.Ready || status.Outstanding != 1 {
		t.Fatal("invalid reports damaged valid handshake")
	}
}
