package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func TestRoutingRecoveryPendingCannotHideFleetScanOverflow(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "overflow-recovery", Epoch: "overflow-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "overflow-recovery", []domain.DeviceID{"device", "device2", "missing-device"}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "overflow-connection", f.now)
	f.connection = must(t, generation, err)
	var active []protocol.ControlCall
	for number := 1; number <= 6; number++ {
		call := routingRequest(t, f, protocol.Status, number).Call
		call.Generation = protocol.Generation{BootEpoch: "lost-gateway", Counter: 1}
		active = append(active, call)
	}
	f.reconcileRouting(t, active)
	// This device has no scan; the protected pool also has no permits. Only the
	// known fleet overflow must prevent recovery from adding a seventh scan.
	idle := addRoutingDeviceMode(t, f, "device2", domain.RecoveryOnly)
	target, err := idle.store.ReadRoutingDrainTarget(t.Context(), idle.credential.Device, idle.now)
	current := must(t, target, err)
	_, err = idle.store.AttestRoutingDrained(t.Context(), routing.Drain{Device: current.Device, Credential: current.Credential, Recovery: current.Recovery, Scope: routing.AllPriorControls, CurrentBoot: current.ProcessBoot, Generation: current.Generation, Now: idle.now})
	requireOK(t, err)
	err = idle.store.AcquireRouting(t.Context(), routingRequest(t, idle, protocol.Cancel, 1))
	requireCode(t, err, domain.Pending)
	status, err := idle.store.CheckRoutingReadiness(t.Context(), idle.credential, idle.connection, idle.now)
	if got := must(t, status, err); got.Ready || got.Reason != routing.CapacityExceeded || got.Outstanding != 0 {
		t.Fatal("incomplete recovery masked known fleet overflow")
	}
	if routingOutstanding(t, f) != 6 {
		t.Fatal("rejected protected control changed imported permits")
	}
}

type (
	routingAdminMarker struct{}
	routingJWTMarker   struct{}
	routingMarkedAdmin struct{}
)

func (routingMarkedAdmin) AuthorizeAdmin(ctx context.Context) error {
	marked, ok := ctx.Value(routingAdminMarker{}).(bool)
	if !ok || !marked {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

func TestRoutingRecoveryRequiresFullRosterBeforeAnyCLIControl(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "pending-routing", Epoch: "pending-epoch", Now: f.now})
	requireOK(t, err)
	f.credential = f.enroll(t, domain.RecoveryOnly)
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "recovery-connection", f.now)
	f.connection = must(t, generation, err)
	status := f.reconcileRouting(t, nil)
	if status.Ready || status.Reason != "recovery_pending" {
		t.Fatal("unsealed roster became ready")
	}
	f.store.admin = routingMarkedAdmin{}
	admin := context.WithValue(t.Context(), routingAdminMarker{}, true)
	jwt := context.WithValue(t.Context(), routingJWTMarker{}, f.actor)
	for number, operation := range []protocol.Operation{protocol.OriginBarrier, protocol.OriginInventory, protocol.ContextInspect, protocol.Status, protocol.Cancel} {
		request := routingRequest(t, f, operation, number+1)
		for _, caller := range []context.Context{t.Context(), jwt, admin} {
			requireCode(t, f.store.AcquireRouting(caller, request), domain.Pending)
		}
	}
	if routingOutstanding(t, f) != 0 {
		t.Fatal("precoverage controls inserted a permit")
	}
	requireCode(t, f.store.AcquireRouting(admin, routingRequest(t, f, protocol.OriginReopen, 6)), domain.Forbidden)
	if admissionErr := f.store.AcquireRouting(admin, routingRequest(t, f, protocol.Admit, 7)); !errors.Is(admissionErr, domain.ErrInvalid) {
		t.Fatalf("recovery allowed fresh admission: %v", admissionErr)
	}
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(admin, "pending-routing", []domain.DeviceID{"device"}))
	generation, err = f.store.NextConnectionGeneration(t.Context(), f.credential, "fenced-recovery-connection", f.now)
	f.connection = must(t, generation, err)
	status = f.reconcileRouting(t, nil)
	if !status.Ready {
		t.Fatal("covered roster remained blocked after complete fenced census")
	}
	request := routingRequest(t, f, protocol.OriginBarrier, 1)
	requireCode(t, f.store.AcquireRouting(t.Context(), request), domain.Forbidden)
	requireOK(t, f.store.AcquireRouting(admin, request))
	completeRouting(t, f, request, protocol.ControlSettled)
}

func TestRoutingAdministrativeControlsNeedAdminEvenWhenReady(t *testing.T) {
	f := newFixture(t)
	f.store.admin = routingMarkedAdmin{}
	admin := context.WithValue(t.Context(), routingAdminMarker{}, true)
	for number, operation := range []protocol.Operation{protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen} {
		request := routingRequest(t, f, operation, number+1)
		requireCode(t, f.store.AcquireRouting(t.Context(), request), domain.Forbidden)
		requireOK(t, f.store.AcquireRouting(admin, request))
		completeRouting(t, f, request, protocol.ControlSettled)
	}
}
