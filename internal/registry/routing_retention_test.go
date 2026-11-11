package registry

import (
	"database/sql"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func reconnectRoutingFixture(t *testing.T, f *fixture, boot string, active []protocol.ControlCall) routing.Readiness {
	t.Helper()
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "retention-gateway", f.now)
	f.connection = must(t, generation, err)
	report := protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: boot, BarrierID: strings.Repeat("a", 32), Generation: protocol.Generation{BootEpoch: string(generation.BootEpoch), Counter: generation.Counter}, Complete: true, Active: active}
	status, err := f.store.ReconcileRouting(t.Context(), f.credential, report, f.now)
	return must(t, status, err)
}

func routingDrainForTarget(target routing.DrainTarget, f *fixture) routing.Drain {
	return routing.Drain{Device: target.Device, Credential: target.Credential, Recovery: target.Recovery, Scope: routing.AllPriorControls, CurrentBoot: target.ProcessBoot, Generation: target.Generation, Now: f.now}
}

func TestRoutingCompactionBoundsSettledHistoryAndKeepsCurrentReplayFence(t *testing.T) {
	f := newFixture(t)
	for number := 1; number <= 12; number++ {
		request := routingRequest(t, f, protocol.ContextInspect, number)
		requireOK(t, f.store.AcquireRouting(t.Context(), request))
		completeRouting(t, f, request, protocol.ControlSettled)
		requireCode(t, f.store.AcquireRouting(t.Context(), request), domain.Conflict)
		reconnectRoutingFixture(t, f, fixtureProcessBoot, nil)
		requireCode(t, f.store.AcquireRouting(t.Context(), request), domain.Conflict)
		var count int
		requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM routing_permits").Scan(&count))
		if count != 0 {
			t.Fatal("settled history survived a newer fenced census")
		}
	}
}

func TestRoutingCompactionPreservesActiveAndHigherRollbackCounters(t *testing.T) {
	f := newFixture(t)
	active := routingRequest(t, f, protocol.Status, 1)
	requireOK(t, f.store.AcquireRouting(t.Context(), active))
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "rollback-routing", Epoch: "rollback-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "rollback-routing", []domain.DeviceID{"device"}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	future := routingRequest(t, f, protocol.ContextInspect, 40).Call
	future.Generation = protocol.Generation{BootEpoch: "lost-future-gateway", Counter: 40}
	reconnectRoutingFixture(t, f, fixtureProcessBoot, []protocol.ControlCall{active.Call, future})
	requireOK(t, f.store.CompleteRouting(t.Context(), f.credential, f.connection, protocol.ControlCompletion{ProcessBoot: fixtureProcessBoot, Call: future, Disposition: protocol.ControlSettled}, f.now))
	reconnectRoutingFixture(t, f, fixtureProcessBoot, []protocol.ControlCall{active.Call})
	var state string
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT state FROM routing_permits WHERE request=? AND connection_counter=40", future.RequestID).Scan(&state))
	if state != "settled" || routingOutstanding(t, f) != 1 {
		t.Fatal("compaction lost a higher rollback tombstone or an older active hold")
	}
	report := protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: fixtureProcessBoot, BarrierID: strings.Repeat("b", 32), Generation: protocol.Generation{BootEpoch: "retention-gateway", Counter: f.connection.Counter + 1}, Complete: true, Active: []protocol.ControlCall{future}}
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "retention-gateway", f.now)
	f.connection = must(t, generation, err)
	_, err = f.store.ReconcileRouting(t.Context(), f.credential, report, f.now)
	requireCode(t, err, domain.EvidenceInvalid)
	missing := future
	missing.Generation.Counter = 1
	missing.RequestID = "g:999"
	report.Active = []protocol.ControlCall{missing}
	_, err = f.store.ReconcileRouting(t.Context(), f.credential, report, f.now)
	requireCode(t, err, domain.EvidenceInvalid)
}

func TestRoutingStaleTerminalAcknowledgmentIsIndependentOfCompaction(t *testing.T) {
	f := newFixture(t)
	request := routingRequest(t, f, protocol.ContextInspect, 1)
	requireOK(t, f.store.AcquireRouting(t.Context(), request))
	reconnectRoutingFixture(t, f, fixtureProcessBoot, []protocol.ControlCall{request.Call})
	_, err := f.store.db.ExecContext(t.Context(), "UPDATE routing_permits SET state='admin_drained'")
	requireOK(t, err)
	completion := protocol.ControlCompletion{ProcessBoot: fixtureProcessBoot, Call: request.Call, Disposition: protocol.ControlSettled}
	completion.Call.RequestSHA256 = strings.Repeat("f", 64)
	before := migrationSnapshot(t, f.store.db)
	requireOK(t, f.store.CompleteRouting(t.Context(), f.credential, f.connection, completion, f.now))
	if !reflect.DeepEqual(before, migrationSnapshot(t, f.store.db)) {
		t.Fatal("stale terminal acknowledgment changed state")
	}
	_, err = transaction(t.Context(), f.store, func(tx *sql.Tx) (struct{}, error) {
		return struct{}{}, compactRoutingPermits(t.Context(), tx, "device", f.connection.Counter)
	})
	requireOK(t, err)
	requireOK(t, f.store.CompleteRouting(t.Context(), f.credential, f.connection, completion, f.now))
	completion.Disposition = protocol.ControlPending
	err = f.store.CompleteRouting(t.Context(), f.credential, f.connection, completion, f.now)
	requireCode(t, err, domain.NotFound)
	completion.Disposition = protocol.ControlSettled
	completion.Call.Generation = protocol.Generation{BootEpoch: string(f.connection.BootEpoch), Counter: f.connection.Counter}
	err = f.store.CompleteRouting(t.Context(), f.credential, f.connection, completion, f.now)
	requireCode(t, err, domain.NotFound)
}

func restoreRoutingSnapshot(t *testing.T, f *fixture, missingPeer bool) {
	t.Helper()
	if missingPeer {
		_, err := f.store.db.ExecContext(t.Context(), "DELETE FROM routing_peers")
		requireOK(t, err)
	}
	requireOK(t, f.store.Close())
	snapshot, err := os.ReadFile(f.path)
	requireOK(t, err)
	store, err := Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, store, err)
	if missingPeer {
		f.reconcileRouting(t, nil)
	}
	requireOK(t, f.store.AcquireRouting(t.Context(), routingRequest(t, f, protocol.Status, 900)))
	requireOK(t, f.store.Close())
	requireOK(t, os.WriteFile(f.path, snapshot, 0o600))
	store, err = Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, store, err)
	if routingOutstanding(t, f) != 0 {
		t.Fatal("test snapshot did not lose the later control as intended")
	}
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "sticky-routing", Epoch: "sticky-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "sticky-routing", []domain.DeviceID{"device"}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
}

func TestRoutingRestoreEmptyReplacementCensusKeepsUnknownDebt(t *testing.T) {
	cases := []struct {
		name    string
		missing bool
	}{{"known-prior", false}, {"missing-prior", true}}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assertStickyRoutingDebt(t, test.missing)
		})
	}
}

func assertStickyRoutingDebt(t *testing.T, missing bool) {
	t.Helper()
	f := newFixture(t)
	restoreRoutingSnapshot(t, f, missing)
	boot := strings.Repeat("b", 32)
	var earlier routing.Drain
	for range 2 {
		status := reconnectRoutingFixture(t, f, boot, nil)
		if status.Ready || status.Reason != routing.ProcessChanged {
			t.Fatal("empty replacement RAM cleared unknown prior CLI ownership")
		}
		if earlier.CurrentBoot == "" {
			target, err := f.store.ReadRoutingDrainTarget(t.Context(), "device", f.now)
			earlier = routingDrainForTarget(must(t, target, err), f)
		}
	}
	_, err := f.store.AttestRoutingDrained(t.Context(), earlier)
	requireCode(t, err, domain.Conflict)
	target, err := f.store.ReadRoutingDrainTarget(t.Context(), "device", f.now)
	current := must(t, target, err)
	if !current.Blocked || current.Covered {
		t.Fatal("sticky debt was not visible in the trusted target")
	}
	drain := routingDrainForTarget(current, f)
	// All-prior confirmation preserves current-owner holds even when the
	// recorded control came from an older connection generation.
	carried := routingRequest(t, f, protocol.ContextInspect, 901)
	carried.ProcessBoot = boot
	carried.Call.Generation.Counter--
	_, err = transaction(t.Context(), f.store, func(tx *sql.Tx) (struct{}, error) {
		return struct{}{}, insertRoutingPermit(t.Context(), tx, carried)
	})
	requireOK(t, err)
	known := drain
	known.Scope, known.PriorBoot = routing.KnownPriorBoot, fixtureProcessBoot
	_, err = f.store.AttestRoutingDrained(t.Context(), known)
	requireCode(t, err, domain.Forbidden)
	result, err := f.store.AttestRoutingDrained(t.Context(), drain)
	if got := must(t, result, err); got.Disposition != routing.Drained || got.Target.Blocked || !got.Target.Covered {
		t.Fatal("zero-row explicit all-prior drain did not establish coverage")
	}
	if routingOutstanding(t, f) != 1 {
		t.Fatal("all-prior drain released current-boot active ownership")
	}
	reconnectRoutingFixture(t, f, boot, []protocol.ControlCall{carried.Call})
	before := migrationSnapshot(t, f.store.db)
	result, err = f.store.AttestRoutingDrained(t.Context(), drain)
	if got := must(t, result, err); got.Disposition != routing.AlreadySatisfied || !reflect.DeepEqual(before, migrationSnapshot(t, f.store.db)) {
		t.Fatal("lost-response retry changed state or retargeted its confirmation")
	}
	wrong := drain
	wrong.Recovery = "another-restore"
	_, err = f.store.AttestRoutingDrained(t.Context(), wrong)
	requireCode(t, err, domain.Conflict)
	wrong = drain
	wrong.CurrentBoot = fixtureProcessBoot
	_, err = f.store.AttestRoutingDrained(t.Context(), wrong)
	requireCode(t, err, domain.Conflict)
	wrong = drain
	wrong.Credential.Generation++
	_, err = f.store.AttestRoutingDrained(t.Context(), wrong)
	requireCode(t, err, domain.Conflict)
	reconnectRoutingFixture(t, f, strings.Repeat("c", 32), nil)
	_, err = f.store.AttestRoutingDrained(t.Context(), drain)
	requireCode(t, err, domain.Conflict)
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "distinct-restore", Epoch: "distinct-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "distinct-restore", []domain.DeviceID{"device"}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	reconnectRoutingFixture(t, f, strings.Repeat("c", 32), nil)
	_, err = f.store.AttestRoutingDrained(t.Context(), drain)
	requireCode(t, err, domain.Conflict)
}

func TestRoutingCompletionAndFencedCompactionSerialize(t *testing.T) {
	f := newFixture(t)
	request := routingRequest(t, f, protocol.ContextInspect, 1)
	requireOK(t, f.store.AcquireRouting(t.Context(), request))
	reconnectRoutingFixture(t, f, fixtureProcessBoot, []protocol.ControlCall{request.Call})
	var joins sync.WaitGroup
	failures := make(chan error, 2)
	joins.Go(func() {
		failures <- f.store.CompleteRouting(t.Context(), f.credential, f.connection, protocol.ControlCompletion{ProcessBoot: fixtureProcessBoot, Call: request.Call, Disposition: protocol.ControlSettled}, f.now)
	})
	joins.Go(func() {
		_, err := transaction(t.Context(), f.store, func(tx *sql.Tx) (struct{}, error) {
			return struct{}{}, compactRoutingPermits(t.Context(), tx, "device", f.connection.Counter)
		})
		failures <- err
	})
	joins.Wait()
	close(failures)
	for err := range failures {
		requireOK(t, err)
	}
	if routingOutstanding(t, f) != 0 {
		t.Fatal("completion/compaction race retained a settled control")
	}
}
