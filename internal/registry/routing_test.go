package registry

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func routingRequest(t *testing.T, f *fixture, operation protocol.Operation, number int) routing.Request {
	t.Helper()
	payload, err := encode(protocol.Command{Operation: operation, Project: "project", Body: []byte(`{}`)})
	data := must(t, payload, err)
	digest := domain.Hash(data)
	return routing.Request{Credential: f.credential, ProcessBoot: fixtureProcessBoot, Call: protocol.ControlCall{Generation: protocol.Generation{BootEpoch: string(f.connection.BootEpoch), Counter: f.connection.Counter}, RequestID: fmt.Sprintf("g:%d", number), Operation: operation, RequestSHA256: hex.EncodeToString(digest[:])}, Payload: data, Now: f.now}
}

func completeRouting(t *testing.T, f *fixture, request routing.Request, disposition protocol.ControlDisposition) {
	t.Helper()
	requireOK(t, f.store.CompleteRouting(t.Context(), f.credential, f.connection, protocol.ControlCompletion{ProcessBoot: request.ProcessBoot, Call: request.Call, Disposition: disposition}, f.now))
}

func routingOutstanding(t *testing.T, f *fixture) int {
	t.Helper()
	status, err := f.store.CheckRoutingReadiness(t.Context(), f.credential, f.connection, f.now)
	return must(t, status, err).Outstanding
}

func TestRoutingAdmissionAtomicityAndNoLegacyBypass(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "atomic-routing")
	transmission := f.transmission(c)
	_, err := f.store.MarkPossibleSend(t.Context(), f.actor, transmission)
	requireCode(t, err, domain.Forbidden)
	assertRoutingAdmissionRejectsChangedBrief(t, f, transmission)
	occupied := routingRequest(t, f, protocol.Status, 1)
	requireOK(t, f.store.AcquireRouting(t.Context(), occupied))
	route, err := f.admissionRoute(t.Context(), transmission)
	request := must(t, route, err)
	_, err = f.store.MarkPossibleSendRouted(t.Context(), f.actor, transmission, request)
	requireCode(t, err, domain.ResourceLimit)
	view, err := f.store.GetForDispatch(t.Context(), f.actor, c.Operation, f.now)
	if got := must(t, view, err); got.Operation.Delivery != domain.Prepared || got.Operation.Reserved {
		t.Fatal("routing capacity failure committed admission")
	}
	completeRouting(t, f, occupied, protocol.ControlSettled)
	_, err = f.store.db.ExecContext(t.Context(), `CREATE TRIGGER routing_failure BEFORE INSERT ON routing_permits BEGIN SELECT RAISE(ABORT,'routing durable failure'); END`)
	requireOK(t, err)
	if _, err = f.store.MarkPossibleSendRouted(t.Context(), f.actor, transmission, request); err == nil {
		t.Fatal("permit insert failure ignored")
	}
	view, err = f.store.GetForDispatch(t.Context(), f.actor, c.Operation, f.now)
	if must(t, view, err).Operation.Delivery != domain.Prepared {
		t.Fatal("permit failure did not roll back admission")
	}
	_, err = f.store.db.ExecContext(t.Context(), "DROP TRIGGER routing_failure")
	requireOK(t, err)
	decision, err := f.store.MarkPossibleSendRouted(t.Context(), f.actor, transmission, request)
	if must(t, decision, err).Kind != domain.SendOnce || routingOutstanding(t, f) != 1 {
		t.Fatal("admission and permit did not commit together")
	}
	f.restart(t)
	decision, err = f.store.MarkPossibleSend(t.Context(), f.actor, transmission)
	if got := must(t, decision, err); got.Kind != domain.ObserveExisting || got.Request.Brief != "" || routingOutstanding(t, f) != 1 {
		t.Fatal("restart replayed admission or freed permit")
	}
	var storedPayloads int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM routing_permits WHERE instr(CAST(call AS TEXT),'sensitive brief')>0").Scan(&storedPayloads))
	if storedPayloads != 0 {
		t.Fatal("routing identity persisted brief")
	}
}

func TestRoutingCompletionExactBindingAndUnpublishedTombstone(t *testing.T) {
	f := newFixture(t)
	request := routingRequest(t, f, protocol.Resolve, 1)
	requireOK(t, f.store.AcquireRouting(t.Context(), request))
	completeRouting(t, f, request, protocol.ControlPending)
	if routingOutstanding(t, f) != 1 {
		t.Fatal("pending released capacity")
	}
	wrong := request.Call
	wrong.RequestSHA256 = strings.Repeat("f", 64)
	err := f.store.CompleteRouting(t.Context(), f.credential, f.connection, protocol.ControlCompletion{ProcessBoot: fixtureProcessBoot, Call: wrong, Disposition: protocol.ControlSettled}, f.now)
	requireCode(t, err, domain.EvidenceInvalid)
	wrongBoot := strings.Repeat("2", 32)
	err = f.store.CompleteRouting(t.Context(), f.credential, f.connection, protocol.ControlCompletion{ProcessBoot: wrongBoot, Call: request.Call, Disposition: protocol.ControlSettled}, f.now)
	requireCode(t, err, domain.Conflict)
	if routingOutstanding(t, f) != 1 {
		t.Fatal("spoofed completion released capacity")
	}
	requireOK(t, f.store.ReleaseUnpublishedRouting(t.Context(), request))
	if routingOutstanding(t, f) != 0 {
		t.Fatal("definitely unpublished control retained")
	}
	requireCode(t, f.store.AcquireRouting(t.Context(), request), domain.Conflict)
	next := routingRequest(t, f, protocol.Resolve, 2)
	requireOK(t, f.store.AcquireRouting(t.Context(), next))
	completeRouting(t, f, next, protocol.ControlSettled)
	completeRouting(t, f, next, protocol.ControlSettled)
	if routingOutstanding(t, f) != 0 {
		t.Fatal("settled completion retained capacity")
	}
}

func TestRoutingSameBootInventoryIsFencedAndReplaySafe(t *testing.T) {
	f := newFixture(t)
	request := routingRequest(t, f, protocol.Status, 1)
	requireOK(t, f.store.AcquireRouting(t.Context(), request))
	f.restart(t)
	old := f.connection
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "gateway-next", f.now)
	f.connection = must(t, generation, err)
	status := f.reconcileRouting(t, []protocol.ControlCall{request.Call})
	if !status.Ready || status.Outstanding != 1 {
		t.Fatal("active old control lost")
	}
	f.reconcileRouting(t, []protocol.ControlCall{request.Call}) // Lost ACK replay changes nothing.
	report := protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: fixtureProcessBoot, BarrierID: strings.Repeat("a", 32), Generation: protocol.Generation{BootEpoch: string(f.connection.BootEpoch), Counter: f.connection.Counter}, Complete: true}
	_, err = f.store.ReconcileRouting(t.Context(), f.credential, report, f.now)
	requireCode(t, err, domain.Conflict)
	err = f.store.CompleteRouting(t.Context(), f.credential, old, protocol.ControlCompletion{ProcessBoot: fixtureProcessBoot, Call: request.Call, Disposition: protocol.ControlSettled}, f.now)
	requireCode(t, err, domain.Conflict)
	if routingOutstanding(t, f) != 1 {
		t.Fatal("old generation completion released live row")
	}
	generation, err = f.store.NextConnectionGeneration(t.Context(), f.credential, "gateway-third", f.now)
	f.connection = must(t, generation, err)
	status = f.reconcileRouting(t, nil)
	if !status.Ready || status.Outstanding != 0 {
		t.Fatal("complete sameboot absence did not reconcile")
	}
}

func TestRoutingChangedProcessRequiresCurrentAdminDrain(t *testing.T) {
	f := newFixture(t)
	correlation := f.prepare(t, "routing-drain")
	transmission := f.transmission(correlation)
	route, routeErr := f.admissionRoute(t.Context(), transmission)
	request := must(t, route, routeErr)
	_, sendErr := f.store.MarkPossibleSendRouted(t.Context(), f.actor, transmission, request)
	requireOK(t, sendErr)
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "new-gateway", f.now)
	f.connection = must(t, generation, err)
	currentBoot := strings.Repeat("2", 32)
	report := protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: currentBoot, BarrierID: strings.Repeat("a", 32), Generation: protocol.Generation{BootEpoch: string(f.connection.BootEpoch), Counter: f.connection.Counter}, Complete: true}
	status, err := f.store.ReconcileRouting(t.Context(), f.credential, report, f.now)
	if got := must(t, status, err); got.Ready || got.Reason != routing.ProcessChanged || got.Outstanding != 1 {
		t.Fatal("different process inferred control closure")
	}
	blocked := routingRequest(t, f, protocol.ContextInspect, 2)
	blocked.ProcessBoot = currentBoot
	requireCode(t, f.store.AcquireRouting(t.Context(), blocked), domain.Pending)
	drain := routing.Drain{Device: "device", Credential: f.credential, Scope: routing.KnownPriorBoot, PriorBoot: fixtureProcessBoot, CurrentBoot: currentBoot, Generation: f.connection, Now: f.now}
	stale := drain
	stale.CurrentBoot = strings.Repeat("3", 32)
	_, err = f.store.AttestRoutingDrained(t.Context(), stale)
	requireCode(t, err, domain.Conflict)
	f.store.admin = nil
	_, err = f.store.AttestRoutingDrained(t.Context(), drain)
	requireCode(t, err, domain.Forbidden)
	f.store.admin = fixtureAdmin{}
	_, err = f.store.AttestRoutingDrained(t.Context(), drain)
	requireOK(t, err)
	status, err = f.store.CheckRoutingReadiness(t.Context(), f.credential, f.connection, f.now)
	if got := must(t, status, err); !got.Ready || got.Outstanding != 0 {
		t.Fatal("valid admin routing drain not applied")
	}
	_, err = f.store.AttestRoutingDrained(t.Context(), drain)
	requireCode(t, err, domain.Conflict)
	operation, readErr := f.store.GetOperation(t.Context(), f.actor, correlation.Operation)
	if got := must(t, operation, readErr); !got.Reserved || got.Delivery != domain.PossibleSend {
		t.Fatal("routing-only drain fabricated Delegate task closure")
	}
}

func assertRoutingAdmissionRejectsChangedBrief(t *testing.T, f *fixture, input domain.Transmission) {
	t.Helper()
	route, err := f.admissionRoute(t.Context(), input)
	request := must(t, route, err)
	request.Payload = bytes.Replace(request.Payload, []byte("sensitive brief"), []byte("different brief"), 1)
	digest := domain.Hash(request.Payload)
	request.Call.RequestSHA256 = hex.EncodeToString(digest[:])
	_, err = f.store.MarkPossibleSendRouted(t.Context(), f.actor, input, request)
	requireCode(t, err, domain.EvidenceInvalid)
}

func TestRoutingConcurrentScanAcquisitionHasSingleDeviceWinner(t *testing.T) {
	f := newFixture(t)
	const callers = 12
	var group sync.WaitGroup
	results := make(chan error, callers)
	for number := 1; number <= callers; number++ {
		request := routingRequest(t, f, protocol.Resolve, number)
		group.Go(func() { results <- f.store.AcquireRouting(context.Background(), request) })
	}
	group.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else {
			requireCode(t, err, domain.ResourceLimit)
		}
	}
	if winners != 1 || routingOutstanding(t, f) != 1 {
		t.Fatalf("device scan bound violated: %d winners", winners)
	}
}
