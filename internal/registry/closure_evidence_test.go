package registry

import (
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func canonicalClosureEvidence() *domain.ClosureEvidence {
	return &domain.ClosureEvidence{Kind: domain.ClosureRegisteredNative, Reference: domain.Hash([]byte("canonical joined owner fixture"))}
}

func lostClosureCorrelation(t *testing.T, source domain.Correlation, operation domain.OperationID, task string) domain.Correlation {
	t.Helper()
	source.Operation = operation
	source.Task = domain.TaskID(strings.Repeat(task, 32))
	request := domain.FrozenRequest{Provider: "provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: domain.ReadOnly, BudgetSeconds: 60, Brief: "sensitive brief"}
	digest, digestErr := domain.RequestDigest(source, request)
	source.RequestDigest = must(t, digest, digestErr)
	return source
}

func TestBareTerminalObservationCannotReleaseLiveReservation(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "unproven-terminal")
	_, sendErr := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireOK(t, sendErr)
	input := domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Terminal, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("canonical spec"))}}
	observeErr := f.store.RecordObservation(t.Context(), input)
	var reserved bool
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT reserved FROM operations WHERE id=?", c.Operation).Scan(&reserved))
	if observeErr == nil || !reserved {
		t.Fatal("bare terminal observation was accepted or freed live quota")
	}
}

func closureInventoryPage(t *testing.T, f *fixture) domain.ValidatedInventoryPage {
	t.Helper()
	_, beginErr := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "closure-recovery", Epoch: "epoch-closure", Now: f.now})
	requireOK(t, beginErr)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "closure-recovery", ExpectedDestinations: 1}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, connectionErr := f.store.NextConnectionGeneration(t.Context(), f.credential, "closure-recovery", f.now)
	f.connection = must(t, connection, connectionErr)
	destination := domain.RecoveryDestination{Recovery: "closure-recovery", Device: "device", Root: binding().Root}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: destination, Generation: f.barrierGeneration(t, destination), Receipt: domain.Hash([]byte("canonical barrier"))}))
	return domain.ValidatedInventoryPage{Destination: destination, Generation: f.barrierGeneration(t, destination), Membership: domain.Hash([]byte("canonical membership")), Now: f.now}
}

func TestBareTerminalInventoryRejectsWholePageWithoutPartialImport(t *testing.T) {
	f := newFixture(t)
	source := f.prepare(t, "inventory-source")
	first := lostClosureCorrelation(t, source, "lost-first", "a")
	second := lostClosureCorrelation(t, source, "lost-terminal", "b")
	page := closureInventoryPage(t, f)
	page.Entries = []domain.InventoryEntry{
		{Correlation: first, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("first spec"))}},
		{Correlation: second, Observation: domain.DelegateObservation{Kind: domain.Terminal, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("second spec"))}},
	}
	importErr := f.store.ApplyInventoryPage(t.Context(), page)
	var imported, committedPages int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM operations WHERE id IN (?,?)", first.Operation, second.Operation).Scan(&imported))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM inventory_pages WHERE recovery=?", page.Destination.Recovery).Scan(&committedPages))
	if importErr == nil || imported != 0 || committedPages != 0 {
		t.Fatal("bare terminal inventory committed an unreserved row or partial page")
	}
}

func TestConfirmedStopSettlesQuotaAndCannotBeErasedOrReplaced(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "confirmed-stop")
	_, sendErr := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireOK(t, sendErr)
	id := domain.CancellationID(strings.Repeat("a", 32))
	_, bindErr := f.store.BindCancellation(t.Context(), f.actor, c.Operation, id)
	requireOK(t, bindErr)
	input := domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Terminal, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("canonical spec")), ConfirmedStop: &domain.StopConfirmation{Cancellation: id}}}
	requireOK(t, f.store.RecordObservation(t.Context(), input))
	assertConfirmedStop(t, f, c.Operation, id)
	input.Observation.ConfirmedStop = nil
	if observeErr := f.store.RecordObservation(t.Context(), input); observeErr == nil {
		t.Fatal("terminal without current proof inherited a previous stop")
	}
	input.Observation.Closure = canonicalClosureEvidence()
	requireOK(t, f.store.RecordObservation(t.Context(), input))
	assertConfirmedStop(t, f, c.Operation, id)
	input.Observation.ConfirmedStop = &domain.StopConfirmation{Cancellation: domain.CancellationID(strings.Repeat("b", 32))}
	requireCode(t, f.store.RecordObservation(t.Context(), input), domain.Conflict)
	f.restart(t)
	assertConfirmedStop(t, f, c.Operation, id)
}

func assertConfirmedStop(t *testing.T, f *fixture, operation domain.OperationID, id domain.CancellationID) {
	t.Helper()
	view, readErr := f.store.GetOperation(t.Context(), f.actor, operation)
	got := must(t, view, readErr)
	if got.Reserved || got.Delivery != domain.Resolved || got.Observation == nil || got.Observation.ConfirmedStop == nil || got.Observation.ConfirmedStop.Cancellation != id {
		t.Fatal("confirmed stop did not retain immutable evidence and settle quota")
	}
}

func TestProvenTerminalInventoryCanImportWithoutReservations(t *testing.T) {
	f := newFixture(t)
	source := f.prepare(t, "proven-inventory-source")
	first := lostClosureCorrelation(t, source, "lost-closure", "a")
	second := lostClosureCorrelation(t, source, "lost-confirmed-stop", "b")
	page := closureInventoryPage(t, f)
	page.Entries = []domain.InventoryEntry{
		{Correlation: first, Observation: domain.DelegateObservation{Kind: domain.Terminal, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("first spec")), Closure: canonicalClosureEvidence()}},
		{Correlation: second, Observation: domain.DelegateObservation{Kind: domain.Terminal, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("second spec")), ConfirmedStop: &domain.StopConfirmation{Cancellation: domain.CancellationID(strings.Repeat("c", 32))}}},
	}
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	var imported, reserved int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM operations WHERE id IN (?,?)", first.Operation, second.Operation).Scan(&imported, &reserved))
	if imported != 2 || reserved != 0 {
		t.Fatal("canonical closure or confirmed stop failed to settle imported identity")
	}
}
