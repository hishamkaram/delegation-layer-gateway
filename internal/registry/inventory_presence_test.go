package registry

import (
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// Canonical inventory reports presence, including tasks whose execution has
// already closed. Presence must not overwrite independently verified closure.
func TestInventoryPresencePreservesKnownTerminalEvidenceAndDate(t *testing.T) {
	f := newFixture(t)
	correlation, observation := settleBeforeInventory(t, f, domain.Terminal)
	page := closureInventoryPage(t, f)
	page.Now = f.now.Add(time.Hour)
	page.Entries = []domain.InventoryEntry{{Correlation: correlation, Observation: domain.DelegateObservation{
		Kind: domain.Existing, ObservedAt: page.Now, SpecDigest: observation.SpecDigest,
	}}}
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	stored, readErr := transaction(t.Context(), f.store, func(tx *sql.Tx) (storedOperation, error) {
		return readOperation(t.Context(), tx, correlation.Operation)
	})
	requireOK(t, readErr)
	if stored.view.Reserved || stored.view.Delivery != domain.Resolved {
		t.Fatal("inventory presence reopened a canonically closed reservation")
	}
	if stored.view.Observation == nil || !reflect.DeepEqual(*stored.view.Observation, observation) {
		t.Fatal("inventory presence replaced closure, result, or their verification date")
	}
}

func settleBeforeInventory(t *testing.T, f *fixture, kind domain.ObservationKind) (domain.Correlation, domain.DelegateObservation) {
	t.Helper()
	correlation := f.prepare(t, "closed-before-inventory")
	_, sendErr := f.markSettledControl(t.Context(), f.actor, f.transmission(correlation))
	requireOK(t, sendErr)
	observation := domain.DelegateObservation{
		Kind: kind, ObservedAt: f.now,
		SpecDigest: domain.Hash([]byte("canonical spec")),
	}
	if kind == domain.Terminal {
		observation.Closure = canonicalClosureEvidence()
		observation.Result = &domain.ResultDescriptor{Digest: domain.Hash([]byte("accepted result")), Bytes: 15}
	}
	_, resolutionErr := f.store.ApplyResolution(t.Context(), domain.ValidatedResolution{
		ValidatedObservation: domain.ValidatedObservation{
			Correlation: correlation, Credential: f.credential,
			Connection: f.connection, Now: f.now, Observation: observation,
		}, DurableRequest: true,
	})
	requireOK(t, resolutionErr)
	return correlation, observation
}

func TestConflictingInventoryPresenceRollsBackWholePage(t *testing.T) {
	cases := []struct {
		name        string
		kind        domain.ObservationKind
		changedSpec bool
		result      *domain.ResultDescriptor
	}{
		{name: "terminal-spec-mismatch", kind: domain.Terminal, changedSpec: true},
		{name: "terminal-result-mismatch", kind: domain.Terminal, result: &domain.ResultDescriptor{Digest: domain.Hash([]byte("substituted result")), Bytes: 15}},
		{name: "refused-task-present", kind: domain.Refused},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			correlation, observation := settleBeforeInventory(t, f, test.kind)
			newCorrelation := lostClosureCorrelation(t, correlation, "rollback-before-conflict", "a")
			page := closureInventoryPage(t, f)
			presence := domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: observation.SpecDigest, Result: test.result}
			if test.changedSpec {
				presence.SpecDigest = domain.Hash([]byte("substituted spec"))
			}
			page.Entries = []domain.InventoryEntry{
				{Correlation: newCorrelation, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("new spec"))}},
				{Correlation: correlation, Observation: presence},
			}
			requireCode(t, f.store.ApplyInventoryPage(t.Context(), page), domain.Conflict)
			var inserted, pages int
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM operations WHERE id=?", newCorrelation.Operation).Scan(&inserted))
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM inventory_pages WHERE recovery=?", page.Destination.Recovery).Scan(&pages))
			if inserted != 0 || pages != 0 {
				t.Fatal("conflicting presence committed earlier page entries or page progress")
			}
		})
	}
}
