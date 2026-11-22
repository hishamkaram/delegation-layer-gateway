package registry

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func preparationInput(t *testing.T, f *fixture, actor domain.Actor, label string, now time.Time) domain.Preparation {
	t.Helper()
	generation, err := transaction(t.Context(), f.store, func(tx *sql.Tx) (domain.AdmissionGeneration, error) {
		return readOpenRootGeneration(t.Context(), tx, destination().Device, binding().Root)
	})
	current := must(t, generation, err)
	task := domain.Hash([]byte(label))
	request := domain.FrozenRequest{Provider: "provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: domain.ReadOnly, BudgetSeconds: 60, Brief: "preparation pressure"}
	correlation := domain.Correlation{Operation: domain.OperationID(label), Task: domain.TaskID(hex.EncodeToString(task[:16])), Gateway: f.gateway, AdmissionGeneration: current, Owner: domain.OperationOwner{Kind: domain.Owned, Principal: actor.Principal}, Destination: destination(), Context: binding(), BriefDigest: domain.Hash([]byte(request.Brief))}
	digest, err := domain.RequestDigest(correlation, request)
	correlation.RequestDigest = must(t, digest, err)
	return domain.Preparation{Correlation: correlation, Request: request, Now: now}
}

func TestPreparationCapacityIsPerPrincipalAndReplayPrecedesPressure(t *testing.T) {
	f := newFixture(t)
	first := preparationInput(t, f, f.actor, "pressure-0", f.now)
	for i := range 32 {
		_, err := f.store.Prepare(t.Context(), f.actor, preparationInput(t, f, f.actor, fmt.Sprintf("pressure-%d", i), f.now))
		requireOK(t, err)
	}
	f.restart(t)
	replayed, err := f.store.Prepare(t.Context(), f.actor, first)
	if got := must(t, replayed, err); got.Correlation != first.Correlation || got.ExpiresAt != f.now.Add(domain.DraftTTL) {
		t.Fatal("replay changed the frozen preparation")
	}
	overflow := preparationInput(t, f, f.actor, "pressure-overflow", f.now)
	_, err = f.store.Prepare(t.Context(), f.actor, overflow)
	requireCode(t, err, domain.ResourceLimit)
	var rows int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations WHERE id=?", overflow.Correlation.Operation).Scan(&rows))
	if rows != 0 {
		t.Fatal("capacity rejection retained an operation row")
	}
	other, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "separate-pressure"})
	otherActor := domain.Actor{Principal: must(t, other, err).ID, Scopes: f.actor.Scopes}
	f.putGrant(t, otherActor.Principal, otherActor.Scopes)
	_, err = f.store.Prepare(t.Context(), otherActor, preparationInput(t, f, otherActor, "other-owner", f.now))
	requireOK(t, err)
	_, err = f.store.BindCancellation(t.Context(), f.actor, first.Correlation.Operation, domain.CancellationID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	requireOK(t, err)
	_, err = f.store.Prepare(t.Context(), f.actor, overflow)
	requireOK(t, err)
	_, err = f.store.Prepare(t.Context(), f.actor, preparationInput(t, f, f.actor, "expired-capacity", f.now.Add(domain.DraftTTL)))
	requireOK(t, err)
}

func TestConcurrentPreparationCannotExceedPrincipalCapacity(t *testing.T) {
	f := newFixture(t)
	for i := range 31 {
		f.prepare(t, fmt.Sprintf("concurrent-prefill-%d", i))
	}
	inputs := []domain.Preparation{preparationInput(t, f, f.actor, "concurrent-last-1", f.now), preparationInput(t, f, f.actor, "concurrent-last-2", f.now)}
	results := make(chan error, len(inputs))
	var group sync.WaitGroup
	for _, input := range inputs {
		group.Go(func() {
			_, err := f.store.Prepare(t.Context(), f.actor, input)
			results <- err
		})
	}
	group.Wait()
	close(results)
	var succeeded, limited int
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			requireCode(t, err, domain.ResourceLimit)
			limited++
		}
	}
	if succeeded != 1 || limited != 1 {
		t.Fatalf("capacity race admitted %d and rejected %d", succeeded, limited)
	}
}

func TestPreparationRetainedBodyPressureNeverDiscardsHistory(t *testing.T) {
	f := newFixture(t)
	prior := f.prepare(t, "body-pressure-existing")
	// Storage pressure counts retained bytes even when an existing row's body
	// cannot be decoded. Corrupt data is never permission to exceed the bound.
	_, err := f.store.db.ExecContext(t.Context(), "UPDATE operations SET request=zeroblob(?) WHERE id=?", domain.MaxRetainedBytes, prior.Operation)
	requireOK(t, err)
	input := preparationInput(t, f, f.actor, "body-pressure-new", f.now)
	_, err = f.store.Prepare(t.Context(), f.actor, input)
	requireCode(t, err, domain.ResourceLimit)
	var rows int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations").Scan(&rows))
	if rows != 1 {
		t.Fatal("body pressure discarded history or inserted a rejected preparation")
	}
	_, err = f.store.ExpireUnsent(t.Context(), f.now.Add(domain.DraftTTL))
	requireOK(t, err)
	_, err = f.store.Prepare(t.Context(), f.actor, input)
	requireOK(t, err)
}

func TestPreparationPressureUsesDurableActiveIndexes(t *testing.T) {
	f := newFixture(t)
	for _, check := range []struct{ query, index string }{
		{"SELECT count(*) FROM operations WHERE owner='owner' AND state='prepared' AND cancellation='' AND preparation_expires_ns>1", "operations_preparations"},
		{"SELECT id FROM operations WHERE owner='owner' AND device='device' AND preparation_key='key'", "operations_preparation_key"},
		{"SELECT COALESCE(sum(length(request)),0) FROM operations WHERE request IS NOT NULL", "operations_retained_bodies"},
	} {
		assertPreparationIndex(t, f.store, check.query, check.index)
	}
}

func assertPreparationIndex(t *testing.T, store *Store, query, index string) {
	t.Helper()
	rows, err := store.db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+query)
	requireOK(t, err)
	defer func() { requireOK(t, rows.Close()) }()
	var indexed bool
	for rows.Next() {
		var id, parent, unused int
		var detail string
		requireOK(t, rows.Scan(&id, &parent, &unused, &detail))
		indexed = indexed || strings.Contains(detail, index)
	}
	requireOK(t, rows.Err())
	if !indexed {
		t.Fatalf("pressure lookup did not use %s", index)
	}
}

func TestPreparationCapacityIgnoresExpiredVariableWidthTimestamp(t *testing.T) {
	f := newFixture(t)
	for number := range 32 {
		f.prepare(t, fmt.Sprintf("legacy-expiry-%d", number))
	}
	expires := f.now.Add(domain.DraftTTL)
	// The historical expires field accepts RFC3339Nano. Preserve its bytes:
	// a whole-second Z sorts after a later fractional instant lexically.
	_, err := f.store.db.ExecContext(t.Context(), "UPDATE operations SET expires=?", expires.Format(time.RFC3339Nano))
	requireOK(t, err)
	view, err := f.store.GetOperation(t.Context(), f.actor, "legacy-expiry-0")
	if got := must(t, view, err); !got.ExpiresAt.Equal(expires) {
		t.Fatal("historical expiry was not accepted as the same instant")
	}
	now := expires.Add(100 * time.Millisecond)
	_, err = f.store.Prepare(t.Context(), f.actor, preparationInput(t, f, f.actor, "after-legacy-expiry", now))
	requireOK(t, err)
	var retained int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations WHERE expires=?", expires.Format(time.RFC3339Nano)).Scan(&retained))
	if retained != 32 {
		t.Fatal("capacity accounting rewrote or removed historical expiry metadata")
	}
	summary, err := f.store.ExpireUnsent(t.Context(), now)
	if got := must(t, summary, err); got.Count != 32 {
		t.Fatalf("expiry clearing disagreed with preparation capacity: %d", got.Count)
	}
}
