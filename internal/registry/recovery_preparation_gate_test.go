package registry

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestIncompleteRestoreIndependentlyFencesMissingPreparation(t *testing.T) {
	for _, test := range []struct {
		name    string
		blocked bool
		root    domain.RootState
	}{
		{"both fences", true, domain.RootPending},
		{"global block with stale open root", true, domain.RootOpen},
		{"pending root with stale open global", false, domain.RootPending},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, input := incompletePreparationRestore(t)
			// Fault injection removes at most one fence. A stale eligibility row
			// must not make an incomplete restore safe for new preparation.
			_, err := f.store.db.ExecContext(t.Context(), "UPDATE settings SET blocked=? WHERE id=1", test.blocked)
			requireOK(t, err)
			_, err = f.store.db.ExecContext(t.Context(), "UPDATE root_admissions SET state=? WHERE device=? AND root_guard=?", test.root, input.Correlation.Destination.Device, input.Correlation.Context.Root)
			requireOK(t, err)

			before := preparationGateOperationIDs(t, f)
			if !slices.Equal(before, []domain.OperationID{"existing-0", "existing-1"}) {
				t.Fatalf("restore fixture lost ordinary operation visibility: %v", before)
			}
			var rowsBefore, keysBefore int
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*),count(preparation_key) FROM operations").Scan(&rowsBefore, &keysBefore))
			_, found, err := f.store.LookupPreparation(t.Context(), f.actor, input.Correlation.Destination.Device, input.Correlation.Route.RequestID, input.Correlation.Route.InputDigest)
			requireOK(t, err)
			if found {
				t.Fatal("restore fixture already contains the new preparation key")
			}

			_, err = f.store.Prepare(t.Context(), f.actor, input)
			requireCode(t, err, domain.Pending)

			_, found, err = f.store.LookupPreparation(t.Context(), f.actor, input.Correlation.Destination.Device, input.Correlation.Route.RequestID, input.Correlation.Route.InputDigest)
			requireOK(t, err)
			if found {
				t.Fatal("incomplete restore published a preparation key")
			}
			if after := preparationGateOperationIDs(t, f); !slices.Equal(after, before) {
				t.Fatalf("rejected preparation changed the ordinary operation list: before=%v after=%v", before, after)
			}
			var rowsAfter, keysAfter int
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*),count(preparation_key) FROM operations").Scan(&rowsAfter, &keysAfter))
			if rowsAfter != rowsBefore || keysAfter != keysBefore {
				t.Fatalf("rejected preparation changed durable rows/keys: before=%d/%d after=%d/%d", rowsBefore, keysBefore, rowsAfter, keysAfter)
			}
		})
	}
}

func incompletePreparationRestore(t *testing.T) (*fixture, domain.Preparation) {
	t.Helper()
	f := newFixture(t)
	makeOwnedFixture(t, f)
	for i := range 2 {
		_, err := f.store.Prepare(t.Context(), f.actor, routedPreparation(t, f, fmt.Sprintf("existing-%d", i), fmt.Sprintf("%032x", i+1)))
		requireOK(t, err)
	}
	input := routedPreparation(t, f, "missing-during-restore", strings.Repeat("3", 32))
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "preparation-restore", Epoch: "preparation-restore-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "preparation-restore", ExpectedDestinations: 1}))
	// Restore current owner authority so authorization cannot mask either fence.
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, testOwnerPolicy()))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "preparation-restore", []domain.DeviceID{f.credential.Device}))
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "preparation-restore", f.now)
	f.connection = must(t, connection, err)
	if status := f.reconcileRouting(t, nil); !status.Ready {
		t.Fatalf("restore fixture did not cover its transport census: %+v", status)
	}
	destination := domain.RecoveryDestination{Recovery: "preparation-restore", Device: f.credential.Device, Root: input.Correlation.Context.Root}
	generation := f.barrierGeneration(t, destination)
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: destination, Generation: generation, Receipt: domain.Hash([]byte("preparation restore barrier"))}))
	cursor := strings.Repeat("f", 32)
	page := domain.ImportedInventoryPage{Destination: destination, Generation: generation, NextCursor: cursor, Entries: []domain.ImportedInventoryEntry{{Refusal: &domain.NamespaceRefusal{Task: domain.TaskID(cursor)}}}, Membership: domain.Hash([]byte("partial canonical membership")), Credential: f.credential, Connection: f.connection, Now: f.now}
	result, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	if must(t, result, err).CanonicalComplete {
		t.Fatal("nonfinal canonical page completed restoration")
	}
	requireCode(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: destination.Recovery, Now: f.now}), domain.Pending)
	return f, input
}

func preparationGateOperationIDs(t *testing.T, f *fixture) []domain.OperationID {
	t.Helper()
	var result []domain.OperationID
	request := domain.OperationPageRequest{Limit: 1}
	for {
		page, err := f.store.ListOperations(t.Context(), f.actor, request)
		operations := must(t, page, err)
		for _, operation := range operations.Items {
			result = append(result, operation.Correlation.Operation)
		}
		if operations.Next == "" {
			return result
		}
		if operations.Next <= request.After {
			t.Fatal("ordinary operation cursor did not advance")
		}
		request.After = operations.Next
	}
}
