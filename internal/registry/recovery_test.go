package registry

import (
	"database/sql"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestRestoreRequiresBarrierInventoryAndExplicitRegularReopen(t *testing.T) {
	f := newFixture(t)
	fixtureEpochBeforeRecovery := f.credential.Epoch
	possible := f.prepare(t, "before-snapshot-send")
	draft := f.prepare(t, "snapshot-draft")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(possible))
	requireOK(t, err)
	oldCredential := f.credential
	priorGeneration := f.rootGeneration(t)
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "restore", Epoch: "epoch2", Now: f.now})
	requireOK(t, err)
	_, err = f.store.CheckCredential(t.Context(), oldCredential, f.now)
	requireCode(t, err, domain.Forbidden)
	_, err = f.store.GetForDispatch(t.Context(), f.actor, draft.Operation, f.now)
	requireCode(t, err, domain.NotFound)
	requireCode(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "restore", ExpectedDestinations: 2}), domain.Conflict)
	requireCode(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: "restore", Now: f.now}), domain.Conflict)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "restore", ExpectedDestinations: 1}))
	requireCode(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: "restore", Now: f.now}), domain.Pending)
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "boot2", f.now)
	f.connection = must(t, connection, err)
	d := domain.RecoveryDestination{Recovery: "restore", Device: "device", Root: domain.RootGuard(fixtureGuard("root"))}
	targetGeneration := f.barrierGeneration(t, d)
	barrier := domain.ValidatedBarrierReceipt{Destination: d, Generation: priorGeneration, Receipt: domain.Hash([]byte("barrier"))}
	requireCode(t, f.store.RecordBarrier(t.Context(), barrier), domain.Conflict)
	barrier.Generation = targetGeneration
	requireOK(t, f.store.RecordBarrier(t.Context(), barrier))
	page := domain.ValidatedInventoryPage{Destination: d, Generation: f.barrierGeneration(t, d), Membership: domain.Hash([]byte("canonical membership")), Now: f.now, Entries: []domain.InventoryEntry{
		{Correlation: possible, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("spec1"))}},
		{Correlation: draft, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("spec2"))}},
	}}
	// This task appeared after the backup; its immutable principal mapping was lost.
	lost := possible
	lost.Operation = "lost-after-snapshot"
	lost.Task = "abcdef0123456789abcdef0123456789"
	lost.Owner.Principal = "unmapped-origin-principal"
	lost.RequestDigest = domain.Hash([]byte("canonical lost request"))
	page.Entries = append(page.Entries, domain.InventoryEntry{Correlation: lost, Observation: domain.DelegateObservation{Kind: domain.Unknown, ObservedAt: f.now}})
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	page.Now = f.now.Add(time.Second)
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	completeness := domain.ValidatedCompletenessReceipt{Destination: d, Generation: f.barrierGeneration(t, d), Membership: domain.Hash([]byte("wrong membership")), Receipt: domain.Hash([]byte("complete"))}
	requireCode(t, f.store.CompleteInventory(t.Context(), completeness), domain.Conflict)
	completeness.Membership = page.Membership
	requireOK(t, f.store.CompleteInventory(t.Context(), completeness))
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "restore", []domain.DeviceID{"device"}))
	routingConnection, routingErr := f.store.NextConnectionGeneration(t.Context(), f.credential, "routing-recovery", f.now)
	f.connection = must(t, routingConnection, routingErr)
	f.reconcileRouting(t, nil)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	_, err = f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: "restore", Now: f.now})
	requireCode(t, err, domain.Forbidden)
	f.credential = f.enroll(t, domain.Regular)
	rebindRegularFixture(t, f)
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: "restore", Now: f.now})
	approved := must(t, plan, err)
	if len(approved.Targets) != 1 {
		t.Fatal("wrong restore target count")
	}
	reopen := domain.ValidatedReopenReceipt{Target: approved.Targets[0], Receipt: domain.Hash([]byte("reopened")), Now: f.now}
	requireOK(t, f.store.RecordReopen(t.Context(), reopen))
	changed := completeness
	changed.Receipt = domain.Hash([]byte("changed receipt"))
	requireCode(t, f.store.CompleteInventory(t.Context(), changed), domain.Conflict)
	requireOK(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: "restore", Now: f.now}))
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "restore", Epoch: "epoch2", Now: f.now})
	requireCode(t, err, domain.Conflict)
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "stale-epoch", Epoch: fixtureEpochBeforeRecovery, Now: f.now})
	requireCode(t, err, domain.Conflict)
	f.putGrant(t, f.actor.Principal, f.actor.Scopes)
	connection, err = f.store.NextConnectionGeneration(t.Context(), f.credential, "boot3", f.now)
	f.connection = must(t, connection, err)
	view, err := f.store.GetOperation(t.Context(), f.actor, draft.Operation)
	if got := must(t, view, err); !got.Reserved || got.Delivery != domain.PossibleSend {
		t.Fatal("inventory did not recover post-snapshot admission")
	}
	_, err = f.store.GetOperation(t.Context(), f.actor, lost.Operation)
	requireCode(t, err, domain.NotFound)
	var owner sql.NullString
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT owner FROM operations WHERE id=?", lost.Operation).Scan(&owner))
	if owner.Valid {
		t.Fatal("lost mapping was assigned to a login")
	}
	var reserved int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM operations WHERE reserved=1").Scan(&reserved))
	if reserved != 3 {
		t.Fatalf("reconstruction lost quota: %d", reserved)
	}
	_, err = f.markSettledControl(t.Context(), f.actor, f.transmission(draft))
	requireOK(t, err) // Observes the recovered existing identity, never resends.
}

func TestRecoveryInventoryRestartInvalidatesApprovalWithoutReleasingSlots(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "unknown")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireOK(t, err)
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "restore", Epoch: "epoch2", Now: f.now})
	requireOK(t, err)
	f.credential = f.enroll(t, domain.RecoveryOnly)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "restore", ExpectedDestinations: 1}))
	d := domain.RecoveryDestination{Recovery: "restore", Device: "device", Root: domain.RootGuard(fixtureGuard("root"))}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: d, Generation: f.barrierGeneration(t, d), Receipt: domain.Hash([]byte("barrier"))}))
	page := domain.ValidatedInventoryPage{Destination: d, Generation: f.barrierGeneration(t, d), Membership: domain.Hash([]byte("membership")), Now: f.now}
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	requireOK(t, f.store.CompleteInventory(t.Context(), domain.ValidatedCompletenessReceipt{Destination: d, Generation: f.barrierGeneration(t, d), Membership: page.Membership, Receipt: domain.Hash([]byte("complete"))}))
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "restore", []domain.DeviceID{"device"}))
	routingConnection, routingErr := f.store.NextConnectionGeneration(t.Context(), f.credential, "routing-recovery", f.now)
	f.connection = must(t, routingConnection, routingErr)
	f.reconcileRouting(t, nil)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	f.credential = f.enroll(t, domain.Regular)
	rebindRegularFixture(t, f)
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: "restore", Now: f.now})
	approved := must(t, plan, err)
	requireOK(t, f.store.RestartInventory(t.Context(), d))
	requireCode(t, f.store.RecordReopen(t.Context(), domain.ValidatedReopenReceipt{Target: approved.Targets[0], Receipt: domain.Hash([]byte("stale reopen")), Now: f.now}), domain.Conflict)
	requireCode(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: "restore", Now: f.now}), domain.Pending)
	var reservations int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM operations WHERE reserved=1").Scan(&reservations))
	if reservations != 1 {
		t.Fatal("incomplete inventory freed unknown capacity")
	}
}
