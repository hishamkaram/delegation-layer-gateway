package registry

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestKnownOldGenerationResumeRequiresCurrentRootButRetainsOriginalBinding(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "old-generation-resume")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireOK(t, err)
	spec := domain.Hash([]byte("canonical existing spec"))
	observation := domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: spec}
	requireOK(t, f.store.RecordObservation(t.Context(), domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: observation}))
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "resume-restore", Epoch: "resume-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "resume-restore", ExpectedDestinations: 1}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "resume-recovery", f.now)
	f.connection = must(t, connection, err)
	destination := domain.RecoveryDestination{Recovery: "resume-restore", Device: "device", Root: binding().Root}
	targetGeneration := f.barrierGeneration(t, destination)
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: destination, Generation: targetGeneration, Receipt: domain.Hash([]byte("barrier"))}))
	member := domain.Hash([]byte("one old task"))
	complete := domain.Hash([]byte("complete"))
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), domain.ValidatedInventoryPage{Destination: destination, Generation: targetGeneration, Membership: member, CompletenessReceipt: &complete, Entries: []domain.InventoryEntry{{Correlation: c, Observation: observation}}, Now: f.now}))
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), "resume-restore", []domain.DeviceID{"device"}))
	f.reconcileRouting(t, nil)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	f.credential = f.enroll(t, domain.Regular)
	connection, err = f.store.NextConnectionGeneration(t.Context(), f.credential, "resume-regular", f.now)
	f.connection = must(t, connection, err)
	f.reconcileRouting(t, nil)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	f.putGrant(t, f.actor.Principal, f.actor.Scopes)
	_, err = f.store.GetForRecovery(t.Context(), f.actor, c.Operation)
	requireCode(t, err, domain.Pending)
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: "resume-restore", Now: f.now})
	target := must(t, plan, err).Targets[0]
	requireOK(t, f.store.RecordReopen(t.Context(), domain.ValidatedReopenReceipt{Target: target, Receipt: domain.Hash([]byte("reopened")), Now: f.now}))
	requireOK(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: "resume-restore", Now: f.now}))
	view, err := f.store.GetForRecovery(t.Context(), f.actor, c.Operation)
	resumable := must(t, view, err)
	if resumable.Correlation != c || resumable.SpecDigest != spec || f.rootGeneration(t) == c.AdmissionGeneration {
		t.Fatal("resume rewrote original task identity or failed to rotate the root")
	}
	requireCode(t, f.store.CheckQueuedAdmission(t.Context(), f.actor, f.transmission(c)), domain.Conflict)
	requireOK(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: c.Destination}, Scopes: f.actor.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 59}}))
	_, err = f.store.GetForRecovery(t.Context(), f.actor, c.Operation)
	requireCode(t, err, domain.Forbidden)
}
