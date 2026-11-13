package registry

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func recoveryWithCompleteRoot(t *testing.T, f *fixture, additional ...domain.RootGuard) domain.RecoveryDestination {
	t.Helper()
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "approval-gate", Epoch: "approval-epoch", Now: f.now})
	requireOK(t, err)
	for _, root := range additional {
		requireOK(t, f.store.RegisterRecoveryDestination(t.Context(), domain.RecoveryDestination{Recovery: "approval-gate", Device: "device", Root: root}))
	}
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "approval-gate", ExpectedDestinations: 1 + len(additional)}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "approval-connection", f.now)
	f.connection = must(t, connection, err)
	destination := domain.RecoveryDestination{Recovery: "approval-gate", Device: "device", Root: binding().Root}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: destination, Generation: f.barrierGeneration(t, destination), Receipt: domain.Hash([]byte("barrier"))}))
	membership := domain.Hash([]byte("empty inventory"))
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), domain.ValidatedInventoryPage{Destination: destination, Generation: f.barrierGeneration(t, destination), Membership: membership, Now: f.now}))
	requireOK(t, f.store.CompleteInventory(t.Context(), domain.ValidatedCompletenessReceipt{Destination: destination, Generation: f.barrierGeneration(t, destination), Membership: membership, Receipt: domain.Hash([]byte("complete inventory"))}))
	return destination
}

func TestRegularRecoveryCredentialWaitsForRoutingRoster(t *testing.T) {
	f := newFixture(t)
	recoveryWithCompleteRoot(t, f)
	grant := domain.EnrollmentGrant{TokenHash: domain.Hash([]byte("regular recovery request")), Device: "device", Mode: domain.Regular, Generation: f.credential.Generation + 1, CreatedAt: f.now, ExpiresAt: f.now.Add(domain.EnrollmentTTL)}
	requireCode(t, f.store.CreateEnrollment(t.Context(), grant), domain.Pending)
	var count int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM enrollment WHERE token=?", grant.TokenHash[:]).Scan(&count))
	if count != 0 {
		t.Fatal("incomplete routing roster persisted a regular enrollment grant")
	}
}

func TestReopenApprovalIndependentlyWaitsForRoutingRoster(t *testing.T) {
	f := newFixture(t)
	recoveryWithCompleteRoot(t, f)
	// Model an older restored image that already contains a regular credential.
	// Approval must enforce its own coverage invariant, independently of issuance.
	credential, err := f.store.CheckCredential(t.Context(), f.credential, f.now)
	value := must(t, credential, err)
	value.Mode = domain.Regular
	data, err := encode(value)
	requireOK(t, err)
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE credentials SET value=? WHERE device=?", data, f.credential.Device)
	requireOK(t, err)
	_, err = f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: "approval-gate", Now: f.now})
	requireCode(t, err, domain.Pending)
	var approved int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM recovery_destinations WHERE recovery='approval-gate' AND approved=1").Scan(&approved))
	if approved != 0 {
		t.Fatal("incomplete routing roster committed reopen authority")
	}
}

func TestInventoryRestartInvalidatesEveryApprovedRoot(t *testing.T) {
	f := newFixture(t)
	otherRoot := domain.RootGuard(fixtureGuard("other-root"))
	primary := recoveryWithCompleteRoot(t, f, otherRoot)
	other := domain.RecoveryDestination{Recovery: primary.Recovery, Device: primary.Device, Root: otherRoot}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: other, Generation: f.barrierGeneration(t, other), Receipt: domain.Hash([]byte("other barrier"))}))
	membership := domain.Hash([]byte("other inventory"))
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), domain.ValidatedInventoryPage{Destination: other, Generation: f.barrierGeneration(t, other), Membership: membership, Now: f.now}))
	requireOK(t, f.store.CompleteInventory(t.Context(), domain.ValidatedCompletenessReceipt{Destination: other, Generation: f.barrierGeneration(t, other), Membership: membership, Receipt: domain.Hash([]byte("other complete"))}))
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), primary.Recovery, []domain.DeviceID{"device"}))
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "approval-census", f.now)
	f.connection = must(t, connection, err)
	f.reconcileRouting(t, nil)
	f.credential = f.enroll(t, domain.Regular)
	result, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: primary.Recovery, Now: f.now})
	plan := must(t, result, err)
	if len(plan.Targets) != 2 {
		t.Fatal("fixture did not approve both roots")
	}
	requireOK(t, f.store.RestartInventory(t.Context(), primary))
	var approved int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM recovery_destinations WHERE recovery='approval-gate' AND approved=1").Scan(&approved))
	if approved != 0 {
		t.Fatal("restarting one root retained authority to reopen another root")
	}
}
