package registry

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestRequireOwnedRedemptionDeniesLegacyBeforeReservationAndCommittedReplay(t *testing.T) {
	f := newFixture(t)
	input := f.enrollment(t, domain.Regular)
	input.RequireOwned = true
	var before, after int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM issuance").Scan(&before))
	_, err := f.store.BeginEnrollment(t.Context(), input)
	requireCode(t, err, domain.Forbidden)
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM issuance").Scan(&after))
	if before != after {
		t.Fatal("owned-required legacy redemption reserved issuance")
	}
	_, err = f.store.CheckCredential(t.Context(), f.credential, f.now)
	requireOK(t, err)
	_, err = f.store.CheckOwnedCredential(t.Context(), f.credential, f.now)
	requireCode(t, err, domain.Forbidden)
	input.RequireOwned = false
	reserved, err := f.store.BeginEnrollment(t.Context(), input)
	intent := must(t, reserved, err)
	_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: signFixture(t, intent, f.key), Now: f.now})
	requireOK(t, err)
	input.RequireOwned = true
	_, err = f.store.BeginEnrollment(t.Context(), input)
	requireCode(t, err, domain.Forbidden)
}

func TestRequireOwnedRedemptionUsesCurrentOwnerPolicyAndStableReplay(t *testing.T) {
	f := newFixture(t)
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, testOwnerPolicy()))
	hash := domain.Hash([]byte("owned-required-bootstrap"))
	_, err := f.store.CreateOwnedEnrollment(t.Context(), f.actor.Principal, "owned", hash, f.now)
	requireOK(t, err)
	input := ownedTokenAttempt(t, f, hash, "owned-required-bootstrap")
	input.RequireOwned = true
	reserved, err := f.store.BeginEnrollment(t.Context(), input)
	intent := must(t, reserved, err)
	_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: signFixture(t, intent, f.key), Now: f.now})
	requireOK(t, err)
	replayed, err := f.store.BeginEnrollment(t.Context(), input)
	requireOK(t, err)
	if replayed.ID != intent.ID {
		t.Fatal("owned replay selected a new issuance")
	}
	_, err = f.store.CheckOwnedCredential(t.Context(), intent.Credential, f.now)
	requireOK(t, err)
	policy := testOwnerPolicy()
	policy.Enabled = false
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	_, err = f.store.BeginEnrollment(t.Context(), input)
	requireCode(t, err, domain.Forbidden)
	_, err = f.store.CheckOwnedCredential(t.Context(), intent.Credential, f.now)
	requireCode(t, err, domain.Forbidden)
}
