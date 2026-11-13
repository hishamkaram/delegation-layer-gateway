package registry

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func readinessInput(t *testing.T, f *fixture) domain.ProjectReadinessRequest {
	t.Helper()
	return domain.ProjectReadinessRequest{Actor: f.actor, Destination: destination(), Context: binding(), Generation: f.rootGeneration(t), Credential: f.credential, Connection: f.connection, Now: f.now}
}

func TestProjectReadinessComparesAdvertisementToCurrentAuthority(t *testing.T) {
	f := newFixture(t)
	input := readinessInput(t, f)
	ready, err := f.store.CheckProjectReadiness(t.Context(), input)
	requireOK(t, err)
	if !ready {
		t.Fatal("eligible authenticated project reported not ready")
	}
	changes := []func(*domain.ProjectReadinessRequest){
		func(r *domain.ProjectReadinessRequest) { r.Context.Root = domain.RootGuard(fixtureGuard("moved-root")) },
		func(r *domain.ProjectReadinessRequest) {
			r.Context.Project = domain.ProjectGuard(fixtureGuard("moved-project"))
		},
		func(r *domain.ProjectReadinessRequest) { r.Generation = "unapproved-advertisement" },
		func(r *domain.ProjectReadinessRequest) { r.Connection.Counter++ },
		func(r *domain.ProjectReadinessRequest) { r.Credential.Generation++ },
	}
	for _, change := range changes {
		candidate := input
		change(&candidate)
		current, currentErr := f.store.CheckProjectReadiness(t.Context(), candidate)
		requireOK(t, currentErr)
		if current {
			t.Fatal("mismatched advertisement escaped current readiness gate")
		}
	}
	start := pendingRoot(t, f)
	candidate := input
	candidate.Destination = start.Route
	candidate.Context = start.ExpectedContext
	candidate.Generation = "unproven-generation"
	pending, err := f.store.CheckProjectReadiness(t.Context(), candidate)
	requireOK(t, err)
	if pending {
		t.Fatal("pending registration inherited peer readiness")
	}
	// An older/partial restored image may still contain a regular credential.
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE settings SET blocked=1 WHERE id=1")
	requireOK(t, err)
	blocked, err := f.store.CheckProjectReadiness(t.Context(), input)
	requireOK(t, err)
	if blocked {
		t.Fatal("global recovery block was absent from readiness decision")
	}
}

func TestProjectReadinessDoesNotDowngradeAuthorizationOrStorageFaults(t *testing.T) {
	f := newFixture(t)
	input := readinessInput(t, f)
	requireOK(t, f.store.RevokeGrant(t.Context(), domain.GrantKey{Principal: f.actor.Principal, Destination: destination()}))
	if _, err := f.store.CheckProjectReadiness(t.Context(), input); err == nil {
		t.Fatal("revoked grant became visible not-ready metadata")
	}
	f.putGrant(t, f.actor.Principal, f.actor.Scopes)
	requireOK(t, f.store.SetPrincipalRevoked(t.Context(), f.actor.Principal, true))
	if _, err := f.store.CheckProjectReadiness(t.Context(), input); err == nil {
		t.Fatal("revoked principal became visible not-ready metadata")
	}
	requireOK(t, f.store.SetPrincipalRevoked(t.Context(), f.actor.Principal, false))
	input.Connection = domain.ConnectionGeneration{}
	if _, err := f.store.CheckProjectReadiness(t.Context(), input); err == nil {
		t.Fatal("malformed connection was silently downgraded")
	}
	input = readinessInput(t, f)
	_, err := f.store.db.ExecContext(t.Context(), "DROP TABLE root_admissions")
	requireOK(t, err)
	if _, err = f.store.CheckProjectReadiness(t.Context(), input); err == nil {
		t.Fatal("registry storage failure was silently downgraded")
	}
}

func TestProjectReadinessRequiresCurrentRegularCredential(t *testing.T) {
	f := newFixture(t)
	input := readinessInput(t, f)
	input.Credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), input.Credential, "recovery-only", f.now)
	input.Connection = must(t, connection, err)
	ready, err := f.store.CheckProjectReadiness(t.Context(), input)
	requireOK(t, err)
	if ready {
		t.Fatal("recovery-only credential advertised execution readiness")
	}
}
