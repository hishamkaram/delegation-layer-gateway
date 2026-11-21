package registry

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func routedPreparation(t *testing.T, f *fixture, label, requestID string) domain.Preparation {
	t.Helper()
	input := preparationInput(t, f, f.actor, label, f.now)
	input.Correlation.Destination.Project = domain.ProjectAlias(input.Correlation.Operation)
	input.Correlation.Route = domain.OperationRoute{Version: 1, RequestID: domain.RequestID(requestID), InputDigest: domain.Hash([]byte("caller input")), ScopeID: "workspace", RelativePath: "repo", WorkspaceGuard: fixtureGuard("workspace")}
	input.Request = domain.FrozenRequest{Native: domain.NativeOptions{Version: 1, Provider: "native-future-provider", Model: domain.Selection{Kind: domain.Explicit, Value: "new-model"}, Effort: domain.Selection{Kind: domain.Explicit, Value: "new-effort"}, Permission: "future-native-permission", Budget: "500"}, Brief: "native execution intent"}
	input.Correlation.BriefDigest = domain.Hash([]byte(input.Request.Brief))
	digest, err := domain.RequestDigest(input.Correlation, input.Request)
	input.Correlation.RequestDigest = must(t, digest, err)
	return input
}

func removeOwnedFixtureProjects(t *testing.T, f *fixture) {
	t.Helper()
	makeOwnedFixture(t, f)
	_, err := f.store.db.ExecContext(t.Context(), "DELETE FROM projects WHERE device='device'")
	requireOK(t, err)
}

func TestRoutedPreparationNeedsNoProjectAndRetainsReplayAfterRequestDisposal(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	input := routedPreparation(t, f, "routed-preparation", strings.Repeat("1", 32))
	_, found, err := f.store.LookupPreparation(t.Context(), f.actor, "device", input.Correlation.Route.RequestID, input.Correlation.Route.InputDigest)
	requireOK(t, err)
	if found {
		t.Fatal("lookup manufactured a missing preparation")
	}
	prepared, err := f.store.Prepare(t.Context(), f.actor, input)
	original := must(t, prepared, err)
	view, err := f.store.GetForDispatch(t.Context(), f.actor, original.Correlation.Operation, f.now)
	if got := must(t, view, err); got.Request.Native != input.Request.Native {
		t.Fatal("Gateway changed Native execution intent")
	}
	page, err := f.store.ListOperations(t.Context(), f.actor, domain.OperationPageRequest{})
	if got := must(t, page, err); len(got.Items) != 1 || got.Items[0].Correlation != original.Correlation {
		t.Fatal("operation-owned route disappeared without a project registration")
	}
	_, err = f.store.ExpireUnsent(t.Context(), f.now.Add(domain.DraftTTL))
	requireOK(t, err)
	f.restart(t)
	prepared, found, err = f.store.LookupPreparation(t.Context(), f.actor, "device", input.Correlation.Route.RequestID, input.Correlation.Route.InputDigest)
	if got := must(t, prepared, err); !found || got != original {
		t.Fatal("request disposal changed the permanent preparation correlation")
	}
	_, _, err = f.store.LookupPreparation(t.Context(), f.actor, "device", input.Correlation.Route.RequestID, domain.Hash([]byte("changed input")))
	requireCode(t, err, domain.Conflict)
	requireOK(t, f.store.DisableOwnerPolicy(t.Context(), f.actor.Principal))
	_, _, err = f.store.LookupPreparation(t.Context(), f.actor, "device", input.Correlation.Route.RequestID, input.Correlation.Route.InputDigest)
	requireCode(t, err, domain.Forbidden)
}

func TestConcurrentRoutedPreparationReplaysFirstCallerKeyBeforeCapacity(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	for i := range 31 {
		_, err := f.store.Prepare(t.Context(), f.actor, routedPreparation(t, f, fmt.Sprintf("routed-prefill-%d", i), fmt.Sprintf("%032x", i+1)))
		requireOK(t, err)
	}
	inputs := []domain.Preparation{routedPreparation(t, f, "routed-first", strings.Repeat("a", 32)), routedPreparation(t, f, "routed-second", strings.Repeat("a", 32))}
	results := make(chan domain.PreparedOperation, len(inputs))
	failures := make(chan error, len(inputs))
	var group sync.WaitGroup
	for _, input := range inputs {
		group.Go(func() {
			prepared, err := f.store.Prepare(t.Context(), f.actor, input)
			results <- prepared
			failures <- err
		})
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		requireOK(t, err)
	}
	var original domain.PreparedOperation
	for got := range results {
		if original == (domain.PreparedOperation{}) {
			original = got
		} else if got != original {
			t.Fatal("concurrent caller-key replay allocated a second operation")
		}
	}
	var rows int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations").Scan(&rows))
	if rows != 32 {
		t.Fatalf("concurrent caller key retained %d rows", rows)
	}
}

func TestRoutedPreparationCannotReplaceOwnershipScopeOrRootGeneration(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *fixture, *domain.Preparation)
		code   domain.ErrorCode
	}{
		{"legacy grant", func(*testing.T, *fixture, *domain.Preparation) {}, domain.NotFound},
		{"disabled owner", func(t *testing.T, f *fixture, _ *domain.Preparation) {
			removeOwnedFixtureProjects(t, f)
			requireOK(t, f.store.DisableOwnerPolicy(t.Context(), f.actor.Principal))
		}, domain.Forbidden},
		{"current scope", func(t *testing.T, f *fixture, _ *domain.Preparation) {
			removeOwnedFixtureProjects(t, f)
			policy := testOwnerPolicy()
			policy.Scopes = domain.ScopeSet{domain.TaskRead}
			requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
		}, domain.NotFound},
		{"generation", func(t *testing.T, f *fixture, _ *domain.Preparation) {
			removeOwnedFixtureProjects(t, f)
			_, err := f.store.db.ExecContext(t.Context(), "UPDATE root_admissions SET generation='replacement-generation'")
			requireOK(t, err)
		}, domain.Conflict},
		{"device revocation", func(t *testing.T, f *fixture, _ *domain.Preparation) {
			removeOwnedFixtureProjects(t, f)
			requireOK(t, f.store.SetDeviceRevoked(t.Context(), "device", true))
		}, domain.NotFound},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			input := routedPreparation(t, f, "routed-authority", strings.Repeat("b", 32))
			test.change(t, f, &input)
			_, err := f.store.Prepare(t.Context(), f.actor, input)
			requireCode(t, err, test.code)
		})
	}
}
