// Package testsupport supplies explicit fake Delegate proof fixtures through
// real Registry APIs. It never bypasses root eligibility or proves native CLI IO.
package testsupport

import (
	"context"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func OpenRoot(t testing.TB, ctx context.Context, store *registry.Store, start domain.RootInitializationStart) domain.RootInitializationProgress {
	t.Helper()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	progress, err := store.BeginRootInitialization(ctx, start)
	check(err)
	if progress.Stage == domain.RootReady {
		return progress
	}
	destination := domain.RecoveryDestination{Recovery: progress.RecoveryID, Device: start.Route.Device, Root: start.ExpectedContext.Root}
	check(store.RecordBarrier(ctx, domain.ValidatedBarrierReceipt{Destination: destination, Generation: progress.Generation, Receipt: domain.Hash([]byte("fixture barrier " + string(progress.RecoveryID)))}))
	membership := domain.Hash([]byte("fixture empty namespace " + string(progress.RecoveryID)))
	complete := domain.Hash([]byte("fixture complete " + string(progress.RecoveryID)))
	check(store.ApplyInventoryPage(ctx, domain.ValidatedInventoryPage{Destination: destination, Generation: progress.Generation, Membership: membership, CompletenessReceipt: &complete, Now: start.Now}))
	plan, err := store.ApproveRecoveryReopen(ctx, domain.RecoveryApproval{Recovery: progress.RecoveryID, Now: start.Now})
	check(err)
	if len(plan.Targets) != 1 {
		t.Fatal("root fixture requires exactly one target")
	}
	check(store.CheckReopen(ctx, domain.ReopenCheck{Target: plan.Targets[0], Credential: start.Credential, Connection: start.Connection, Now: start.Now}))
	check(store.RecordReopen(ctx, domain.ValidatedReopenReceipt{Target: plan.Targets[0], Receipt: domain.Hash([]byte("fixture reopen " + string(progress.RecoveryID))), Now: start.Now}))
	check(store.FinishRecovery(ctx, domain.RecoveryFinish{Recovery: progress.RecoveryID, Now: start.Now}))
	ready, err := store.ReadRootInitializationProgress(ctx, domain.RootInitializationLookup{Route: start.Route, ExpectedContext: start.ExpectedContext})
	check(err)
	if ready.Stage != domain.RootReady {
		t.Fatal("root fixture did not establish eligibility")
	}
	return ready
}
