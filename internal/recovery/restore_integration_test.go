package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
)

func TestRestoreBeginRetryRetainsIdentityAndRevokesPreviousCredential(t *testing.T) {
	f := newRecoveryTLS(t)
	restorer, err := recovery.NewRestorer(f.store, f.service, func() time.Time { return f.now })
	recoveryOK(t, err)
	first, err := restorer.Begin(f.ctx, "explicit-restore")
	recoveryOK(t, err)
	second, err := restorer.Begin(f.ctx, "explicit-restore")
	recoveryOK(t, err)
	if first != second || first.Kind != domain.RestoreRecovery || first.Epoch == "" {
		t.Fatal("retry changed the durable recovery identity or credential epoch")
	}
	_, err = f.store.CheckConnection(f.ctx, f.ref, f.peer.Generation(), f.now)
	if err == nil {
		t.Fatal("credential from before restore remained authorized")
	}
	page, err := restorer.Progress(f.ctx, domain.RecoveryProgressRequest{Recovery: first.ID, Limit: 1})
	recoveryOK(t, err)
	if page.Session != first || page.Status != domain.RecoveryActive || len(page.Destinations) != 1 || page.Destinations[0].Destination.Device != f.lookup.Route.Device || page.Destinations[0].Destination.Root != f.lookup.ExpectedContext.Root {
		t.Fatal("durable progress changed the prior root roster")
	}
	if err = restorer.Seal(f.ctx, domain.RecoveryRosterSeal{Recovery: first.ID, ExpectedDestinations: 0}); err == nil {
		t.Fatal("incorrect roster count was accepted")
	}
	recoveryOK(t, restorer.Seal(f.ctx, domain.RecoveryRosterSeal{Recovery: first.ID, ExpectedDestinations: 1}))
	if err = restorer.Finish(f.ctx, first.ID); err == nil {
		t.Fatal("restore finished without canonical inventory and reopen proof")
	}
	_, err = restorer.Begin(context.Background(), first.ID)
	var denied *domain.Error
	if !errors.As(err, &denied) || denied.Code != domain.Forbidden {
		t.Fatal("recovery retry bypassed private administrative authority")
	}
}
