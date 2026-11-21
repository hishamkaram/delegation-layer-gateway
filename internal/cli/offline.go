package cli

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

type migrationOptions struct {
	preview                      bool
	acceptExecutionPolicyRemoval bool
}

func migrateDatabase(ctx context.Context, path string, options migrationOptions, stdout io.Writer) error {
	preview, err := registry.PreviewMigration(ctx, path)
	if err != nil {
		return problem(exitRuntime, "database_migration_failed", err)
	}
	requiresAcceptance := preview.ObsoleteExecutionPolicyCount != 0 && !options.acceptExecutionPolicyRemoval
	if options.preview || requiresAcceptance {
		if err = writeJSON(stdout, preview); err != nil {
			return err
		}
		if options.preview {
			return nil
		}
		return problem(exitUsage, "execution_policy_removal_requires_acceptance", nil)
	}
	result, err := registry.Migrate(ctx, path)
	if err != nil {
		return problem(exitRuntime, "database_migration_failed", err)
	}
	return writeJSON(stdout, struct {
		Gateway     string `json:"gateway_id"`
		FromVersion int    `json:"from_version"`
		ToVersion   int    `json:"to_version"`
	}{string(result.Gateway), result.FromVersion, result.ToVersion})
}

// The caller owns the private database and holds its exclusive process lease.
// This local authority exists only for the one-shot offline maintenance call.
type offlineAuthority struct{}

func (offlineAuthority) AuthorizeAdmin(ctx context.Context) error { return ctx.Err() }

func beginOfflineRecovery(ctx context.Context, path string, id domain.RecoveryID, stdout io.Writer) (result error) {
	gateway, err := registry.ReadIdentity(ctx, path)
	if err != nil {
		return problem(exitRuntime, "database_identity_unavailable", err)
	}
	store, err := registry.Open(ctx, path, registry.Options{Gateway: gateway, Admin: offlineAuthority{}})
	if err != nil {
		return problem(exitRuntime, "database_unavailable", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = problem(exitCleanup, "database_cleanup_unconfirmed", errors.Join(result, closeErr))
		}
	}()
	now := time.Now().UTC()
	session, err := recovery.BeginRestore(ctx, store, id, now)
	if err != nil {
		return problem(exitRuntime, "recovery_begin_failed", err)
	}
	// Reassert the stored epoch through its authority before reporting a retry as
	// fenced. The offline lease excludes listeners and concurrent recovery owners.
	session, err = store.BeginRecovery(ctx, domain.RecoveryStart{ID: id, Epoch: session.Epoch, Now: now})
	if err != nil {
		return problem(exitRuntime, "recovery_begin_failed", err)
	}
	return writeJSON(stdout, adminapi.RecoverySession{RecoveryID: string(session.ID), Kind: session.Kind, StartedAt: session.StartedAt, RosterSealed: session.RosterSealed})
}
