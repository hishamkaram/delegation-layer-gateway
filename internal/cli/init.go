package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func databaseCommand(ctx context.Context, args []string, stdout io.Writer, name string) (result error) {
	set := flags(name)
	path := set.String("database", "", "absolute private SQLite database path")
	var recoveryID string
	if name == "begin-recovery" {
		set.StringVar(&recoveryID, "recovery-id", "", "stable identity for this explicit restore intent")
	}
	if err := parse(set, args); err != nil {
		return err
	}
	if name == "begin-recovery" && domain.RoutingToken(recoveryID) != nil {
		return problem(exitUsage, "recovery_id_invalid", nil)
	}
	if err := databaseParent(*path); err != nil {
		return err
	}
	lease, err := instance.Acquire(filepath.Join(filepath.Dir(*path), "gateway.lock"))
	if err != nil {
		return problem(exitRuntime, "database_unavailable", err)
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			result = problem(exitCleanup, "database_cleanup_unconfirmed", errors.Join(result, closeErr))
		}
	}()
	switch name {
	case "init":
		return createDatabase(ctx, *path, stdout)
	case "migrate":
		return migrateDatabase(ctx, *path, stdout)
	case "begin-recovery":
		return beginOfflineRecovery(ctx, *path, domain.RecoveryID(recoveryID), stdout)
	}
	id, err := registry.ReadIdentity(ctx, *path)
	if err != nil {
		return problem(exitRuntime, "database_identity_unavailable", err)
	}
	return writeJSON(stdout, struct {
		Gateway string `json:"gateway_id"`
	}{string(id)})
}

func databaseParent(path string) error {
	if !absolute(path) {
		return problem(exitUsage, "database_path_invalid", nil)
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !privateParent(info) {
		return problem(exitUsage, "database_parent_invalid", err)
	}
	return nil
}

func createDatabase(ctx context.Context, path string, stdout io.Writer) (result error) {
	store, err := registry.Create(ctx, path, registry.CreateOptions{})
	if err != nil {
		return problem(exitRuntime, "database_creation_failed", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = problem(exitCleanup, "database_cleanup_unconfirmed", errors.Join(result, closeErr))
		}
	}()
	id, err := store.Identity(ctx)
	if err != nil {
		return problem(exitRuntime, "database_identity_unavailable", err)
	}
	return writeJSON(stdout, struct {
		Gateway string `json:"gateway_id"`
	}{string(id)})
}
