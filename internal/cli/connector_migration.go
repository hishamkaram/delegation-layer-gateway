package cli

import (
	"context"
	"errors"
	"io"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connectorconfig"
)

// The configuration owner performs the offline cutover under its own locks.
// CLI exposes only counts and requires explicit acceptance before removing a
// saved execution ceiling; credential and project identity remain unchanged.
func migrateConnector(ctx context.Context, args []string, stdout io.Writer) error {
	set := flags("connector migrate")
	path := set.String("config", "", "private connector JSON configuration")
	previewOnly := set.Bool("preview", false, "report migration counts without changing the configuration")
	accept := set.Bool("accept-execution-policy-removal", false, "accept removal of saved connector execution ceilings")
	if err := parse(set, args); err != nil {
		return err
	}
	if _, err := privateRead(*path, maxConfigBytes); err != nil {
		return err
	}
	preview, err := connectorconfig.PreviewMigration(*path)
	if err != nil {
		return problem(exitUsage, "connector_migration_invalid", err)
	}
	needsAcceptance := preview.ExecutionPolicies != 0 && !*accept
	if *previewOnly || needsAcceptance {
		if err = writeJSON(stdout, preview); err != nil {
			return err
		}
		if *previewOnly {
			return nil
		}
		return problem(exitUsage, "execution_policy_removal_requires_acceptance", nil)
	}
	preview, err = connectorconfig.Migrate(ctx, *path, *accept)
	if err != nil {
		if errors.Is(err, connectorconfig.ErrMigrationAcceptanceRequired) {
			return problem(exitUsage, "execution_policy_removal_requires_acceptance", err)
		}
		return problem(exitRuntime, "connector_migration_failed", err)
	}
	return writeJSON(stdout, preview)
}
