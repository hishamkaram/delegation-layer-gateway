package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type MigrationResult struct {
	Gateway     domain.GatewayID `json:"gateway_id"`
	FromVersion int              `json:"from_version"`
	ToVersion   int              `json:"to_version"`
}

// Migrate upgrades an existing private schema-6, 7, 8 or 9 database without replacing its
// authority or discarding evidence. The caller holds the process instance lease.
// A valid schema-10 database is an idempotent success. Open never migrates.
func Migrate(ctx context.Context, path string) (result MigrationResult, err error) {
	if err = validateRegistryFile(path); err != nil {
		return result, err
	}
	store, err := connect(ctx, path, nil, false)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	return transaction(ctx, store, func(tx *sql.Tx) (MigrationResult, error) {
		return migrateRegistry(ctx, tx)
	})
}

func migrateRegistry(ctx context.Context, tx *sql.Tx) (MigrationResult, error) {
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return MigrationResult{}, err
	}
	if version < 6 || version > 10 {
		return MigrationResult{}, fmt.Errorf("registry migration supports schema 6, 7, 8, 9 or 10: %w", domain.Reject(domain.Conflict))
	}
	gateway, err := validateRegistryAuthority(ctx, tx, "")
	if err != nil {
		return MigrationResult{}, err
	}
	if version == 6 {
		if _, err = tx.ExecContext(ctx, migrateRoutingPermits); err != nil {
			return MigrationResult{}, fmt.Errorf("migrate routing permits: %w", err)
		}
	}
	if err = verifyRoutingConstraints(ctx, tx); err != nil {
		return MigrationResult{}, err
	}
	if err = migrateAccessSchema(ctx, tx, version); err != nil {
		return MigrationResult{}, err
	}
	return MigrationResult{Gateway: gateway, FromVersion: version, ToVersion: 10}, nil
}

func migrateAccessSchema(ctx context.Context, tx *sql.Tx, version int) error {
	if version < 8 {
		if _, err := tx.ExecContext(ctx, ownershipSchema); err != nil {
			return fmt.Errorf("migrate ownership: %w", err)
		}
	}
	if version < 9 {
		if _, err := tx.ExecContext(ctx, projectResolutionSchema); err != nil {
			return fmt.Errorf("migrate project correlations: %w", err)
		}
	}
	if err := verifyOwnershipSchema(ctx, tx); err != nil {
		return err
	}
	if err := verifyProjectResolutionSchema(ctx, tx); err != nil {
		return err
	}
	if version < 10 {
		if err := migrateExecutionPolicies(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE operations ADD COLUMN preparation_key TEXT; ALTER TABLE operations ADD COLUMN preparation_expires_ns INTEGER;"); err != nil {
			return fmt.Errorf("migrate preparation storage: %w", err)
		}
		if err := migratePreparationExpiries(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, preparationSchema); err != nil {
			return fmt.Errorf("create preparation indexes: %w", err)
		}
	}
	return verifyPreparationSchema(ctx, tx)
}

const migrateRoutingPermits = `
CREATE TABLE routing_permits_v7 ` + routingPermitDefinition + `;
INSERT INTO routing_permits_v7(device,connection_boot,connection_counter,request,process_boot,credential,call,protected,scan,state)
SELECT device,connection_boot,connection_counter,request,process_boot,credential,call,protected,scan,state FROM routing_permits;
DROP TABLE routing_permits;
ALTER TABLE routing_permits_v7 RENAME TO routing_permits;
` + routingActiveIndex + `;
PRAGMA user_version=7;
`
