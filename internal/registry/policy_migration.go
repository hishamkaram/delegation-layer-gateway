package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// MigrationPreview contains counts and identity only. It never exposes policy
// contents, requests, credentials or local paths. Migrate is the explicit apply.
type MigrationPreview struct {
	MigrationResult
	GrantCount                   int `json:"grant_count"`
	OwnerPolicyCount             int `json:"owner_policy_count"`
	ObsoleteExecutionPolicyCount int `json:"obsolete_execution_policy_count"`
}

// PreviewMigration reads an existing database without applying schema or policy
// changes. The caller holds the process lease to exclude an older writer.
func PreviewMigration(ctx context.Context, path string) (result MigrationPreview, err error) {
	if err = validateRegistryFile(path); err != nil {
		return result, err
	}
	store, err := connect(ctx, path, nil, true)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	return transaction(ctx, store, func(tx *sql.Tx) (MigrationPreview, error) {
		var preview MigrationPreview
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&preview.FromVersion); err != nil {
			return preview, err
		}
		if preview.FromVersion < 6 || preview.FromVersion > 10 {
			return preview, domain.Reject(domain.Conflict)
		}
		gateway, err := validateRegistryAuthority(ctx, tx, "")
		if err != nil {
			return preview, err
		}
		preview.Gateway, preview.ToVersion = gateway, 10
		if err = tx.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(json_type(value,'$.Ceiling') IS NOT NULL),0) FROM grants").Scan(&preview.GrantCount, &preview.ObsoleteExecutionPolicyCount); err != nil {
			return preview, err
		}
		if preview.FromVersion >= 8 {
			var obsolete int
			if err = tx.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(json_type(value,'$.Ceiling') IS NOT NULL),0) FROM owner_policies").Scan(&preview.OwnerPolicyCount, &obsolete); err != nil {
				return preview, err
			}
			preview.ObsoleteExecutionPolicyCount += obsolete
		}
		return preview, nil
	})
}

func migrateExecutionPolicies(ctx context.Context, tx *sql.Tx) error {
	// SQLite owns this rewrite. Only access-policy records lose the obsolete
	// field; frozen operation/request/options bytes are never re-encoded.
	for _, query := range []string{
		"UPDATE grants SET value=CAST(json_remove(value,'$.Ceiling') AS BLOB) WHERE json_type(value,'$.Ceiling') IS NOT NULL",
		"UPDATE owner_policies SET value=CAST(json_remove(value,'$.Ceiling') AS BLOB) WHERE json_type(value,'$.Ceiling') IS NOT NULL",
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("remove obsolete execution policy: %w", err)
		}
	}
	if err := validateMigratedGrants(ctx, tx); err != nil {
		return err
	}
	return validateMigratedOwnerPolicies(ctx, tx)
}

func validateMigratedGrants(ctx context.Context, tx *sql.Tx) (err error) {
	rows, err := tx.QueryContext(ctx, "SELECT principal,device,project,value FROM grants")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var key domain.GrantKey
		var data []byte
		if err = rows.Scan(&key.Principal, &key.Destination.Device, &key.Destination.Project, &data); err != nil {
			return err
		}
		grant, decodeErr := decode[domain.Grant](data)
		if decodeErr != nil {
			return decodeErr
		}
		if grant.Key != key || grant.Validate() != nil {
			return domain.Reject(domain.EvidenceInvalid)
		}
	}
	return rows.Err()
}

func validateMigratedOwnerPolicies(ctx context.Context, tx *sql.Tx) (err error) {
	rows, err := tx.QueryContext(ctx, "SELECT value FROM owner_policies")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var data []byte
		if err = rows.Scan(&data); err != nil {
			return err
		}
		policy, decodeErr := decode[domain.OwnerPolicy](data)
		if decodeErr != nil {
			return decodeErr
		}
		if policy.Validate() != nil {
			return domain.Reject(domain.EvidenceInvalid)
		}
	}
	return rows.Err()
}
