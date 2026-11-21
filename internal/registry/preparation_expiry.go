package registry

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// Registry owns preparation_expires_ns as a derived index of the immutable
// expires instant. Creation and explicit migration write it; quota and expiry
// clearing read it. Original metadata and frozen evidence are never normalized.
func expirationNanoseconds(instant time.Time) (int64, error) {
	nanoseconds := instant.UnixNano()
	if instant.IsZero() || !time.Unix(0, nanoseconds).Equal(instant) {
		return 0, domain.ErrInvalid
	}
	return nanoseconds, nil
}

type migrationExpiry struct {
	rowID int64
	nanos int64
}

func migratePreparationExpiries(ctx context.Context, tx *sql.Tx) error {
	var after int64
	for {
		batch, err := readMigrationExpiries(ctx, tx, after)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, expiry := range batch {
			if _, err = tx.ExecContext(ctx, "UPDATE operations SET preparation_expires_ns=? WHERE row_id=?", expiry.nanos, expiry.rowID); err != nil {
				return err
			}
			after = expiry.rowID
		}
	}
}

func readMigrationExpiries(ctx context.Context, tx *sql.Tx, after int64) (batch []migrationExpiry, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT row_id,expires FROM operations WHERE state='prepared' AND row_id>? ORDER BY row_id LIMIT 100", after)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var expiry migrationExpiry
		var text string
		if err = rows.Scan(&expiry.rowID, &text); err != nil {
			return nil, err
		}
		instant, parseErr := time.Parse(time.RFC3339Nano, text)
		if parseErr != nil {
			return nil, domain.Reject(domain.EvidenceInvalid)
		}
		expiry.nanos, err = expirationNanoseconds(instant)
		if err != nil {
			return nil, domain.Reject(domain.EvidenceInvalid)
		}
		batch = append(batch, expiry)
	}
	return batch, rows.Err()
}

func validatePreparationExpiry(view domain.OperationView, stored sql.NullInt64) error {
	if view.Delivery != domain.Prepared {
		return nil
	}
	nanos, err := expirationNanoseconds(view.ExpiresAt)
	if err != nil || !stored.Valid || stored.Int64 != nanos {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func checkPreparationCapacity(ctx context.Context, tx *sql.Tx, owner domain.PrincipalID, now time.Time, requestBytes int) error {
	nowNS, err := expirationNanoseconds(now)
	if err != nil {
		return err
	}
	var outstanding int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM operations WHERE owner=? AND state='prepared' AND cancellation='' AND preparation_expires_ns>?", owner, nowNS).Scan(&outstanding); err != nil {
		return err
	}
	if outstanding >= domain.MaxOutstandingPreparations {
		return domain.Reject(domain.ResourceLimit)
	}
	var retained int64
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(request)),0) FROM operations WHERE request IS NOT NULL").Scan(&retained); err != nil {
		return err
	}
	if retained+int64(requestBytes) > domain.MaxRetainedBytes {
		return domain.Reject(domain.ResourceLimit)
	}
	return nil
}
