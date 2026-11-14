package registry

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// MetadataSnapshot is a consistent administrative view of registry configuration.
// RegisteredDevices counts registered, non-revoked devices. AuthorizedDevices counts
// those devices covered by current owner policy or a legacy grant to a
// non-revoked principal. Registry owns both policy forms. These counts
// describe neither current OAuth claims, connectivity nor execution readiness,
// and are not an authorization oracle.
type MetadataSnapshot struct {
	RegisteredDevices uint64
	AuthorizedDevices uint64
}

// MetadataSnapshot reads both aggregate counts in one transaction. It requires
// administrative authority and returns an error when the snapshot is unavailable;
// callers must not publish an unavailable snapshot as healthy zero counts.
func (s *Store) MetadataSnapshot(ctx context.Context) (MetadataSnapshot, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return MetadataSnapshot{}, err
	}
	snapshot, err := transaction(ctx, s, func(tx *sql.Tx) (MetadataSnapshot, error) {
		var result MetadataSnapshot
		err := tx.QueryRowContext(ctx, effectiveAccessCTE+`
SELECT COUNT(*), COALESCE(SUM(CASE WHEN EXISTS (
    SELECT 1 FROM effective_access g JOIN principals p ON p.id=g.principal
    WHERE g.device=d.id AND p.revoked=0 AND EXISTS (
        SELECT 1 FROM json_each(g.scopes) scope
        WHERE scope.type='text' AND scope.value IN (?,?,?,?)
    )
) THEN 1 ELSE 0 END),0)
FROM devices d WHERE d.revoked=0`, domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel).
			Scan(&result.RegisteredDevices, &result.AuthorizedDevices)
		if err != nil {
			return MetadataSnapshot{}, fmt.Errorf("read registry metadata: %w", err)
		}
		return result, nil
	})
	if err != nil {
		return MetadataSnapshot{}, err
	}
	return snapshot, nil
}
