package registry

import (
	"context"
	"database/sql"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// CheckConnection revalidates a response's original credential and generation
// immediately before an adapter releases data. It grants no operation access.
func (s *Store) CheckConnection(ctx context.Context, ref domain.CredentialRef, generation domain.ConnectionGeneration, now time.Time) (domain.Credential, error) {
	if ref.Validate() != nil || generation.Validate() != nil || now.IsZero() {
		return domain.Credential{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.Credential, error) { return checkConnection(ctx, tx, ref, generation, now) })
}
