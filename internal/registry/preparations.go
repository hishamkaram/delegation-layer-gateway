package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// LookupPreparation resolves a durable caller key before filesystem inspection.
// Revoked authority never reveals an old correlation; a reused key with changed
// input conflicts even after expiry, confirmation or request-body disposal.
func (s *Store) LookupPreparation(ctx context.Context, actor domain.Actor, device domain.DeviceID, request domain.RequestID, input domain.Digest) (domain.PreparedOperation, bool, error) {
	authority := domain.OwnedDeviceRequest{Actor: actor, Device: device, Scope: domain.TaskDispatch}
	if err := authority.Validate(); err != nil {
		return domain.PreparedOperation{}, false, err
	}
	if domain.TaskID(request).Validate() != nil || input.Validate() != nil {
		return domain.PreparedOperation{}, false, domain.ErrInvalid
	}
	type lookup struct {
		operation domain.PreparedOperation
		found     bool
	}
	result, err := transaction(ctx, s, func(tx *sql.Tx) (lookup, error) {
		if _, err := authorizeOwnedDevice(ctx, tx, authority); err != nil {
			return lookup{}, err
		}
		operation, found, err := lookupPreparation(ctx, tx, actor.Principal, device, request, input)
		return lookup{operation: operation, found: found}, err
	})
	return result.operation, result.found, err
}

func lookupPreparation(ctx context.Context, tx *sql.Tx, owner domain.PrincipalID, device domain.DeviceID, request domain.RequestID, input domain.Digest) (domain.PreparedOperation, bool, error) {
	var id domain.OperationID
	if err := tx.QueryRowContext(ctx, "SELECT id FROM operations WHERE owner=? AND device=? AND preparation_key=?", owner, device, request).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.PreparedOperation{}, false, nil
		}
		return domain.PreparedOperation{}, false, err
	}
	op, err := readOperation(ctx, tx, id)
	if err != nil {
		return domain.PreparedOperation{}, false, err
	}
	c := op.view.Correlation
	if c.Route.Version != 1 || c.Route.RequestID != request || c.Destination.Device != device || c.Owner.Principal != owner {
		return domain.PreparedOperation{}, false, domain.Reject(domain.EvidenceInvalid)
	}
	if c.Route.InputDigest != input {
		return domain.PreparedOperation{}, false, domain.Reject(domain.Conflict)
	}
	return domain.PreparedOperation{Correlation: c, ExpiresAt: op.view.ExpiresAt}, true, nil
}

func preparationKey(c domain.Correlation) *domain.RequestID {
	if c.Route.Version == 0 {
		return nil
	}
	return &c.Route.RequestID
}

func authorizeCorrelation(ctx context.Context, tx *sql.Tx, actor domain.Actor, c domain.Correlation, scope domain.Scope) (domain.Authorization, error) {
	if c.Route.Version == 0 {
		return authorize(ctx, tx, domain.AuthorizationRequest{Actor: actor, Destination: c.Destination, Scope: scope})
	}
	request := domain.OwnedDeviceRequest{Actor: actor, Device: c.Destination.Device, Scope: scope}
	if err := request.Validate(); err != nil {
		return domain.Authorization{}, err
	}
	current, err := authorizeOwnedDevice(ctx, tx, request)
	if err != nil {
		return domain.Authorization{}, err
	}
	return domain.Authorization{Principal: current.Principal, Destination: c.Destination, Grant: domain.Grant{Key: domain.GrantKey{Principal: current.Principal, Destination: c.Destination}, Scopes: current.Policy.Scopes}}, nil
}

func preparationIdentityMatches(route domain.OperationRoute, key sql.NullString) bool {
	if route.Version == 1 {
		return key.Valid && key.String == string(route.RequestID)
	}
	return !key.Valid
}
