package registry

import (
	"context"
	"database/sql"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// AuthorizeOwnedDevice authorizes owner-only inventory/resolution before any
// project exists. A legacy device cannot acquire this authority through grants.
func (s *Store) AuthorizeOwnedDevice(ctx context.Context, input domain.OwnedDeviceRequest) (domain.OwnedDeviceAuthorization, error) {
	if err := input.Validate(); err != nil {
		return domain.OwnedDeviceAuthorization{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.OwnedDeviceAuthorization, error) {
		return authorizeOwnedDevice(ctx, tx, input)
	})
}

func authorizeOwnedDevice(ctx context.Context, tx *sql.Tx, input domain.OwnedDeviceRequest) (domain.OwnedDeviceAuthorization, error) {
	owner, err := deviceOwner(ctx, tx, input.Device)
	if err != nil {
		return domain.OwnedDeviceAuthorization{}, err
	}
	if owner == "" || owner != input.Actor.Principal {
		return domain.OwnedDeviceAuthorization{}, domain.Reject(domain.NotFound)
	}
	policy, err := ownerPolicy(ctx, tx, owner)
	if err != nil {
		return domain.OwnedDeviceAuthorization{}, err
	}
	if !policy.Scopes.Has(input.Scope) {
		return domain.OwnedDeviceAuthorization{}, domain.Reject(domain.NotFound)
	}
	device, err := readDevice(ctx, tx, input.Device)
	if err != nil {
		return domain.OwnedDeviceAuthorization{}, err
	}
	if device.Revoked {
		return domain.OwnedDeviceAuthorization{}, domain.Reject(domain.NotFound)
	}
	return domain.OwnedDeviceAuthorization{Principal: owner, Device: device, Policy: policy}, nil
}
