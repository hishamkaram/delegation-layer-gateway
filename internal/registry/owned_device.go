package registry

import (
	"context"
	"database/sql"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// requireDeviceOwner shares the required ownership/current eligibility gate for
// Native bootstrap and v2 connections. Legacy optional ownership stays separate.
func requireDeviceOwner(ctx context.Context, tx *sql.Tx, device domain.DeviceID) error {
	owner, err := deviceOwner(ctx, tx, device)
	if err != nil {
		return err
	}
	if owner == "" {
		return domain.Reject(domain.Forbidden)
	}
	_, err = ownerPolicy(ctx, tx, owner)
	return err
}

func (s *Store) CheckOwnedCredential(ctx context.Context, ref domain.CredentialRef, now time.Time) (domain.Credential, error) {
	return transaction(ctx, s, func(tx *sql.Tx) (domain.Credential, error) {
		current, err := credential(ctx, tx, ref, now)
		if err != nil {
			return domain.Credential{}, err
		}
		if err = requireDeviceOwner(ctx, tx, ref.Device); err != nil {
			return domain.Credential{}, err
		}
		return current, nil
	})
}

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
