package server

import (
	"context"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

// Registry alone mutates revocation. This adapter records a successful explicit
// device-revocation command, including an idempotent repeated revocation.
type auditedAdministrativeStore struct {
	*registry.Store
	recorder *observability.Recorder
}

func (s auditedAdministrativeStore) CreateOwnedEnrollment(ctx context.Context, principal domain.PrincipalID, name string, hash domain.Digest, now time.Time) (domain.Device, error) {
	device, err := s.Store.CreateOwnedEnrollment(ctx, principal, name, hash, now)
	if err == nil {
		s.recorder.Record(observability.Event{Code: observability.EnrollmentGrantCreated, Principal: principal, Device: device.ID})
	}
	return device, err
}

func (s auditedAdministrativeStore) PutOwnerPolicy(ctx context.Context, principal domain.PrincipalID, policy domain.OwnerPolicy) error {
	err := s.Store.PutOwnerPolicy(ctx, principal, policy)
	if err == nil {
		s.recorder.Record(observability.Event{Code: observability.OwnerPolicyChanged, Principal: principal})
	}
	return err
}

func (s auditedAdministrativeStore) DisableOwnerPolicy(ctx context.Context, principal domain.PrincipalID) error {
	err := s.Store.DisableOwnerPolicy(ctx, principal)
	if err == nil {
		s.recorder.Record(observability.Event{Code: observability.OwnerPolicyChanged, Principal: principal})
	}
	return err
}

func (s auditedAdministrativeStore) SetDeviceRevoked(ctx context.Context, device domain.DeviceID, revoked bool) error {
	err := s.Store.SetDeviceRevoked(ctx, device, revoked)
	if err == nil && revoked {
		s.recorder.Record(observability.Event{Code: observability.CredentialRevoked, Device: device})
	}
	return err
}
