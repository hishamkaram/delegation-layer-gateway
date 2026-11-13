package server

import (
	"context"

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

func (s auditedAdministrativeStore) SetDeviceRevoked(ctx context.Context, device domain.DeviceID, revoked bool) error {
	err := s.Store.SetDeviceRevoked(ctx, device, revoked)
	if err == nil && revoked {
		s.recorder.Record(observability.Event{Code: observability.CredentialRevoked, Device: device})
	}
	return err
}
