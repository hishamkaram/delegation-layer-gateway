package workspaces

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// ReadFilesystem routes a read without creating a project, pin or operation.
// Native alone acquires requested filesystem data under the selected scope.
func (s *Service) ReadFilesystem(ctx context.Context, actor domain.Actor, device domain.DeviceID, operation protocol.Operation, request protocol.FilesystemRequest) (protocol.FilesystemResponse, error) {
	observed, err := s.ObserveFilesystem(ctx, actor, device, operation, request)
	return observed.Value, err
}

// ObserveFilesystem retains the exact source for a later consumer output gate.
func (s *Service) ObserveFilesystem(ctx context.Context, actor domain.Actor, device domain.DeviceID, operation protocol.Operation, request protocol.FilesystemRequest) (observation gateway.MetadataObservation[protocol.FilesystemResponse], err error) {
	if request.ValidateFor(operation) != nil {
		return observation, domain.ErrInvalid
	}
	body, err := protocol.Encode(request, 64<<10)
	if err != nil {
		return observation, err
	}
	var result protocol.FilesystemResponse
	source, err := s.exchangeOwnedMetadata(ctx, actor, device, operation, body, func(reply protocol.Reply, _ domain.RootGuard) error {
		if protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes) != nil || result.ValidateFor(operation, request) != nil {
			return domain.Reject(domain.EvidenceInvalid)
		}
		return nil
	})
	if err != nil {
		return observation, err
	}
	return gateway.MetadataObservation[protocol.FilesystemResponse]{Value: result, Source: source}, nil
}
