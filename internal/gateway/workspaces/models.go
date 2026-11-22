package workspaces

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// ListModels explicitly asks Native for advisory discovery. Native owns its
// inspection lifecycle; these facts never veto an execution request.
func (s *Service) ListModels(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.ModelQuery) (protocol.ModelPage, error) {
	observed, err := s.ObserveModels(ctx, actor, device, request)
	return observed.Value, err
}

// ObserveModels retains the exact source of advisory model metadata.
func (s *Service) ObserveModels(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.ModelQuery) (observation gateway.MetadataObservation[protocol.ModelPage], err error) {
	if request.Validate() != nil {
		return observation, domain.ErrInvalid
	}
	body, err := protocol.Encode(request, 64<<10)
	if err != nil {
		return observation, err
	}
	var result protocol.ModelPage
	source, err := s.exchangeOwnedMetadata(ctx, actor, device, protocol.ProviderModels, body, func(reply protocol.Reply, _ domain.RootGuard) error {
		if protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes) != nil || result.ValidateFor(request) != nil {
			return domain.Reject(domain.EvidenceInvalid)
		}
		return nil
	})
	if err != nil {
		return observation, err
	}
	return gateway.MetadataObservation[protocol.ModelPage]{Value: result, Source: source}, nil
}
