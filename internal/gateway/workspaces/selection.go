package workspaces

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// InspectSelection is passive and creates no project, pin or admission namespace.
func (s *Service) InspectSelection(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.SelectionRequest) (protocol.SelectionObservation, error) {
	observed, err := s.ObserveSelection(ctx, actor, device, request)
	return observed.Value, err
}

// ObserveSelection retains the exact source of newly requested selector facts.
func (s *Service) ObserveSelection(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.SelectionRequest) (observation gateway.MetadataObservation[protocol.SelectionObservation], err error) {
	if request.Validate() != nil {
		return observation, domain.ErrInvalid
	}
	body, err := protocol.Encode(request, 64<<10)
	if err != nil {
		return observation, err
	}
	var result protocol.SelectionObservation
	source, err := s.exchangeOwnedMetadata(ctx, actor, device, protocol.SelectProject, body, func(reply protocol.Reply, root domain.RootGuard) error {
		if protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes) != nil || result.ValidateFor(request) != nil || result.Context.Root != string(root) {
			return domain.Reject(domain.EvidenceInvalid)
		}
		return nil
	})
	if err != nil {
		return observation, err
	}
	return gateway.MetadataObservation[protocol.SelectionObservation]{Value: result, Source: source}, nil
}

// PrepareSelection performs the existing explicit first-task namespace setup,
// then observes the selector. Filesystem reads and InspectSelection stay passive.
func (s *Service) PrepareSelection(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.SelectionRequest) (protocol.SelectionObservation, error) {
	if request.Validate() != nil {
		return protocol.SelectionObservation{}, domain.ErrInvalid
	}
	if err := s.authorize(ctx, actor, device, domain.TaskDispatch); err != nil {
		return protocol.SelectionObservation{}, err
	}
	snapshot, err := s.snapshot(device)
	if err != nil {
		return protocol.SelectionObservation{}, err
	}
	if snapshot.CapabilitiesV2.Root == nil {
		return protocol.SelectionObservation{}, &gateway.RemoteError{Failure: protocol.Failure{Code: "device_not_ready", Retryable: true}}
	}
	current := binding(snapshot, domain.RootGuard(snapshot.CapabilitiesV2.Root.Root))
	if err = s.initialize(ctx, current); err != nil {
		return protocol.SelectionObservation{}, err
	}
	return s.InspectSelection(ctx, actor, device, request)
}
