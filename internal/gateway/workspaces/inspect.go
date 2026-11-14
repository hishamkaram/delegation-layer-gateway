package workspaces

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// InspectProject reads a saved immutable pin and obtains fresh capabilities for
// precisely that handle. It never resolves a missing project implicitly.
func (s *Service) InspectProject(ctx context.Context, actor domain.Actor, destination domain.Destination, scope domain.Scope) (gateway.TargetedProjectObservation, error) {
	if scope != domain.InventoryRead && scope != domain.TaskDispatch {
		return gateway.TargetedProjectObservation{}, domain.ErrInvalid
	}
	pin, err := s.options.Store.GetResolvedProject(ctx, actor, destination, scope)
	if err != nil {
		return gateway.TargetedProjectObservation{}, err
	}
	snapshot, err := s.snapshot(destination.Device)
	if err != nil {
		return gateway.TargetedProjectObservation{}, err
	}
	if snapshot.CapabilitiesV2.Root == nil || snapshot.CapabilitiesV2.Root.Root != string(pin.Context.Root) {
		return gateway.TargetedProjectObservation{}, domain.Reject(domain.Conflict)
	}
	current := binding(snapshot, pin.Context.Root)
	id := domain.ResolutionID(pin.Handle)
	body, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(s.options.GatewayID)}, 64<<10)
	if err != nil {
		return gateway.TargetedProjectObservation{}, err
	}
	var capability protocol.ProjectCapabilityV2
	_, tx, err := s.options.Controls.Exchange(ctx, gateway.MetadataCall{
		Actor: actor, Device: destination.Device, Operation: domain.OperationID(id), Scope: scope,
		Command: protocol.Command{Operation: protocol.ContextInspect, Project: string(pin.Handle), Body: body},
		Authorize: func(call context.Context) error {
			return s.options.Store.CheckResolvedProject(call, actor, domain.ProjectResolutionPin{Request: id, Binding: current, Pin: pin, Now: s.options.Now()}, scope)
		},
		Acquire: func(call context.Context, input routing.Request) error {
			return s.options.Store.AcquireProjectMetadata(call, actor, id, scope, input)
		},
		Check: func(call context.Context, tx domain.Transmission) error {
			live, checkErr := s.liveBinding(pin.Context.Root, tx)
			if checkErr != nil {
				return checkErr
			}
			return s.options.Store.CheckResolvedProject(call, actor, domain.ProjectResolutionPin{Request: id, Binding: live, Pin: pin, Now: s.options.Now()}, scope)
		},
		Validate: func(reply protocol.Reply, _ domain.Transmission) error {
			if protocol.DecodeStrict(reply.Body, &capability, protocol.MaxFrameBytes) != nil || capability.Validate() != nil || fromWire(capability.Project) != pin {
				return domain.Reject(domain.EvidenceInvalid)
			}
			return nil
		},
	})
	if err != nil {
		return gateway.TargetedProjectObservation{}, err
	}
	if err = ctx.Err(); err != nil {
		return gateway.TargetedProjectObservation{}, err
	}
	return gateway.TargetedProjectObservation{Capability: capability, Credential: tx.Credential, Connection: tx.Connection, ObservedAt: tx.Now}, nil
}
