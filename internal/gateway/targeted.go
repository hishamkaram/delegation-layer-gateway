package gateway

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// A targeted v2 observation is gathered before admission reservation. The
// transport writer's queued guard performs only current Registry checks;
// initiating another RPC from that writer would deadlock its own queue.
func (s *Service) currentProject(ctx context.Context, actor domain.Actor, destination domain.Destination, snapshot LinkSnapshot) (protocol.ProjectCapability, error) {
	if snapshot.WireVersion != protocol.WireVersion2 {
		return project(snapshot, destination.Project)
	}
	if s.targeted == nil {
		return protocol.ProjectCapability{}, &RemoteError{Failure: protocol.Failure{Code: "incompatible_delegate"}}
	}
	observation, err := s.targeted.InspectProject(ctx, actor, destination, domain.TaskDispatch)
	if err != nil {
		return protocol.ProjectCapability{}, err
	}
	if observation.Capability.Validate() != nil || observation.ObservedAt.IsZero() || observation.Credential != snapshot.Credential || observation.Connection != snapshot.Connection || observation.Capability.Project.Handle != string(destination.Project) {
		return protocol.ProjectCapability{}, domain.Reject(domain.Conflict)
	}
	capability := observation.Capability.Capability
	if !capability.Ready {
		return protocol.ProjectCapability{}, domain.Reject(domain.Pending)
	}
	return capability, nil
}

func matchReservation(snapshot LinkSnapshot, reservation Reservation) error {
	actual := reservation.Transmission()
	if actual.Credential != snapshot.Credential || actual.Connection != snapshot.Connection {
		return domain.Reject(domain.Conflict)
	}
	return nil
}
