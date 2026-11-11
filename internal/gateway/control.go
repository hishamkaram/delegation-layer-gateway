package gateway

import (
	"context"
	"encoding/hex"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (s *Service) Resolve(ctx context.Context, actor domain.Actor, id domain.OperationID) (domain.OperationView, error) {
	return s.observe(ctx, actor, id, protocol.Resolve)
}

func (s *Service) Status(ctx context.Context, actor domain.Actor, id domain.OperationID) (domain.OperationView, error) {
	return s.observe(ctx, actor, id, protocol.Status)
}

func (s *Service) Collect(ctx context.Context, actor domain.Actor, id domain.OperationID) (domain.OperationView, error) {
	return s.observe(ctx, actor, id, protocol.Collect)
}

func (s *Service) observe(ctx context.Context, actor domain.Actor, id domain.OperationID, operation protocol.Operation) (domain.OperationView, error) {
	view, err := s.store.GetOperation(ctx, actor, id)
	if err != nil {
		return view, err
	}
	if view.Delivery == domain.Prepared || view.Delivery == domain.ExpiredUnsent {
		return view, nil
	}
	spec := domain.Digest{}
	if view.Observation != nil {
		spec = view.Observation.SpecDigest
	}
	body, err := protocol.Encode(protocol.TaskControl{Task: binding(view.Correlation, spec)}, protocol.MaxFrameBytes)
	if err != nil {
		return view, err
	}
	reply, transmission, err := s.control(ctx, actor, view.Correlation, domain.TaskRead, protocol.Command{Operation: operation, Project: string(view.Correlation.Destination.Project), Body: body}, nil)
	if err != nil {
		return view, err
	}
	observed, err := s.acceptReply(ctx, actor, view.Correlation, transmission, reply, domain.TaskRead, "")
	if err != nil {
		return view, err
	}
	return observed, nil
}

// Recover performs only an explicit existing-only Delegate recovery, with the
// original identity/spec. Current grants and retained options are checked twice.
func (s *Service) Recover(ctx context.Context, actor domain.Actor, id domain.OperationID) (domain.OperationView, error) {
	view, err := s.store.GetForRecovery(ctx, actor, id)
	if err != nil {
		return domain.OperationView{}, err
	}
	body, err := protocol.Encode(protocol.TaskControl{Task: binding(view.Correlation, view.SpecDigest)}, protocol.MaxFrameBytes)
	if err != nil {
		return domain.OperationView{}, err
	}
	guard := func(guardCtx context.Context) error {
		current, checkErr := s.store.GetForRecovery(guardCtx, actor, id)
		if checkErr != nil {
			return checkErr
		}
		if current != view {
			return domain.Reject(domain.Conflict)
		}
		return nil
	}
	reply, transmission, err := s.control(ctx, actor, view.Correlation, domain.TaskDispatch, protocol.Command{Operation: protocol.ResumeExisting, Project: string(view.Correlation.Destination.Project), Body: body}, guard)
	if err != nil {
		return domain.OperationView{}, err
	}
	observed, err := s.acceptReply(ctx, actor, view.Correlation, transmission, reply, domain.TaskDispatch, "")
	observed.Observation = nil
	return observed, err
}

type CancellationResult struct {
	Operation        domain.OperationID
	Cancellation     domain.CancellationID
	DefinitelyUnsent bool
	ClosureConfirmed bool
}

func (s *Service) Cancel(ctx context.Context, actor domain.Actor, id domain.OperationID, cancellation domain.CancellationID) (CancellationResult, error) {
	bound, err := s.store.BindCancellation(ctx, actor, id, cancellation)
	if err != nil {
		return CancellationResult{}, err
	}
	result := CancellationResult{Operation: id, Cancellation: cancellation, DefinitelyUnsent: bound.DefinitelyUnsent}
	if bound.DefinitelyUnsent {
		return result, nil
	}
	// Resolve with an absent fence first. This closes a delayed first admission
	// without treating a missing reply as proof that the task never existed.
	fence, err := protocol.Encode(protocol.TaskControl{Task: binding(bound.Correlation, bound.SpecDigest)}, protocol.MaxFrameBytes)
	if err != nil {
		return result, err
	}
	reply, transmission, err := s.control(ctx, actor, bound.Correlation, domain.TaskCancel, protocol.Command{Operation: protocol.FenceAbsent, Project: string(bound.Correlation.Destination.Project), Body: fence}, nil)
	if err != nil {
		return result, err
	}
	view, err := s.acceptReply(ctx, actor, bound.Correlation, transmission, reply, domain.TaskCancel, cancellation)
	if err != nil {
		return result, err
	}
	if view.Observation == nil {
		return result, domain.Reject(domain.Pending)
	}
	if view.Observation.Kind == domain.Refused || view.Observation.Kind == domain.Terminal {
		result.ClosureConfirmed = true
		return result, nil
	}
	if view.Observation.Kind != domain.Existing {
		return result, domain.Reject(domain.Pending)
	}
	return s.cancelExisting(ctx, actor, bound, view.Observation.SpecDigest, result)
}

func (s *Service) cancelExisting(ctx context.Context, actor domain.Actor, bound domain.CancellationBinding, spec domain.Digest, result CancellationResult) (CancellationResult, error) {
	request := protocol.Cancellation{Task: binding(bound.Correlation, spec), CancellationID: string(bound.Cancellation)}
	if err := request.Validate(); err != nil {
		return result, err
	}
	body, err := protocol.Encode(request, protocol.MaxFrameBytes)
	if err != nil {
		return result, err
	}
	reply, transmission, err := s.control(ctx, actor, bound.Correlation, domain.TaskCancel, protocol.Command{Operation: protocol.Cancel, Project: string(bound.Correlation.Destination.Project), Body: body}, nil)
	if err != nil {
		return result, err
	}
	view, err := s.acceptReply(ctx, actor, bound.Correlation, transmission, reply, domain.TaskCancel, bound.Cancellation)
	if err != nil {
		return result, err
	}
	result.ClosureConfirmed = view.Observation != nil && (view.Observation.Kind == domain.Terminal || view.Observation.Kind == domain.Refused)
	return result, nil
}

func (s *Service) control(ctx context.Context, actor domain.Actor, c domain.Correlation, scope domain.Scope, command protocol.Command, guard func(context.Context) error) (reply protocol.Reply, transmission domain.Transmission, err error) {
	if _, err = s.store.Authorize(ctx, domain.AuthorizationRequest{Actor: actor, Destination: c.Destination, Scope: scope}); err != nil {
		return protocol.Reply{}, domain.Transmission{}, err
	}
	reservation, err := s.link.Reserve(ctx, c.Destination.Device, c.Operation, command)
	if err != nil {
		return protocol.Reply{}, domain.Transmission{}, err
	}
	defer releaseReservation(ctx, reservation, &err)
	transmission = reservation.Transmission()
	transmission.Operation = c.Operation
	transmission.Now = s.now()
	if transmission.Credential.Device != c.Destination.Device {
		return protocol.Reply{}, transmission, domain.Reject(domain.EvidenceInvalid)
	}
	if err = s.acquireControlRoute(ctx, reservation); err != nil {
		return protocol.Reply{}, transmission, err
	}
	err = reservation.Publish(ctx, func(guardCtx context.Context) error {
		if _, authorizeErr := s.store.Authorize(guardCtx, domain.AuthorizationRequest{Actor: actor, Destination: c.Destination, Scope: scope}); authorizeErr != nil {
			return authorizeErr
		}
		if guard != nil {
			return guard(guardCtx)
		}
		return nil
	})
	if err != nil {
		return protocol.Reply{}, transmission, err
	}
	reply, err = reservation.Await(ctx)
	if err != nil {
		return protocol.Reply{}, transmission, err
	}
	if reply.Operation != command.Operation || reply.Validate() != nil {
		return protocol.Reply{}, transmission, domain.Reject(domain.EvidenceInvalid)
	}
	return reply, transmission, nil
}

func binding(c domain.Correlation, spec domain.Digest) protocol.TaskBinding {
	result := protocol.TaskBinding{TaskID: string(c.Task), Context: protocol.ContextBinding{Root: string(c.Context.Root), Project: string(c.Context.Project)}, Origin: protocol.Origin{GatewayID: string(c.Gateway), AdmissionGeneration: string(c.AdmissionGeneration), OperationID: string(c.Operation), PrincipalRef: string(c.Owner.Principal), RequestSHA256: hex.EncodeToString(c.RequestDigest[:])}}
	if spec != (domain.Digest{}) {
		result.SpecSHA256 = hex.EncodeToString(spec[:])
	}
	return result
}
