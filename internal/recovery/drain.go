package recovery

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type DrainStore interface {
	GetAdministrativeTask(context.Context, domain.NativeTaskKey) (domain.AdministrativeTaskView, error)
	ListAdministrativeTasks(context.Context, domain.AdministrativeTaskPageRequest) (domain.AdministrativeTaskPage, error)
	BindAdministrativeCancellation(context.Context, domain.NativeTaskKey, domain.CancellationID) (domain.AdministrativeTaskView, error)
	CheckAdministrativeDrain(context.Context, domain.AdministrativeDrainCheck) error
	RecordAdministrativeObservation(context.Context, domain.AdministrativeObservation) (domain.AdministrativeTaskView, error)
	BindAdministrativeRoute(context.Context, domain.AdministrativeRouteBinding) error
}

type DrainRequest struct {
	Key          domain.NativeTaskKey
	Route        domain.Destination
	Action       domain.AdministrativeAction
	Cancellation domain.CancellationID
}

// Drainer routes explicit controls. Registry retains cancellation intent and
// holds, while Delegate supplies every execution and closure observation.
type Drainer struct {
	store     DrainStore
	namespace *Service
	now       func() time.Time
}

func NewDrainer(store DrainStore, namespace *Service, now func() time.Time) (*Drainer, error) {
	if store == nil || namespace == nil || now == nil {
		return nil, domain.ErrInvalid
	}
	return &Drainer{store: store, namespace: namespace, now: now}, nil
}

func (d *Drainer) List(ctx context.Context, input domain.AdministrativeTaskPageRequest) (domain.AdministrativeTaskPage, error) {
	return d.store.ListAdministrativeTasks(ctx, input)
}

func (d *Drainer) Get(ctx context.Context, key domain.NativeTaskKey) (domain.AdministrativeTaskView, error) {
	return d.store.GetAdministrativeTask(ctx, key)
}

func (d *Drainer) Control(ctx context.Context, input DrainRequest) (domain.AdministrativeTaskView, error) {
	if input.Key.Validate() != nil || input.Route.Validate() != nil || input.Route.Device != input.Key.Device || input.Action.Validate() != nil {
		return domain.AdministrativeTaskView{}, domain.ErrInvalid
	}
	if input.Action == domain.AdministrativeCancel {
		return d.cancel(ctx, input)
	}
	if input.Cancellation != "" {
		return domain.AdministrativeTaskView{}, domain.ErrInvalid
	}
	view, err := d.store.GetAdministrativeTask(ctx, input.Key)
	if err != nil {
		return view, err
	}
	return d.observe(ctx, input, view)
}

func (d *Drainer) cancel(ctx context.Context, input DrainRequest) (domain.AdministrativeTaskView, error) {
	if input.Cancellation.Validate() != nil {
		return domain.AdministrativeTaskView{}, domain.ErrInvalid
	}
	view, err := d.store.BindAdministrativeCancellation(ctx, input.Key, input.Cancellation)
	if err != nil {
		return view, err
	}
	fence := input
	fence.Action = domain.AdministrativeFence
	view, err = d.observe(ctx, fence, view)
	if err != nil || !view.Reserved {
		return view, err
	}
	if view.Observation == nil || view.Observation.Kind != domain.Existing || view.Binding.SpecDigest == (domain.Digest{}) {
		return view, domain.Reject(domain.Pending)
	}
	return d.observe(ctx, input, view)
}

func (d *Drainer) observe(ctx context.Context, input DrainRequest, view domain.AdministrativeTaskView) (domain.AdministrativeTaskView, error) {
	if view.Correlation != nil && view.Correlation.Operation != view.Binding.Origin.Operation {
		return view, domain.Reject(domain.EvidenceInvalid)
	}
	command, err := drainCommand(input, view)
	if err != nil {
		return view, err
	}
	check := domain.AdministrativeDrainCheck{Key: input.Key, Action: input.Action, Destination: input.Route}
	observed := view
	_, _, err = d.namespace.wire.exchangeWithOperation(ctx, input.Route, view.Binding.Origin.Operation, command, func(call context.Context, current domain.Transmission) error {
		if current.Operation != view.Binding.Origin.Operation {
			return domain.Reject(domain.EvidenceInvalid)
		}
		guard := check
		guard.Credential, guard.Connection, guard.Now = current.Credential, current.Connection, current.Now
		return d.store.CheckAdministrativeDrain(call, guard)
	}, func(reply protocol.Reply, transmission domain.Transmission) error {
		now := d.now()
		check.Credential, check.Connection, check.Now = transmission.Credential, transmission.Connection, now
		observation, acceptErr := drainObservation(reply, view, now)
		if acceptErr != nil {
			return acceptErr
		}
		updated, acceptErr := d.store.RecordAdministrativeObservation(ctx, domain.AdministrativeObservation{Check: check, Binding: view.Binding, Observation: observation})
		if acceptErr != nil {
			return acceptErr
		}
		observed = updated
		if observation.Kind == domain.Existing {
			return d.store.BindAdministrativeRoute(ctx, domain.AdministrativeRouteBinding{Destination: input.Route, Context: view.Binding.Context, Credential: transmission.Credential, Connection: transmission.Connection, Now: d.now()})
		}
		return nil
	})
	return observed, err
}

func drainCommand(input DrainRequest, view domain.AdministrativeTaskView) (protocol.Command, error) {
	operation := protocol.Resolve
	switch input.Action {
	case domain.AdministrativeResolve:
	case domain.AdministrativeStatus:
		operation = protocol.Status
	case domain.AdministrativeCollect:
		operation = protocol.Collect
	case domain.AdministrativeFence:
		operation = protocol.FenceAbsent
	case domain.AdministrativeCancel:
		operation = protocol.Cancel
	default:
		return protocol.Command{}, domain.ErrInvalid
	}
	task := drainBinding(view.Binding)
	var body []byte
	var err error
	if operation == protocol.Cancel {
		if view.Cancellation != input.Cancellation || view.Binding.SpecDigest == (domain.Digest{}) {
			return protocol.Command{}, domain.Reject(domain.Conflict)
		}
		body, err = protocol.Encode(protocol.Cancellation{Task: task, CancellationID: string(view.Cancellation)}, protocol.MaxFrameBytes)
	} else {
		body, err = protocol.Encode(protocol.TaskControl{Task: task}, protocol.MaxFrameBytes)
	}
	return protocol.Command{Operation: operation, Project: string(input.Route.Project), Body: body}, err
}

func drainBinding(binding domain.AdministrativeTaskBinding) protocol.TaskBinding {
	origin := binding.Origin
	result := protocol.TaskBinding{TaskID: string(binding.Task), Context: protocol.ContextBinding{Root: string(binding.Context.Root), Project: string(binding.Context.Project)}, Origin: protocol.Origin{GatewayID: string(origin.Gateway), AdmissionGeneration: string(origin.AdmissionGeneration), OperationID: string(origin.Operation), PrincipalRef: string(origin.Principal), RequestSHA256: hex.EncodeToString(origin.RequestDigest[:])}}
	if binding.SpecDigest != (domain.Digest{}) {
		result.SpecSHA256 = hex.EncodeToString(binding.SpecDigest[:])
	}
	return result
}

func drainObservation(reply protocol.Reply, view domain.AdministrativeTaskView, now time.Time) (domain.DelegateObservation, error) {
	var observation protocol.TaskObservation
	if protocol.DecodeStrict(reply.Body, &observation, protocol.MaxFrameBytes) != nil || observation.Validate() != nil {
		return domain.DelegateObservation{}, domain.Reject(domain.EvidenceInvalid)
	}
	want := drainBinding(view.Binding)
	got := observation.Task
	if got.TaskID != want.TaskID || got.Context != want.Context || got.Origin != want.Origin || (want.SpecSHA256 != "" && got.SpecSHA256 != want.SpecSHA256) {
		return domain.DelegateObservation{}, domain.Reject(domain.EvidenceInvalid)
	}
	if observation.Resolution == "existing" {
		if view.Correlation != nil && observation.BriefSHA256 != hex.EncodeToString(view.Correlation.BriefDigest[:]) {
			return domain.DelegateObservation{}, domain.Reject(domain.EvidenceInvalid)
		}
		if view.Receipt != nil && observation.BriefSHA256 != hex.EncodeToString(view.Receipt.BriefDigest[:]) {
			return domain.DelegateObservation{}, domain.Reject(domain.EvidenceInvalid)
		}
	}
	return gateway.ObservationFromReply(reply, observation, view.Cancellation, now)
}
