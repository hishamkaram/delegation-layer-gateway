// Package gateway composes authorization, immutable correlation and routing.
// Registry owns Gateway persistence; Delegate alone owns task execution/outcomes.
package gateway

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type DispatchStore interface {
	AuthorizeOwnedDevice(context.Context, domain.OwnedDeviceRequest) (domain.OwnedDeviceAuthorization, error)
	LookupPreparation(context.Context, domain.Actor, domain.DeviceID, domain.RequestID, domain.Digest) (domain.PreparedOperation, bool, error)
	Authorize(context.Context, domain.AuthorizationRequest) (domain.Authorization, error)
	Prepare(context.Context, domain.Actor, domain.Preparation) (domain.PreparedOperation, error)
	GetForDispatch(context.Context, domain.Actor, domain.OperationID, time.Time) (domain.DispatchView, error)
	MarkPossibleSendRouted(context.Context, domain.Actor, domain.Transmission, routing.Request) (domain.SendDecision, error)
	AcquireRouting(context.Context, routing.Request) error
	CheckQueuedAdmission(context.Context, domain.Actor, domain.Transmission) error
	ApplyResolution(context.Context, domain.ValidatedResolution) (domain.OperationView, error)
	GetOperation(context.Context, domain.Actor, domain.OperationID) (domain.OperationView, error)
	GetForRecovery(context.Context, domain.Actor, domain.OperationID) (domain.RecoveryView, error)
	BindCancellation(context.Context, domain.Actor, domain.OperationID, domain.CancellationID) (domain.CancellationBinding, error)
	CheckConnection(context.Context, domain.CredentialRef, domain.ConnectionGeneration, time.Time) (domain.Credential, error)
}
type LinkSnapshot struct {
	WireVersion    int
	CapabilitiesV2 *protocol.CapabilityReportV2
	ProcessBoot    string
	Credential     domain.CredentialRef
	Connection     domain.ConnectionGeneration
	Capabilities   protocol.CapabilityReport
	ObservedAt     time.Time
}

// Link owns only live routing resources. Reserve fixes and encodes the actual
// generation before the registry is allowed to mark a transmission possible.
type Link interface {
	Snapshot(domain.DeviceID) (LinkSnapshot, error)
	Reserve(context.Context, domain.DeviceID, domain.OperationID, protocol.Command) (Reservation, error)
}
type Reservation interface {
	Transmission() domain.Transmission
	TransferSnapshot() routing.TransferSnapshot
	Routing() (routing.Request, error)
	ArmRouting(routing.Request) error
	Publish(context.Context, func(context.Context) error) error
	Await(context.Context) (protocol.Reply, error)
	Release(context.Context) error
}
type Service struct {
	observer RoutingObserver
	store    DispatchStore
	link     Link
	gateway  domain.GatewayID
	random   io.Reader
	now      func() time.Time
	targeted TargetedCapabilities
}

func New(store DispatchStore, link Link, gateway domain.GatewayID, random io.Reader, now func() time.Time, observer RoutingObserver, targeted ...TargetedCapabilities) (*Service, error) {
	if store == nil || link == nil || domain.Token(string(gateway)) != nil || random == nil || now == nil || observer == nil {
		return nil, domain.ErrInvalid
	}
	if len(targeted) > 1 || (len(targeted) == 1 && targeted[0] == nil) {
		return nil, domain.ErrInvalid
	}
	service := &Service{store: store, link: link, gateway: gateway, random: random, now: now, observer: observer}
	if len(targeted) == 1 {
		service.targeted = targeted[0]
	}
	return service, nil
}

func (s *Service) Prepare(ctx context.Context, actor domain.Actor, destination domain.Destination, request domain.FrozenRequest) (prepared domain.PreparedOperation, err error) {
	attempt := s.startObservation(actor, routing.PrepareClass)
	defer func() { attempt.finish(err) }()
	if actor.Validate() != nil || destination.Validate() != nil || request.Validate() != nil {
		return domain.PreparedOperation{}, domain.ErrInvalid
	}
	authorized, err := s.store.Authorize(ctx, domain.AuthorizationRequest{Actor: actor, Destination: destination, Scope: domain.TaskDispatch})
	attempt.authorize(err)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	attempt.value.Destination = authorized.Destination
	snapshot, err := s.link.Snapshot(destination.Device)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	if snapshot.Credential.Device != destination.Device {
		return domain.PreparedOperation{}, domain.Reject(domain.Conflict)
	}
	capability, err := s.currentProject(ctx, actor, destination, snapshot)
	if err != nil {
		s.observeClassAuthorizationFailure(actor, routing.PrepareClass, err)
		return domain.PreparedOperation{}, err
	}
	var entropy [32]byte
	if _, err = io.ReadFull(s.random, entropy[:]); err != nil {
		return domain.PreparedOperation{}, errors.New("operation entropy unavailable")
	}
	correlation := domain.Correlation{Operation: domain.OperationID(hex.EncodeToString(entropy[:16])), Task: domain.TaskID(hex.EncodeToString(entropy[16:])), Gateway: s.gateway, AdmissionGeneration: domain.AdmissionGeneration(capability.AdmissionGeneration), Owner: domain.OperationOwner{Kind: domain.Owned, Principal: actor.Principal}, Destination: destination, Context: domain.ContextBinding{Root: domain.RootGuard(capability.Context.Root), Project: domain.ProjectGuard(capability.Context.Project)}, BriefDigest: domain.Hash([]byte(request.Brief))}
	correlation.RequestDigest, err = domain.RequestDigest(correlation, request)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	command, err := admissionCommand(correlation, request)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	if err = preflight(command, string(correlation.Operation)); err != nil {
		return domain.PreparedOperation{}, err
	}
	prepared, err = s.store.Prepare(ctx, actor, domain.Preparation{Correlation: correlation, Request: request, Now: s.now()})
	if err == nil {
		attempt.bind(prepared.Correlation)
		attempt.value.Prepared = true
	} else {
		s.observeClassAuthorizationFailure(actor, routing.PrepareClass, err)
	}
	return prepared, err
}

type DispatchResult struct {
	Operation domain.OperationView
}

func (s *Service) Dispatch(ctx context.Context, actor domain.Actor, operation domain.OperationID) (result DispatchResult, err error) {
	attempt := s.startObservation(actor, routing.ControlClass(protocol.Admit))
	defer func() { attempt.finish(err) }()
	view, err := s.store.GetForDispatch(ctx, actor, operation, s.now())
	attempt.authorize(err)
	if err != nil {
		return DispatchResult{}, err
	}
	attempt.bind(view.Operation.Correlation)
	operationKind := dispatchOperation(view.Operation.Correlation)
	attempt.value.Control.Class = routing.ControlClass(operationKind)
	if view.Operation.Delivery != domain.Prepared {
		return DispatchResult{Operation: view.Operation}, nil
	}
	reservation, err := s.reserveDispatch(ctx, actor, view, operation)
	if err != nil {
		s.observeAuthorizationFailure(actor, operationKind, err)
		return DispatchResult{}, err
	}
	attempt.reservation = reservation
	defer releaseReservation(ctx, reservation, &err)
	transmission := reservation.Transmission()
	transmission.Operation = operation
	transmission.Now = s.now()
	route, err := reservation.Routing()
	if err != nil {
		return DispatchResult{}, err
	}
	attempt.route(transmission, route)
	route.Now = transmission.Now
	decision, err := s.store.MarkPossibleSendRouted(ctx, actor, transmission, route)
	if err != nil {
		s.observeAuthorizationFailure(actor, operationKind, err)
		return DispatchResult{}, err
	}
	if decision.Kind == domain.ObserveExisting {
		return DispatchResult{Operation: decision.Operation}, nil
	}
	if decision.Kind != domain.SendOnce {
		return DispatchResult{}, domain.Reject(domain.EvidenceInvalid)
	}
	if err = reservation.ArmRouting(route); err != nil {
		return DispatchResult{Operation: decision.Operation}, err
	}
	// The payload was encoded and queue capacity reserved before the durable
	// decision. Recheck current grants immediately before the transport write.
	err = reservation.Publish(ctx, func(guardCtx context.Context) error {
		transmission.Now = s.now()
		return attempt.guard(func() error { return s.store.CheckQueuedAdmission(guardCtx, actor, transmission) })
	})
	if err != nil {
		return DispatchResult{Operation: decision.Operation}, err
	}
	reply, err := reservation.Await(ctx)
	if err != nil {
		return DispatchResult{Operation: decision.Operation}, err
	}
	if reply.Operation != operationKind || reply.Validate() != nil {
		return DispatchResult{Operation: decision.Operation}, domain.Reject(domain.EvidenceInvalid)
	}
	attempt.replyValid = true
	observed, err := s.acceptReply(ctx, actor, view.Operation.Correlation, transmission, reply, domain.TaskDispatch, "")
	if err != nil {
		return DispatchResult{Operation: decision.Operation}, err
	}
	observed.Observation = nil // Dispatch permission never grants cached result/status access.
	return DispatchResult{Operation: observed}, nil
}

func (s *Service) reserveDispatch(ctx context.Context, actor domain.Actor, view domain.DispatchView, operation domain.OperationID) (Reservation, error) {
	snapshot, err := s.link.Snapshot(view.Operation.Correlation.Destination.Device)
	if err != nil {
		return nil, err
	}
	if view.Operation.Correlation.Route.Version == 1 {
		if err = validateSelectedSnapshot(snapshot, view.Operation.Correlation); err != nil {
			return nil, err
		}
	} else {
		capability, e := s.currentProject(ctx, actor, view.Operation.Correlation.Destination, snapshot)
		if e != nil {
			return nil, e
		}
		if err = matchesCapability(snapshot, capability, view); err != nil {
			return nil, err
		}
	}
	command, err := s.dispatchCommand(ctx, actor, view.Operation.Correlation, view.Request)
	if err != nil {
		return nil, err
	}
	// Historical unsent v4 drafts remain replayable, but must pass the current
	// control budget before their first possible-send transition or reservation.
	if view.Operation.Correlation.RequestVersion == domain.CompactRequestVersion {
		if err = preflight(command, string(operation)); err != nil {
			return nil, err
		}
	}
	reservation, err := s.link.Reserve(ctx, view.Operation.Correlation.Destination.Device, operation, command)
	if err != nil {
		return nil, err
	}
	if err = matchReservation(snapshot, reservation); err != nil {
		releaseReservation(ctx, reservation, &err)
		return nil, err
	}
	return reservation, nil
}

func project(snapshot LinkSnapshot, alias domain.ProjectAlias) (protocol.ProjectCapability, error) {
	if snapshot.Credential.Validate() != nil || snapshot.Connection.Validate() != nil || snapshot.Capabilities.Validate() != nil {
		return protocol.ProjectCapability{}, domain.Reject(domain.EvidenceInvalid)
	}
	for _, capability := range snapshot.Capabilities.Projects {
		if capability.Alias == string(alias) {
			if !capability.Ready {
				return protocol.ProjectCapability{}, domain.Reject(domain.Pending)
			}
			return capability, nil
		}
	}
	return protocol.ProjectCapability{}, domain.Reject(domain.NotFound)
}

func matchesCapability(snapshot LinkSnapshot, capability protocol.ProjectCapability, view domain.DispatchView) error {
	c := view.Operation.Correlation
	if snapshot.Credential.Device != c.Destination.Device || capability.Context.Root != string(c.Context.Root) || capability.Context.Project != string(c.Context.Project) || capability.AdmissionGeneration != string(c.AdmissionGeneration) {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func admissionCommand(c domain.Correlation, r domain.FrozenRequest) (protocol.Command, error) {
	if c.Kind == domain.RequestKindContinuation {
		return protocol.Command{}, domain.ErrInvalid
	}
	task, err := binding(c, domain.Digest{})
	if err != nil {
		return protocol.Command{}, err
	}
	admission := protocol.Admission{Native: wireNativeOptions(r.Native), Task: task, Provider: string(r.Provider), Model: protocol.Selection{Kind: string(r.Model.Kind), Value: r.Model.Value}, Effort: protocol.Selection{Kind: string(r.Effort.Kind), Value: r.Effort.Value}, Permission: string(r.Permission), BudgetSeconds: r.BudgetSeconds, Brief: r.Brief}
	if err = admission.Validate(); err != nil {
		return protocol.Command{}, err
	}
	body, err := protocol.Encode(admission, protocol.MaxFrameBytes)
	return protocol.Command{Operation: protocol.Admit, Project: string(c.Destination.Project), Body: body}, err
}

func dispatchOperation(c domain.Correlation) protocol.Operation {
	if c.Kind == domain.RequestKindContinuation {
		return protocol.Continue
	}
	return protocol.Admit
}

func (s *Service) dispatchCommand(ctx context.Context, actor domain.Actor, c domain.Correlation, request domain.FrozenRequest) (protocol.Command, error) {
	if c.Kind != domain.RequestKindContinuation {
		return admissionCommand(c, request)
	}
	parent, err := s.continuationPredecessor(ctx, actor, c.Predecessor.Operation)
	if err != nil {
		return protocol.Command{}, err
	}
	return continuationCommand(c, request, parent)
}

func preflight(command protocol.Command, operation string) error {
	if err := preflightFrame(command, maximumControlFrame(operation, protocol.Version), protocol.MaxAdmissionFrameBytes); err != nil {
		return err
	}
	task, err := preflightTask(command)
	if err != nil {
		return err
	}
	// This synthetic projection is used only for encoded-size bounds. No receipt
	// or task closure is recorded, and the immutable admission binding is intact.
	task.SpecSHA256 = strings.Repeat("f", 64)
	for _, control := range []protocol.Operation{protocol.FenceAbsent, protocol.Cancel} {
		if err = preflightProtectedControl(task, command.Project, operation, control); err != nil {
			return err
		}
	}
	return nil
}

func preflightTask(command protocol.Command) (protocol.TaskBinding, error) {
	if command.Operation == protocol.Continue {
		var value protocol.Continuation
		if protocol.DecodeStrict(command.Body, &value, protocol.MaxFrameBytes) != nil || value.Validate() != nil {
			return protocol.TaskBinding{}, protocol.ErrInvalid
		}
		return value.Task, nil
	}
	var value protocol.Admission
	if command.Operation != protocol.Admit || protocol.DecodeStrict(command.Body, &value, protocol.MaxFrameBytes) != nil || value.Validate() != nil {
		return protocol.TaskBinding{}, protocol.ErrInvalid
	}
	return value.Task, nil
}

func maximumControlFrame(operation string, version int) protocol.Frame {
	return protocol.Frame{Version: version, Type: protocol.Request, RequestID: strings.Repeat("r", 128), Generation: protocol.Generation{BootEpoch: strings.Repeat("b", 128), Counter: math.MaxUint64}, OperationID: operation, TTLMillis: protocol.MaxTTL.Milliseconds()}
}

func preflightFrame[T any](value T, frame protocol.Frame, limit int) error {
	payload, err := protocol.Encode(value, protocol.MaxFrameBytes)
	if err != nil {
		return err
	}
	frame.Payload = payload
	encoded, err := protocol.EncodeFrameVersion(frame, frame.Version)
	if err != nil {
		return err
	}
	if len(encoded) > limit {
		return protocol.ErrTooLarge
	}
	return nil
}

func preflightProtectedControl(task protocol.TaskBinding, project, operation string, control protocol.Operation) error {
	var body []byte
	var err error
	if control == protocol.Cancel {
		body, err = protocol.Encode(protocol.Cancellation{Task: task, CancellationID: strings.Repeat("c", 32)}, protocol.MaxFrameBytes)
	} else {
		body, err = protocol.Encode(protocol.TaskControl{Task: task}, protocol.MaxFrameBytes)
	}
	if err != nil {
		return err
	}
	command := protocol.Command{Operation: control, Project: project, Body: body}
	for _, version := range []int{protocol.Version, protocol.WireVersion2} {
		frame := maximumControlFrame(operation, version)
		if err = preflightFrame(command, frame, protocol.MaxProtectedFrameBytes); err != nil {
			return err
		}
		if err = preflightProtectedReplies(task, command, frame); err != nil {
			return err
		}
	}
	return nil
}

func preflightProtectedReplies(task protocol.TaskBinding, command protocol.Command, frame protocol.Frame) error {
	// These are the longest TaskObservation values allowed by its validators.
	// A full closure exceeds the mutually exclusive pending-closure projection;
	// false stop flags encode longer than true, and result length is int64-bound.
	observation := protocol.TaskObservation{Task: task, BriefSHA256: strings.Repeat("f", 64), Resolution: "existing", Admission: "not-admitted", Liveness: "undetermined", Publication: "committed", Verdict: "committed", Result: &protocol.Descriptor{SHA256: strings.Repeat("d", 64), Length: math.MaxInt64}, Stop: &protocol.StopObservation{RequestID: strings.Repeat("c", 32)}, ExecutionClosure: &protocol.ExecutionClosure{Kind: "unregistered-recovered", ReferenceSHA256: strings.Repeat("e", 64)}}
	if observation.Validate() != nil {
		return protocol.ErrInvalid
	}
	body, err := protocol.Encode(observation, protocol.MaxFrameBytes)
	if err != nil {
		return err
	}
	replies := []protocol.Reply{
		{Operation: command.Operation, Body: body},
		{Operation: command.Operation, Error: &protocol.Failure{Code: "result_verification_timeout", Stage: strings.Repeat("s", 128)}},
	}
	frame.Type = protocol.Response
	for _, reply := range replies {
		if err = preflightFrame(reply, frame, protocol.MaxProtectedFrameBytes); err != nil {
			return err
		}
		if err = preflightCompletedReply(reply, frame); err != nil {
			return err
		}
	}
	return nil
}

func preflightCompletedReply(reply protocol.Reply, frame protocol.Frame) error {
	// Bound each validated field independently. The outer frame permits 128-byte
	// IDs; a completion call permits only the shorter canonical g:uint64 ID.
	call := protocol.ControlCall{Generation: frame.Generation, RequestID: "g:18446744073709551615", OperationID: frame.OperationID, Operation: reply.Operation, RequestSHA256: strings.Repeat("f", 64)}
	disposition := protocol.ControlPending
	if reply.Error != nil {
		disposition = protocol.ControlNotClaimed
	}
	response := protocol.ControlResponse{Completion: protocol.ControlCompletion{ProcessBoot: strings.Repeat("a", 32), Call: call, Disposition: disposition}, Reply: reply}
	if response.ValidateVersion(frame.Version) != nil {
		return protocol.ErrInvalid
	}
	return preflightFrame(response, frame, protocol.MaxProtectedFrameBytes)
}
