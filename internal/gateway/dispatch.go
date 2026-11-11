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
	ProcessBoot  string
	Credential   domain.CredentialRef
	Connection   domain.ConnectionGeneration
	Capabilities protocol.CapabilityReport
	ObservedAt   time.Time
}

// Link owns only live routing resources. Reserve fixes and encodes the actual
// generation before the registry is allowed to mark a transmission possible.
type Link interface {
	Snapshot(domain.DeviceID) (LinkSnapshot, error)
	Reserve(context.Context, domain.DeviceID, domain.OperationID, protocol.Command) (Reservation, error)
}
type Reservation interface {
	Transmission() domain.Transmission
	Routing() (routing.Request, error)
	ArmRouting(routing.Request) error
	Publish(context.Context, func(context.Context) error) error
	Await(context.Context) (protocol.Reply, error)
	Release(context.Context) error
}
type Service struct {
	store   DispatchStore
	link    Link
	gateway domain.GatewayID
	random  io.Reader
	now     func() time.Time
}

func New(store DispatchStore, link Link, gateway domain.GatewayID, random io.Reader, now func() time.Time) (*Service, error) {
	if store == nil || link == nil || domain.Token(string(gateway)) != nil || random == nil || now == nil {
		return nil, domain.ErrInvalid
	}
	return &Service{store: store, link: link, gateway: gateway, random: random, now: now}, nil
}

func (s *Service) Prepare(ctx context.Context, actor domain.Actor, destination domain.Destination, request domain.FrozenRequest) (domain.PreparedOperation, error) {
	if actor.Validate() != nil || destination.Validate() != nil || request.Validate() != nil {
		return domain.PreparedOperation{}, domain.ErrInvalid
	}
	if _, err := s.store.Authorize(ctx, domain.AuthorizationRequest{Actor: actor, Destination: destination, Scope: domain.TaskDispatch}); err != nil {
		return domain.PreparedOperation{}, err
	}
	snapshot, err := s.link.Snapshot(destination.Device)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	if snapshot.Credential.Device != destination.Device {
		return domain.PreparedOperation{}, domain.Reject(domain.Conflict)
	}
	capability, err := project(snapshot, destination.Project)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	if !allows(capability, request) {
		return domain.PreparedOperation{}, domain.Reject(domain.Forbidden)
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
		if errors.Is(err, protocol.ErrTooLarge) {
			return domain.PreparedOperation{}, domain.Reject(domain.ResourceLimit)
		}
		return domain.PreparedOperation{}, err
	}
	if err = preflight(command, string(correlation.Operation)); err != nil {
		return domain.PreparedOperation{}, domain.Reject(domain.ResourceLimit)
	}
	return s.store.Prepare(ctx, actor, domain.Preparation{Correlation: correlation, Request: request, Now: s.now()})
}

type DispatchResult struct {
	Operation domain.OperationView
}

func (s *Service) Dispatch(ctx context.Context, actor domain.Actor, operation domain.OperationID) (result DispatchResult, err error) {
	view, err := s.store.GetForDispatch(ctx, actor, operation, s.now())
	if err != nil {
		return DispatchResult{}, err
	}
	if view.Operation.Delivery != domain.Prepared {
		return DispatchResult{Operation: view.Operation}, nil
	}
	reservation, err := s.reserveDispatch(ctx, view, operation)
	if err != nil {
		return DispatchResult{}, err
	}
	defer releaseReservation(ctx, reservation, &err)
	transmission := reservation.Transmission()
	transmission.Operation = operation
	transmission.Now = s.now()
	route, err := reservation.Routing()
	if err != nil {
		return DispatchResult{}, err
	}
	route.Now = transmission.Now
	decision, err := s.store.MarkPossibleSendRouted(ctx, actor, transmission, route)
	if err != nil {
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
		return s.store.CheckQueuedAdmission(guardCtx, actor, transmission)
	})
	if err != nil {
		return DispatchResult{Operation: decision.Operation}, err
	}
	reply, err := reservation.Await(ctx)
	if err != nil {
		return DispatchResult{Operation: decision.Operation}, err
	}
	if reply.Operation != protocol.Admit || reply.Validate() != nil {
		return DispatchResult{Operation: decision.Operation}, domain.Reject(domain.EvidenceInvalid)
	}
	observed, err := s.acceptReply(ctx, actor, view.Operation.Correlation, transmission, reply, domain.TaskDispatch, "")
	if err != nil {
		return DispatchResult{Operation: decision.Operation}, err
	}
	observed.Observation = nil // Dispatch permission never grants cached result/status access.
	return DispatchResult{Operation: observed}, nil
}

func (s *Service) reserveDispatch(ctx context.Context, view domain.DispatchView, operation domain.OperationID) (Reservation, error) {
	snapshot, err := s.link.Snapshot(view.Operation.Correlation.Destination.Device)
	if err != nil {
		return nil, err
	}
	if err = matches(snapshot, view); err != nil {
		return nil, err
	}
	command, err := admissionCommand(view.Operation.Correlation, view.Request)
	if err != nil {
		return nil, err
	}
	return s.link.Reserve(ctx, view.Operation.Correlation.Destination.Device, operation, command)
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

func matches(snapshot LinkSnapshot, view domain.DispatchView) error {
	capability, err := project(snapshot, view.Operation.Correlation.Destination.Project)
	if err != nil {
		return err
	}
	c := view.Operation.Correlation
	if snapshot.Credential.Device != c.Destination.Device || capability.Context.Root != string(c.Context.Root) || capability.Context.Project != string(c.Context.Project) || capability.AdmissionGeneration != string(c.AdmissionGeneration) {
		return domain.Reject(domain.Conflict)
	}
	if !allows(capability, view.Request) {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

func allows(project protocol.ProjectCapability, request domain.FrozenRequest) bool {
	for _, provider := range project.Providers {
		if provider.Provider != string(request.Provider) {
			continue
		}
		if request.BudgetSeconds > provider.MaxBudgetSeconds || !contains(provider.Permissions, string(request.Permission)) {
			return false
		}
		return selectionAllowed(request.Model, provider.Models) && selectionAllowed(request.Effort, provider.Efforts)
	}
	return false
}

func selectionAllowed(selection domain.Selection, values []string) bool {
	return selection.Kind == domain.NativeDefault || (selection.Kind == domain.Explicit && contains(values, selection.Value))
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func admissionCommand(c domain.Correlation, r domain.FrozenRequest) (protocol.Command, error) {
	admission := protocol.Admission{Task: protocol.TaskBinding{TaskID: string(c.Task), Context: protocol.ContextBinding{Root: string(c.Context.Root), Project: string(c.Context.Project)}, Origin: protocol.Origin{GatewayID: string(c.Gateway), AdmissionGeneration: string(c.AdmissionGeneration), OperationID: string(c.Operation), PrincipalRef: string(c.Owner.Principal), RequestSHA256: hex.EncodeToString(c.RequestDigest[:])}}, Provider: string(r.Provider), Model: protocol.Selection{Kind: string(r.Model.Kind), Value: r.Model.Value}, Effort: protocol.Selection{Kind: string(r.Effort.Kind), Value: r.Effort.Value}, Permission: string(r.Permission), BudgetSeconds: r.BudgetSeconds, Brief: r.Brief}
	if err := admission.Validate(); err != nil {
		return protocol.Command{}, err
	}
	body, err := protocol.Encode(admission, protocol.MaxFrameBytes)
	return protocol.Command{Operation: protocol.Admit, Project: string(c.Destination.Project), Body: body}, err
}

func preflight(command protocol.Command, operation string) error {
	payload, err := protocol.Encode(command, protocol.MaxFrameBytes)
	if err != nil {
		return err
	}
	encoded, err := protocol.EncodeFrame(protocol.Frame{Version: protocol.Version, Type: protocol.Request, RequestID: strings.Repeat("r", 128), Generation: protocol.Generation{BootEpoch: strings.Repeat("b", 128), Counter: math.MaxUint64}, OperationID: operation, TTLMillis: 30000, Payload: payload})
	if err != nil {
		return err
	}
	if len(encoded) > protocol.MaxAdmissionFrameBytes {
		return protocol.ErrTooLarge
	}
	return nil
}
