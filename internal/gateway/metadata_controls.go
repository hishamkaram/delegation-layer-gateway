package gateway

import (
	"context"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// MetadataCall is a consumer-owned routing request, never a Native task or an
// execution result. Callbacks close over the concrete immutable Registry
// request; no HTTP/MCP caller supplies callbacks, raw CLI arguments or policy.
type MetadataCall struct {
	Actor     domain.Actor
	Device    domain.DeviceID
	Operation domain.OperationID
	Scope     domain.Scope
	Command   protocol.Command
	Authorize func(context.Context) error
	Acquire   func(context.Context, routing.Request) error
	Check     func(context.Context, domain.Transmission) error
	// Validate checks the precise typed reply body, without storage mutation.
	Validate func(protocol.Reply, domain.Transmission) error
}

func (c MetadataCall) valid() bool {
	if c.Actor.Validate() != nil || domain.CredentialToken(string(c.Device)) != nil || domain.RoutingToken(string(c.Operation)) != nil || c.Command.ValidateVersion(protocol.WireVersion2) != nil {
		return false
	}
	if c.Authorize == nil || c.Acquire == nil || c.Check == nil || c.Validate == nil || !c.Actor.Scopes.Has(c.Scope) {
		return false
	}
	return c.permittedOperation()
}

func (c MetadataCall) permittedOperation() bool {
	switch c.Command.Operation {
	case protocol.ResolveProject:
		return c.Scope == domain.TaskDispatch && c.Command.Root != ""
	case protocol.ContextInspect:
		return (c.Scope == domain.InventoryRead || c.Scope == domain.TaskDispatch) && c.Command.Project != ""
	case protocol.Admit, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen:
		return false
	}
	return false
}

// MetadataControls reuses live Link reservations, census and resource permits.
// It owns no background worker, retry loop, task ledger or task authority.
type MetadataControls struct {
	link     Link
	now      func() time.Time
	observer RoutingObserver
}

func NewMetadataControls(link Link, now func() time.Time, observer RoutingObserver) (*MetadataControls, error) {
	if link == nil || now == nil || observer == nil {
		return nil, domain.ErrInvalid
	}
	return &MetadataControls{link: link, now: now, observer: observer}, nil
}

// ObserveAuthorizationFailure covers a denial before any route/intent exists.
// It discloses no requested destination and ignores mixed operational faults.
// Later routed denials are recorded by Exchange instead.
func (m *MetadataControls) ObserveAuthorizationFailure(actor domain.Actor, operation protocol.Operation, err error) {
	observeClassAuthorizationFailure(m.observer, actor, routing.ControlClass(operation), err)
}

func (m *MetadataControls) Exchange(ctx context.Context, call MetadataCall) (reply protocol.Reply, tx domain.Transmission, result error) {
	if ctx == nil || !call.valid() {
		return reply, tx, domain.ErrInvalid
	}
	attempt := newRoutingAttempt(m.observer, call.Actor, routing.ControlClass(call.Command.Operation))
	defer func() { attempt.finish(result) }()
	if result = call.Authorize(ctx); result != nil {
		attempt.authorize(result)
		return
	}
	attempt.authorize(nil)
	attempt.value.Destination = domain.Destination{Device: call.Device, Project: domain.ProjectAlias(call.Command.Project)}
	attempt.value.RootOnly = call.Command.Root != ""
	attempt.value.Operation = call.Operation
	snapshot, err := m.link.Snapshot(call.Device)
	if err != nil {
		return reply, tx, err
	}
	if snapshot.WireVersion != protocol.WireVersion2 {
		return reply, tx, &RemoteError{Failure: protocol.Failure{Code: "incompatible_delegate"}}
	}
	reservation, err := m.link.Reserve(ctx, call.Device, call.Operation, call.Command)
	if err != nil {
		return reply, tx, err
	}
	attempt.reservation = reservation
	defer releaseReservation(ctx, reservation, &result)
	return m.exchangeReserved(ctx, call, reservation, attempt)
}

func (m *MetadataControls) exchangeReserved(ctx context.Context, call MetadataCall, reservation Reservation, attempt *routingAttempt) (reply protocol.Reply, tx domain.Transmission, result error) {
	tx = reservation.Transmission()
	if tx.Credential.Device != call.Device {
		return reply, tx, domain.Reject(domain.EvidenceInvalid)
	}
	check := func(checkCtx context.Context) error {
		current := tx
		current.Now = m.now()
		return call.Check(checkCtx, current)
	}
	if result = check(ctx); result != nil {
		return
	}
	if result = m.acquire(ctx, call, reservation, attempt, tx); result != nil {
		return
	}
	if result = reservation.Publish(ctx, func(writeCtx context.Context) error { return attempt.guard(func() error { return check(writeCtx) }) }); result != nil {
		return
	}
	reply, result = reservation.Await(ctx)
	if result != nil {
		return
	}
	if result = attempt.guard(func() error { return check(ctx) }); result != nil {
		return protocol.Reply{}, tx, result
	}
	if reply.ValidateVersion(protocol.WireVersion2) != nil || reply.Operation != call.Command.Operation {
		return protocol.Reply{}, tx, domain.Reject(domain.EvidenceInvalid)
	}
	if reply.Error != nil {
		attempt.replyValid = true
		return protocol.Reply{}, tx, &RemoteError{Failure: *reply.Error}
	}
	tx.Now = m.now()
	if result = call.Validate(reply, tx); result != nil {
		return protocol.Reply{}, tx, result
	}
	attempt.replyValid = true
	return reply, tx, nil
}

func (m *MetadataControls) acquire(ctx context.Context, call MetadataCall, reservation Reservation, attempt *routingAttempt, tx domain.Transmission) error {
	request, err := reservation.Routing()
	if err != nil {
		return err
	}
	request.Now = m.now()
	attempt.route(tx, request)
	if err = call.Acquire(ctx, request); err != nil {
		return err
	}
	return reservation.ArmRouting(request)
}

// TargetedProjectObservation is dated peer metadata tied to the exact current
// credential and connection. It carries no authoritative task outcome.
type TargetedProjectObservation struct {
	Capability protocol.ProjectCapabilityV2
	Credential domain.CredentialRef
	Connection domain.ConnectionGeneration
	ObservedAt time.Time
}

type TargetedCapabilities interface {
	InspectProject(context.Context, domain.Actor, domain.Destination, domain.Scope) (TargetedProjectObservation, error)
}
