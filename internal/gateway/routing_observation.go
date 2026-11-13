package gateway

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// RoutingObserver receives dated metadata only. It cannot authorize, mutate a
// correlation, settle a permit or change an execution/result decision.
type RoutingObserver interface{ ObserveRouting(RoutingObservation) }

type RoutingObserverFunc func(RoutingObservation)

func (f RoutingObserverFunc) ObserveRouting(value RoutingObservation) { f(value) }

type RoutingObservation struct {
	Principal      domain.PrincipalID
	Destination    domain.Destination
	Operation      domain.OperationID
	Control        routing.ControlMetadata
	Prepared       bool
	ResourceDenied bool
	Failed         bool
}

// routingAttempt belongs to one service invocation. Only the queued guard can
// outlive that invocation, so its decision is the sole concurrently written
// field. No metadata recording occurs inside a guard or transport/store lock.
type routingAttempt struct {
	observer    RoutingObserver
	started     time.Time
	value       RoutingObservation
	reservation Reservation
	recheck     atomic.Uint32
	replyValid  bool
	finished    bool
}

func (s *Service) startObservation(actor domain.Actor, class routing.ControlClass) *routingAttempt {
	principal := actor.Principal
	if domain.Token(string(principal)) != nil {
		principal = ""
	}
	return &routingAttempt{observer: s.observer, started: time.Now(), value: RoutingObservation{Principal: principal, Control: routing.ControlMetadata{Class: class, Actor: routing.PrincipalActor, Authorization: routing.NotEvaluated, Recheck: routing.NotEvaluated, Transport: routing.NotAttempted, TransferSnapshot: routing.TransferSnapshot{WriteState: routing.WriteNotStarted}}}}
}

func (a *routingAttempt) authorize(err error) {
	a.value.Control.Authorization = AuthorizationObservation(err)
}

func (a *routingAttempt) bind(c domain.Correlation) {
	a.value.Destination = c.Destination
	a.value.Operation = c.Operation
}

func (a *routingAttempt) route(tx domain.Transmission, request routing.Request) {
	a.value.Control.Connection = tx.Connection
	a.value.Control.Request = domain.RequestID(request.Call.RequestID)
}

// AuthorizationObservation preserves concealed absence and mixed-fault
// uncertainty. It does not inspect arbitrary wrapped/native error messages.
func AuthorizationObservation(err error) routing.AuthorizationDecision {
	if err == nil {
		return routing.Allowed
	}
	cause := SoleError(err)
	var policy *domain.Error
	if errors.As(cause, &policy) && policy != nil && (policy.Code == domain.Forbidden || policy.Code == domain.NotFound) {
		return routing.DeniedOrMissing
	}
	return routing.DecisionUnknown
}

// SoleError returns a sole leaf without changing the original error graph.
// Ambiguous joins, ordinary wrappers and leaves with custom As return nil.
func SoleError(err error) error {
	// errors.Join with one non-nil cause is transparent; two causes retain
	// operational uncertainty even if one is a policy or capacity rejection.
	for {
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok {
			// Ordinary wrappers and custom As implementations cannot establish
			// that a policy error is the only operational meaning of a failure.
			_, wrapped := err.(interface{ Unwrap() error })
			_, customAs := err.(interface{ As(any) bool })
			if wrapped || customAs {
				return nil
			}
			return err
		}
		causes := joined.Unwrap()
		if len(causes) != 1 {
			return nil
		}
		err = causes[0]
	}
}

func (a *routingAttempt) guard(check func() error) error {
	err := check()
	decision := AuthorizationObservation(err)
	value := uint32(3)
	switch decision {
	case routing.Allowed:
		value = 1
	case routing.DeniedOrMissing:
		value = 2
	case routing.NotEvaluated, routing.DecisionUnknown:
	}
	a.recheck.Store(value)
	return err
}

func observedRecheck(value uint32) routing.AuthorizationDecision {
	switch value {
	case 0:
		return routing.NotEvaluated
	case 1:
		return routing.Allowed
	case 2:
		return routing.DeniedOrMissing
	default:
		return routing.DecisionUnknown
	}
}

func (a *routingAttempt) finish(err error) {
	if a.finished {
		return
	}
	// Only the caller finalizes. A fence can finish before a subsequent cancel;
	// its deferred cleanup cannot emit or relabel the same observation again.
	a.finished = true
	a.value.Control.Recheck = observedRecheck(a.recheck.Load())
	if a.reservation != nil {
		a.value.Control.TransferSnapshot = a.reservation.TransferSnapshot()
		a.value.Control.Transport = TransportObservation(a.value.Control.TransferSnapshot, a.replyValid)
	}
	if a.value.Control.Authorization == routing.DeniedOrMissing || a.value.Control.Recheck == routing.DeniedOrMissing {
		a.value.Destination = domain.Destination{}
		a.value.Operation = ""
	}
	a.value.ResourceDenied = ResourceDeniedObservation(err)
	a.value.Failed = err != nil
	a.value.Control.DurationNS = time.Since(a.started).Nanoseconds()
	a.observer.ObserveRouting(a.value)
}

func ResourceDeniedObservation(err error) bool {
	cause := SoleError(err)
	var policy *domain.Error
	if errors.As(cause, &policy) && policy != nil {
		return policy.Code == domain.ResourceLimit
	}
	var remote *RemoteError
	return errors.As(cause, &remote) && remote != nil && remote.Failure.Code == "resource_limit"
}

func TransportObservation(snapshot routing.TransferSnapshot, validReply bool) routing.TransportOutcome {
	switch snapshot.WriteState {
	case routing.WriteNotStarted:
		return routing.NotSent
	case routing.WriteAttemptedUnknown:
		return routing.WriteUnknown
	case routing.WriteCompleted:
		if snapshot.ResponseKnown {
			if validReply {
				return routing.ReplyReceived
			}
			return routing.ReplyInvalid
		}
		return routing.WrittenNoReply
	default:
		return routing.WriteUnknown
	}
}

func (s *Service) observeAuthorizationFailure(actor domain.Actor, operation protocol.Operation, err error) {
	s.observeClassAuthorizationFailure(actor, routing.ControlClass(operation), err)
}

func (s *Service) observeClassAuthorizationFailure(actor domain.Actor, class routing.ControlClass, err error) {
	if AuthorizationObservation(err) == routing.DeniedOrMissing {
		attempt := s.startObservation(actor, class)
		attempt.authorize(err)
		attempt.finish(err)
	}
}
