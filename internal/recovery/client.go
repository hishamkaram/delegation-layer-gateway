// Package recovery coordinates explicit administrative namespace recovery.
// Registry owns durable progress; Delegate owns namespace and task evidence.
package recovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// exchangeStore has no task execution or result mutation capability.
type exchangeStore interface {
	AuthorizeAdministrative(context.Context) error
	CheckConnection(context.Context, domain.CredentialRef, domain.ConnectionGeneration, time.Time) (domain.Credential, error)
	AcquireRouting(context.Context, routing.Request) error
}

type client struct {
	observer gateway.RoutingObserver
	store    exchangeStore
	link     gateway.Link
	now      func() time.Time
	random   io.Reader
}

// exchange is private: each typed administrative operation supplies its own
// durable-state guard. It never accepts a caller-supplied arbitrary wire body.
func (c *client) exchange(ctx context.Context, destination domain.Destination, command protocol.Command, guard func(context.Context, domain.Transmission) error, accept func(protocol.Reply, domain.Transmission) error) (reply protocol.Reply, transmission domain.Transmission, result error) {
	if !validExchangeRequest(destination, command, guard, accept) {
		return reply, transmission, domain.ErrInvalid
	}
	if result = c.store.AuthorizeAdministrative(ctx); result != nil {
		c.observeAdminDenial(command.Operation, result)
		return
	}
	var entropy [16]byte
	if _, result = io.ReadFull(c.random, entropy[:]); result != nil {
		return reply, transmission, errors.New("recovery control entropy unavailable")
	}
	return c.exchangeWithOperation(ctx, destination, domain.OperationID(hex.EncodeToString(entropy[:])), command, guard, accept)
}

// Task controls retain the operation from Delegate's immutable native binding.
// Transport separately allocates a fresh request identity for each control.
func (c *client) exchangeWithOperation(ctx context.Context, destination domain.Destination, operation domain.OperationID, command protocol.Command, guard func(context.Context, domain.Transmission) error, accept func(protocol.Reply, domain.Transmission) error) (reply protocol.Reply, transmission domain.Transmission, result error) {
	started := time.Now()
	observation := gateway.RoutingObservation{Control: routing.ControlMetadata{Class: routing.ControlClass(command.Operation), Actor: routing.LocalAdminActor, Authorization: routing.NotEvaluated, Recheck: routing.NotEvaluated, Transport: routing.NotAttempted, TransferSnapshot: routing.TransferSnapshot{WriteState: routing.WriteNotStarted}}}
	var reservation gateway.Reservation
	var recheck atomic.Uint32
	validReply := false
	defer func() { c.finishObservation(observation, reservation, started, recheck.Load(), validReply, result) }()
	if !validExchangeRequest(destination, command, guard, accept) || domain.RoutingToken(string(operation)) != nil {
		return reply, transmission, domain.ErrInvalid
	}
	result = c.store.AuthorizeAdministrative(ctx)
	observation.Control.Authorization = gateway.AuthorizationObservation(result)
	if result != nil {
		return
	}
	observation.Destination, observation.Operation = destination, operation
	var err error
	reservation, err = c.link.Reserve(ctx, destination.Device, operation, command)
	if err != nil {
		return reply, transmission, err
	}
	released := false
	release := func() error {
		released = true
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return reservation.Release(cleanup)
	}
	defer func() {
		if !released {
			result = errors.Join(result, release())
		}
	}()
	transmission = reservation.Transmission()
	if transmission.Credential.Device != destination.Device {
		return reply, transmission, domain.Reject(domain.EvidenceInvalid)
	}
	check := func(call context.Context) error {
		return c.check(call, transmission, guard, nil)
	}
	if result = check(ctx); result != nil {
		return
	}
	if result = c.arm(ctx, reservation, &observation.Control); result != nil {
		return
	}
	if result = reservation.Publish(ctx, func(call context.Context) error {
		return c.check(call, transmission, guard, &recheck)
	}); result != nil {
		return
	}
	reply, result = reservation.Await(ctx)
	if result != nil {
		return
	}
	validReply = matchingReply(reply, command.Operation)
	if result = check(ctx); result != nil {
		c.observeAdminDenial(command.Operation, result)
		return protocol.Reply{}, transmission, result
	}
	result = checkedReply(reply, command.Operation)
	if result != nil {
		return protocol.Reply{}, transmission, result
	}
	// Preserve release-before-consumer ordering. The immediate typed consumer
	// owns reply validation/application; a later recovery phase is separate.
	if result = release(); result != nil {
		return
	}
	result = accept(reply, transmission)
	return
}

func validExchangeRequest(destination domain.Destination, command protocol.Command, guard func(context.Context, domain.Transmission) error, accept func(protocol.Reply, domain.Transmission) error) bool {
	return destination.Validate() == nil && command.Project == string(destination.Project) && guard != nil && accept != nil
}

func matchingReply(reply protocol.Reply, operation protocol.Operation) bool {
	return reply.Operation == operation && reply.Validate() == nil
}

func checkedReply(reply protocol.Reply, operation protocol.Operation) error {
	if !matchingReply(reply, operation) {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if reply.Error != nil {
		return &gateway.RemoteError{Failure: *reply.Error}
	}
	return nil
}

func defaultClient(store exchangeStore, link gateway.Link, now func() time.Time, observer gateway.RoutingObserver) *client {
	return &client{store: store, link: link, now: now, random: rand.Reader, observer: observer}
}

func (c *client) arm(ctx context.Context, reservation gateway.Reservation, metadata *routing.ControlMetadata) error {
	route, err := reservation.Routing()
	if err != nil {
		return err
	}
	metadata.Request = domain.RequestID(route.Call.RequestID)
	metadata.Connection = reservation.Transmission().Connection
	route.Now = c.now()
	if err = c.store.AcquireRouting(ctx, route); err != nil {
		return err
	}
	return reservation.ArmRouting(route)
}

func recoveryRecheck(value uint32) routing.AuthorizationDecision {
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

func (c *client) check(ctx context.Context, tx domain.Transmission, guard func(context.Context, domain.Transmission) error, decision *atomic.Uint32) error {
	err := c.store.AuthorizeAdministrative(ctx)
	value := uint32(3)
	switch gateway.AuthorizationObservation(err) {
	case routing.Allowed:
		value = 1
	case routing.DeniedOrMissing:
		value = 2
	case routing.NotEvaluated, routing.DecisionUnknown:
	}
	if decision != nil {
		decision.Store(value)
	}
	if err != nil {
		return err
	}
	now := c.now()
	if _, err = c.store.CheckConnection(ctx, tx.Credential, tx.Connection, now); err != nil {
		return err
	}
	tx.Now = now
	return guard(ctx, tx)
}

func (c *client) observeAdminDenial(operation protocol.Operation, err error) {
	if gateway.AuthorizationObservation(err) != routing.DeniedOrMissing {
		return
	}
	c.observer.ObserveRouting(gateway.RoutingObservation{Failed: true, Control: routing.ControlMetadata{Class: routing.ControlClass(operation), Actor: routing.LocalAdminActor, Authorization: routing.DeniedOrMissing, Recheck: routing.NotEvaluated, Transport: routing.NotAttempted, TransferSnapshot: routing.TransferSnapshot{WriteState: routing.WriteNotStarted}}})
}

func (c *client) finishObservation(observation gateway.RoutingObservation, reservation gateway.Reservation, started time.Time, recheck uint32, validReply bool, result error) {
	observation.Control.Recheck = recoveryRecheck(recheck)
	if reservation != nil {
		observation.Control.TransferSnapshot = reservation.TransferSnapshot()
		observation.Control.Transport = gateway.TransportObservation(observation.Control.TransferSnapshot, validReply)
	}
	observation.Control.DurationNS = time.Since(started).Nanoseconds()
	observation.Failed = result != nil
	observation.ResourceDenied = gateway.ResourceDeniedObservation(result)
	c.observer.ObserveRouting(observation)
}
