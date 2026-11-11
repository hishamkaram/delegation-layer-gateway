// Package recovery coordinates explicit administrative namespace recovery.
// Registry owns durable progress; Delegate owns namespace and task evidence.
package recovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
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
	store  exchangeStore
	link   gateway.Link
	now    func() time.Time
	random io.Reader
}

// exchange is private: each typed administrative operation supplies its own
// durable-state guard. It never accepts a caller-supplied arbitrary wire body.
func (c *client) exchange(ctx context.Context, destination domain.Destination, command protocol.Command, guard func(context.Context, domain.Transmission) error) (reply protocol.Reply, transmission domain.Transmission, result error) {
	if destination.Validate() != nil || command.Project != string(destination.Project) || guard == nil {
		return reply, transmission, domain.ErrInvalid
	}
	if result = c.store.AuthorizeAdministrative(ctx); result != nil {
		return
	}
	var entropy [16]byte
	if _, result = io.ReadFull(c.random, entropy[:]); result != nil {
		return reply, transmission, errors.New("recovery control entropy unavailable")
	}
	return c.exchangeWithOperation(ctx, destination, domain.OperationID(hex.EncodeToString(entropy[:])), command, guard)
}

// Task controls retain the operation from Delegate's immutable native binding.
// Transport separately allocates a fresh request identity for each control.
func (c *client) exchangeWithOperation(ctx context.Context, destination domain.Destination, operation domain.OperationID, command protocol.Command, guard func(context.Context, domain.Transmission) error) (reply protocol.Reply, transmission domain.Transmission, result error) {
	if destination.Validate() != nil || command.Project != string(destination.Project) || guard == nil || domain.RoutingToken(string(operation)) != nil {
		return reply, transmission, domain.ErrInvalid
	}
	if result = c.store.AuthorizeAdministrative(ctx); result != nil {
		return
	}
	reservation, err := c.link.Reserve(ctx, destination.Device, operation, command)
	if err != nil {
		return reply, transmission, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		result = errors.Join(result, reservation.Release(cleanup))
	}()
	transmission = reservation.Transmission()
	if transmission.Credential.Device != destination.Device {
		return reply, transmission, domain.Reject(domain.EvidenceInvalid)
	}
	check := func(call context.Context) error { return c.check(call, transmission, guard) }
	if result = check(ctx); result != nil {
		return
	}
	if result = c.arm(ctx, reservation); result != nil {
		return
	}
	if result = reservation.Publish(ctx, check); result != nil {
		return
	}
	reply, result = reservation.Await(ctx)
	if result != nil {
		return
	}
	if result = check(ctx); result != nil {
		return protocol.Reply{}, transmission, result
	}
	result = checkedReply(reply, command.Operation)
	if result != nil {
		return protocol.Reply{}, transmission, result
	}
	return
}

func checkedReply(reply protocol.Reply, operation protocol.Operation) error {
	if reply.Operation != operation || reply.Validate() != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if reply.Error != nil {
		return &gateway.RemoteError{Failure: *reply.Error}
	}
	return nil
}

func defaultClient(store exchangeStore, link gateway.Link, now func() time.Time) *client {
	return &client{store: store, link: link, now: now, random: rand.Reader}
}

func (c *client) check(ctx context.Context, tx domain.Transmission, guard func(context.Context, domain.Transmission) error) error {
	if err := c.store.AuthorizeAdministrative(ctx); err != nil {
		return err
	}
	now := c.now()
	if _, err := c.store.CheckConnection(ctx, tx.Credential, tx.Connection, now); err != nil {
		return err
	}
	tx.Now = now
	return guard(ctx, tx)
}

func (c *client) arm(ctx context.Context, reservation gateway.Reservation) error {
	route, err := reservation.Routing()
	if err != nil {
		return err
	}
	route.Now = c.now()
	if err = c.store.AcquireRouting(ctx, route); err != nil {
		return err
	}
	return reservation.ArmRouting(route)
}
