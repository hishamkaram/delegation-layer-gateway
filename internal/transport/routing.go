package transport

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// RoutingAuthority is the durable Gateway owner. Callback execution is bounded
// and synchronous outside transport locks; failures never release permits.
type RoutingAuthority interface {
	ReconcileRouting(context.Context, domain.CredentialRef, protocol.ControlInventory, time.Time) (routing.Readiness, error)
	CompleteRouting(context.Context, domain.CredentialRef, domain.ConnectionGeneration, protocol.ControlCompletion, time.Time) error
	ReleaseUnpublishedRouting(context.Context, routing.Request) error
}

// ConnectorRouting owns the fenced local CLI census across socket generations.
type ConnectorRouting interface {
	Inventory(context.Context, domain.ConnectionGeneration) (protocol.ControlInventory, error)
	Acknowledge(context.Context, protocol.ControlInventoryAck) error
}

func controlCall(frame protocol.Frame, operation protocol.Operation) protocol.ControlCall {
	hash := domain.Hash(frame.Payload)
	return protocol.ControlCall{Generation: frame.Generation, RequestID: frame.RequestID, OperationID: frame.OperationID, Operation: operation, RequestSHA256: hex.EncodeToString(hash[:])}
}

func (h *Hub) routingHandshake(ctx context.Context, s *session) error {
	frame, readErr := s.readHandshake(ctx)
	if readErr != nil {
		return readErr
	}
	var inventory protocol.ControlInventory
	if frame.Type != protocol.RoutingInventory || frame.RequestID != "routing" || frame.OperationID != "" || protocol.DecodeStrict(frame.Payload, &inventory, MaxProtectedFrameBytes) != nil || inventory.Validate() != nil || inventory.Generation != wireGeneration(s.generation) {
		return fail(ErrProtocol, nil)
	}
	status, reconcileErr := s.routing.ReconcileRouting(ctx, s.ref, inventory, s.now())
	if reconcileErr != nil {
		return fail(ErrForbidden, reconcileErr)
	}
	ack := protocol.ControlInventoryAck{CredentialMode: string(s.mode), PolicyVersion: protocol.RoutingPolicyVersion, ProcessBoot: inventory.ProcessBoot, BarrierID: inventory.BarrierID, Generation: inventory.Generation, Ready: status.Ready, Reason: string(status.Reason)}
	if ack.Validate() != nil {
		return fail(ErrProtocol, nil)
	}
	encoded, encodeErr := protocol.Encode(ack, MaxProtectedFrameBytes)
	if encodeErr != nil {
		return fail(ErrProtocol, encodeErr)
	}
	s.mu.Lock()
	s.processBoot = inventory.ProcessBoot
	s.routingReady = ack.Ready
	s.routingAck = ack
	s.mu.Unlock()
	return s.writeHandshake(ctx, protocol.Frame{Version: protocol.Version, Type: protocol.RoutingInventoryAck, RequestID: "routing", Generation: inventory.Generation, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: encoded})
}

func (c *Client) routingHandshake(ctx context.Context) error {
	s := c.session
	inventory, inventoryErr := c.routing.Inventory(ctx, s.generation)
	if inventoryErr != nil {
		return fail(ErrNotReady, inventoryErr)
	}
	if inventory.Validate() != nil || inventory.Generation != wireGeneration(s.generation) {
		return fail(ErrProtocol, nil)
	}
	encoded, encodeErr := protocol.Encode(inventory, MaxProtectedFrameBytes)
	if encodeErr != nil {
		return fail(ErrProtocol, encodeErr)
	}
	frame := protocol.Frame{Version: protocol.Version, Type: protocol.RoutingInventory, RequestID: "routing", Generation: inventory.Generation, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: encoded}
	if writeErr := s.writeHandshake(ctx, frame); writeErr != nil {
		return writeErr
	}
	ack, ackReadErr := s.readRoutingAck(ctx, inventory)
	if ackReadErr != nil {
		return ackReadErr
	}
	if ackErr := c.routing.Acknowledge(ctx, ack); ackErr != nil {
		return fail(ErrNotReady, ackErr)
	}
	s.mu.Lock()
	s.processBoot = ack.ProcessBoot
	s.routingReady = ack.Ready
	s.routingAck = ack
	s.mode = domain.CredentialMode(ack.CredentialMode)
	s.mu.Unlock()
	return nil
}

func (s *session) readRoutingAck(ctx context.Context, inventory protocol.ControlInventory) (protocol.ControlInventoryAck, error) {
	response, readErr := s.readHandshake(ctx)
	if readErr != nil {
		return protocol.ControlInventoryAck{}, readErr
	}
	var ack protocol.ControlInventoryAck
	if response.Type != protocol.RoutingInventoryAck || response.RequestID != "routing" || response.OperationID != "" || protocol.DecodeStrict(response.Payload, &ack, MaxProtectedFrameBytes) != nil || ack.Validate() != nil {
		return protocol.ControlInventoryAck{}, fail(ErrProtocol, nil)
	}
	if ack.ProcessBoot != inventory.ProcessBoot || ack.BarrierID != inventory.BarrierID || ack.Generation != inventory.Generation {
		return protocol.ControlInventoryAck{}, fail(ErrProtocol, nil)
	}
	return ack, nil
}

func (c *Client) ProcessBoot() string {
	s := c.session
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.processBoot
}

func (c *Client) RoutingReady() bool {
	s := c.session
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routingReady && s.mode == domain.Regular && !s.closing
}

func (c *Client) CredentialMode() domain.CredentialMode {
	s := c.session
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}
