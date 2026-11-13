// Package wirelink adapts the strict authenticated transport to application
// ports. It owns no task state, execution, retry policy or persistent authority.
package wirelink

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

type Hub interface {
	Snapshot(domain.DeviceID) (transport.Snapshot, error)
	Reserve(context.Context, domain.DeviceID, protocol.Frame) (*transport.Reservation, error)
}
type Link struct{ hub Hub }

func New(hub Hub) (*Link, error) {
	if hub == nil {
		return nil, domain.ErrInvalid
	}
	return &Link{hub: hub}, nil
}

func (l *Link) Snapshot(device domain.DeviceID) (gateway.LinkSnapshot, error) {
	snapshot, err := l.hub.Snapshot(device)
	if err != nil {
		return gateway.LinkSnapshot{}, publicError(err)
	}
	if !snapshot.Online {
		return gateway.LinkSnapshot{}, publicError(transport.ErrOffline)
	}
	capabilities := snapshot.Capabilities
	capabilities.Projects = append([]protocol.ProjectCapability(nil), capabilities.Projects...)
	// Online legacy/unreconciled sessions never advertise execution readiness.
	// Current rights are still independently checked in registry transactions.
	if !snapshot.RoutingReady || snapshot.ProcessBoot == "" {
		for i := range capabilities.Projects {
			capabilities.Projects[i].Ready = false
		}
	}
	return gateway.LinkSnapshot{ProcessBoot: snapshot.ProcessBoot, Credential: snapshot.Credential, Connection: snapshot.Generation, Capabilities: capabilities, ObservedAt: snapshot.CapabilitiesObservedAt}, nil
}

func (l *Link) Reserve(ctx context.Context, device domain.DeviceID, operation domain.OperationID, command protocol.Command) (gateway.Reservation, error) {
	payload, err := protocol.Encode(command, protocol.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	frame := protocol.Frame{Version: protocol.Version, Type: protocol.Request, OperationID: string(operation), TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload}
	reserved, err := l.hub.Reserve(ctx, device, frame)
	if err != nil {
		return nil, publicError(err)
	}
	return &reservation{wire: reserved}, nil
}

type reservation struct{ wire *transport.Reservation }

func (r *reservation) Transmission() domain.Transmission {
	meta := r.wire.Frame()
	return domain.Transmission{Operation: domain.OperationID(meta.OperationID), Credential: meta.Credential, Connection: meta.Connection, EncodedFrameBytes: meta.EncodedFrameBytes}
}

func (r *reservation) TransferSnapshot() routing.TransferSnapshot {
	value := r.wire.TransferSnapshot()
	state := routing.WriteAttemptedUnknown
	switch value.WriteState {
	case transport.WriteNotStarted:
		state = routing.WriteNotStarted
	case transport.WriteAttemptedUnknown:
		state = routing.WriteAttemptedUnknown
	case transport.WriteCompleted:
		state = routing.WriteCompleted
	}
	return routing.TransferSnapshot{WriteState: state, EncodedRequestFrameBytes: value.EncodedRequestFrameBytes, EncodedResponseFrameBytes: value.EncodedResponseFrameBytes, ResponseKnown: value.ResponseKnown}
}

func (r *reservation) Routing() (routing.Request, error) {
	request, err := r.wire.Routing()
	return request, publicError(err)
}

func (r *reservation) ArmRouting(request routing.Request) error {
	return publicError(r.wire.ArmRouting(request))
}

func (r *reservation) Publish(ctx context.Context, guard func(context.Context) error) error {
	if guard == nil {
		return domain.Reject(domain.Forbidden)
	}
	return publicError(r.wire.Publish(ctx, func(call context.Context, _ transport.Metadata) error { return guard(call) }))
}

func (r *reservation) Await(ctx context.Context) (protocol.Reply, error) {
	frame, err := r.wire.Await(ctx)
	if err != nil {
		return protocol.Reply{}, publicError(err)
	}
	var response protocol.ControlResponse
	if frame.Type != protocol.Response || protocol.DecodeStrict(frame.Payload, &response, protocol.MaxFrameBytes) != nil || response.Validate() != nil {
		return protocol.Reply{}, domain.Reject(domain.EvidenceInvalid)
	}
	return response.Reply, nil
}

func (r *reservation) Release(ctx context.Context) error {
	return publicError(r.wire.ReleaseUnused(ctx))
}

func publicError(err error) error {
	if err == nil {
		return nil
	}
	code := "protocol_error"
	retry := false
	switch {
	case errors.Is(err, transport.ErrOffline):
		code = "device_offline"
		retry = true
	case errors.Is(err, transport.ErrNotReady):
		code = "device_not_ready"
		retry = true
	case errors.Is(err, transport.ErrCapacity):
		code = "resource_limit"
		retry = true
	case errors.Is(err, transport.ErrExpired), errors.Is(err, context.DeadlineExceeded):
		code = "timeout"
		retry = true
	case errors.Is(err, transport.ErrForbidden):
		code = "forbidden"
	case errors.Is(err, transport.ErrConflict):
		code = "conflict"
	case errors.Is(err, context.Canceled):
		return context.Canceled
	}
	return &gateway.RemoteError{Failure: protocol.Failure{Code: code, Retryable: retry}}
}
