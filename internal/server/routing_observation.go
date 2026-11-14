package server

import (
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

// ObserveRouting maps only validated routing metadata to the existing sink.
// Recorder owns failures; recording cannot change any Gateway/Native outcome.
func (r *Runtime) ObserveRouting(value gateway.RoutingObservation) {
	r.recorder.Record(routingEvent(value))
}

func routingEvent(value gateway.RoutingObservation) observability.Event {
	code := observability.ControlUnknown
	switch {
	case value.Control.Authorization == routing.DeniedOrMissing || value.Control.Recheck == routing.DeniedOrMissing:
		code = observability.AuthorizationDenied
	case value.ResourceDenied:
		code = observability.ResourceDenied
	case value.Prepared:
		code = observability.OperationPrepared
	case !value.Failed && (value.Control.Transport == routing.ReplyReceived || value.Control.Authorization == routing.Allowed && (value.Control.Transport == routing.NotAttempted || value.Control.Transport == routing.NotSent)):
		code = observability.ControlCompleted
	}
	return observability.Event{Code: code, RootOnly: value.RootOnly, Principal: value.Principal, Device: value.Destination.Device, Project: value.Destination.Project, Operation: value.Operation, Control: value.Control}
}

func (r *Runtime) observeConnection(value transport.ConnectionObservation) {
	code := observability.DeviceConnectionFailed
	switch value.State {
	case transport.ConnectionEstablished:
		code = observability.DeviceConnected
	case transport.ConnectionClosed:
		code = observability.DeviceDisconnected
	case transport.ConnectionFailed:
		code = observability.DeviceConnectionFailed
	}
	r.recorder.Record(observability.Event{Code: code, Device: value.Credential.Device, Credential: observability.CredentialIdentity{DeviceID: value.Credential.Device, Epoch: value.Credential.Epoch, Generation: value.Credential.Generation}, Connection: value.Generation, ConnectionDurationNS: value.Duration.Nanoseconds()})
}

func (r *Runtime) observeHTTPRejection(reason httpguard.Rejection) {
	switch reason {
	case httpguard.OriginRejected:
		r.recorder.CountBoundaryRejection(observability.BoundaryOrigin)
	case httpguard.CapacityRejected:
		r.recorder.CountBoundaryRejection(observability.BoundaryCapacity)
	}
}
