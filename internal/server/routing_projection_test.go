package server

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func TestReceivedReplyDoesNotHideFailedFinalization(t *testing.T) {
	value := gateway.RoutingObservation{Principal: "principal", Destination: domain.Destination{Device: "device", Project: "project"}, Operation: "operation", Control: routing.ControlMetadata{Class: routing.ControlClass(protocol.Status), Actor: routing.PrincipalActor, Authorization: routing.Allowed, Recheck: routing.Allowed, Transport: routing.ReplyReceived, DurationNS: 1, TransferSnapshot: routing.TransferSnapshot{WriteState: routing.WriteCompleted, EncodedRequestFrameBytes: 100, EncodedResponseFrameBytes: 200, ResponseKnown: true}}}
	if event := routingEvent(value); event.Code != observability.ControlCompleted {
		t.Fatalf("clean response observation: %+v", event)
	}
	// A binding, storage or release fault occurs after a valid transport reply.
	// Preserve both observations instead of reporting clean control completion.
	value.Failed = true
	event := routingEvent(value)
	if event.Code != observability.ControlUnknown || event.Control != value.Control || event.Operation != value.Operation {
		t.Fatalf("finalization failure erased by transport success: %+v", event)
	}
}

func TestSuccessfulUnpublishedRetryIsACompletedLocalObservation(t *testing.T) {
	value := gateway.RoutingObservation{Principal: "principal", Control: routing.ControlMetadata{Class: routing.ControlClass(protocol.Admit), Actor: routing.PrincipalActor, Authorization: routing.Allowed, Recheck: routing.NotEvaluated, Transport: routing.NotSent, TransferSnapshot: routing.TransferSnapshot{WriteState: routing.WriteNotStarted, EncodedRequestFrameBytes: 100}}}
	event := routingEvent(value)
	if event.Code != observability.ControlCompleted || event.Control.Transport != routing.NotSent || event.Control.ResponseKnown {
		t.Fatalf("no-send success acquired false failure or delivery: %+v", event)
	}
}
