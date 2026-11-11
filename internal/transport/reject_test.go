package transport

import (
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestRejectSaturationNeverClaimsControl(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	r, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	failure := protocol.Failure{Code: "resource_limit", Retryable: true}
	if rejectErr := received.Reject(t.Context(), failure); rejectErr != nil {
		t.Fatal(rejectErr)
	}
	response, err := r.Await(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var reply protocol.Reply
	if decodeErr := protocol.DecodeStrict(response.Payload, &reply, protocol.MaxFrameBytes); decodeErr != nil || reply.Error == nil || reply.Error.Code != "resource_limit" {
		t.Fatal("saturation did not return typed refusal")
	}
	requireError(t, received.Reject(t.Context(), failure), ErrConflict)
	_, err = received.Claim(t.Context())
	requireError(t, err, ErrOffline)
	received.session.mu.Lock()
	claimed := received.claimed
	received.session.mu.Unlock()
	if claimed {
		t.Fatal("rejection accepted a CLI control")
	}
}

func TestRejectExpiredControlDoesNotSendRefusal(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	r, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(31 * time.Second)
	requireError(t, received.Reject(t.Context(), protocol.Failure{Code: "resource_limit", Retryable: true}), ErrExpired)
	received.session.mu.Lock()
	released, claimed, replied := received.released, received.claimed, received.replied
	received.session.mu.Unlock()
	if !released || claimed || replied {
		t.Fatal("expired refusal claimed or replied to a stale control")
	}
	requireError(t, r.Release(), ErrConflict)
}
