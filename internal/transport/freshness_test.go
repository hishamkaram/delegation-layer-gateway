package transport

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestTrafficDoesNotRefreshCapabilityObservation(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	before, err := f.hub.Snapshot("device-one")
	if err != nil || before.CapabilitiesObservedAt.IsZero() {
		t.Fatalf("missing capability receipt time: %v", err)
	}
	f.clock.advance(time.Second)
	reservation, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if releaseErr := reservation.Release(); releaseErr != nil && !errors.Is(releaseErr, ErrConflict) {
			t.Error(releaseErr)
		}
	}()
	if err = reservation.Publish(t.Context(), allowed); err != nil {
		t.Fatal(err)
	}
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = received.Claim(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = received.Reply(t.Context(), protocol.Reply{Operation: protocol.ContextInspect, Body: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err = reservation.Await(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := f.hub.Snapshot("device-one")
	if err != nil {
		t.Fatal(err)
	}
	if !after.LastSeen.After(before.LastSeen) {
		t.Fatal("response receipt not observed")
	}
	if !after.CapabilitiesObservedAt.Equal(before.CapabilitiesObservedAt) {
		t.Fatal("unrelated traffic falsely refreshed provider capabilities")
	}
}

func TestHandshakeDeadlineDoesNotOwnEstablishedSession(t *testing.T) {
	f := newFixture(t, Settings{HandshakeTimeout: time.Second})
	client := f.dial(t)
	timer := time.NewTimer(1100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("lifetime test canceled")
	}
	r, reserveErr := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if reserveErr != nil {
		t.Fatal("handshake expiry closed established session")
	}
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, receiveErr := client.Receive(t.Context())
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if _, claimErr := received.Claim(t.Context()); claimErr != nil {
		t.Fatal(claimErr)
	}
	if replyErr := received.Reply(t.Context(), protocol.Reply{Operation: protocol.ContextInspect, Body: json.RawMessage(`{}`)}); replyErr != nil {
		t.Fatal(replyErr)
	}
	if _, awaitErr := r.Await(t.Context()); awaitErr != nil {
		t.Fatal(awaitErr)
	}
}
