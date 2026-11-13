package transport

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestOutboundAllocationLimitRotatesSessionWithUnpublishedCalls(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	original := gatewaySession(t, f)
	consumeOutboundAllocations(t, f, client)
	reservation, received := claimLastOutboundAllocation(t, f, client)
	binding := received.Metadata()
	unexpected, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if unexpected != nil {
		if releaseErr := unexpected.Release(); releaseErr != nil {
			t.Fatal(releaseErr)
		}
	}
	requireError(t, err, ErrOffline)
	if errors.Is(err, ErrCapacity) {
		t.Fatal("session exhaustion reported a resource quota")
	}
	waitSessionJoined(t, original)
	_, err = reservation.Await(t.Context())
	requireError(t, err, ErrOffline)
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	next := f.dial(t)
	if next.Generation() == binding.Connection {
		t.Fatal("reconnect reused the exhausted generation")
	}
	if received.Metadata() != binding {
		t.Fatal("claimed work lost its original authenticated binding")
	}
	protectedOperationRoundTrip(t, f, next, protocol.Status)
}

func waitSessionJoined(t *testing.T, s *session) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-s.done:
	case <-timer.C:
		t.Fatal("exhausted session did not join its owned workers")
	}
}

func TestOutboundLimitPreservesDurableClaimAcrossFencedReconnect(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	f.hub.mu.Lock()
	original := f.hub.sessions["device-one"]
	f.hub.mu.Unlock()
	original.mu.Lock()
	original.sequence = MaxSessionRequests - 1
	original.mu.Unlock()
	reservation := f.prepare(t, inspect(t))
	if publishErr := reservation.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, claimErr := received.Claim(t.Context()); claimErr != nil {
		t.Fatal(claimErr)
	}
	_, err = f.hub.Reserve(t.Context(), "device-one", inspect(t))
	requireError(t, err, ErrOffline)
	waitSessionJoined(t, original)
	if f.status(t, client.Generation()).Outstanding != 1 {
		t.Fatal("allocation exhaustion released a possibly sent durable permit")
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	active := newCensusPeer()
	active.active = []protocol.ControlCall{received.ControlCall()}
	next := f.dial(t, active)
	if next.Generation() == client.Generation() || f.status(t, next.Generation()).Outstanding != 1 {
		t.Fatal("new fenced generation lost the accepted old control")
	}
	if closeErr := next.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	joined := f.dial(t, newCensusPeer())
	if f.status(t, joined.Generation()).Outstanding != 0 {
		t.Fatal("fenced joined absence failed to reconcile the old control")
	}
}

func consumeOutboundAllocations(t *testing.T, f *fixture, client *Client) {
	t.Helper()
	for index := 0; index < MaxSessionRequests-1; index++ {
		if index%2 == 0 {
			reservation, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
			if err != nil {
				t.Fatal(err)
			}
			if releaseErr := reservation.Release(); releaseErr != nil {
				t.Fatal(releaseErr)
			}
		} else {
			protectedOperationRoundTrip(t, f, client, protocol.Status)
		}
	}
}

func claimLastOutboundAllocation(t *testing.T, f *fixture, client *Client) (*Reservation, *Received) {
	t.Helper()
	reservation, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if reservation.Frame().RequestID != "g:"+strconv.Itoa(MaxSessionRequests) {
		t.Fatal("last allocation did not reach the session limit")
	}
	if publishErr := reservation.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, claimErr := received.Claim(t.Context()); claimErr != nil {
		t.Fatal(claimErr)
	}
	return reservation, received
}

func TestCapabilityAllocationLimitRotatesClientSession(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	client.session.mu.Lock()
	client.session.sequence = MaxSessionRequests - 1
	client.session.mu.Unlock()
	report := protocol.CapabilityReport{ObservedAt: f.clock.now()}
	if err := client.ReportCapabilities(t.Context(), report); err != nil {
		t.Fatal(err)
	}
	err := client.ReportCapabilities(t.Context(), report)
	requireError(t, err, ErrOffline)
	waitSessionJoined(t, client.session)
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	next := f.dial(t)
	if next.Generation() == client.Generation() {
		t.Fatal("capability exhaustion reused the old generation")
	}
	if reportErr := next.ReportCapabilities(t.Context(), report); reportErr != nil {
		t.Fatal(reportErr)
	}
	protectedOperationRoundTrip(t, f, next, protocol.Status)
}
