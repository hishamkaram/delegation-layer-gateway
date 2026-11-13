package transport

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type handshakeGatedPeer struct {
	*censusPeer
	acknowledged chan struct{}
	release      <-chan struct{}
}

func (p handshakeGatedPeer) Acknowledge(ctx context.Context, ack protocol.ControlInventoryAck) error {
	if err := p.censusPeer.Acknowledge(ctx, ack); err != nil {
		return err
	}
	close(p.acknowledged)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.release:
		return nil
	}
}

func TestSnapshotOnlineWaitsForCompleteWireHandshake(t *testing.T) {
	f := newRoutedFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandshake := func() { releaseOnce.Do(func() { close(release) }) }
	peer := handshakeGatedPeer{censusPeer: newCensusPeer(), acknowledged: make(chan struct{}), release: release}
	var client *Client
	var dialErr error
	dialDone := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		releaseHandshake()
		<-dialDone
		if client != nil {
			if closeErr := client.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
	})
	go func() {
		defer close(dialDone)
		client, dialErr = Dial(ctx, ClientConfig{
			URL:         "wss" + strings.TrimPrefix(f.server.URL, "https"),
			GatewayID:   f.gateway,
			Certificate: f.certificate,
			Capabilities: protocol.CapabilityReport{
				ObservedAt: f.clock.now(),
				Projects:   []protocol.ProjectCapability{{Alias: "project-one", Ready: false}},
			},
			Routing: peer,
		}, f.http, f.clock.now)
	}()
	select {
	case <-peer.acknowledged:
	case <-dialDone:
		t.Fatalf("dial ended before routing ACK gate: %v", dialErr)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	assertHandshakeUnavailable(t, ctx, f)

	releaseHandshake()
	select {
	case <-dialDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	if readyErr := f.hub.WaitReady(ctx, "device-one"); readyErr != nil {
		t.Fatal(readyErr)
	}
	assertHandshakeAvailable(t, ctx, f)
}

func assertHandshakeUnavailable(t *testing.T, ctx context.Context, f *routedFixture) {
	t.Helper()
	// The real hello and routing exchange finished, but the peer cannot send
	// capabilities until this gate opens. The session is registered, not usable.
	before, snapshotErr := f.hub.Snapshot("device-one")
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	if before.Online {
		t.Fatal("incomplete wire handshake advertised online")
	}
	if before.RoutingReady {
		t.Fatal("incomplete wire handshake advertised routing ready")
	}
	reservation, reserveErr := f.hub.Reserve(ctx, "device-one", inspect(t))
	if reservation != nil {
		if releaseErr := reservation.ReleaseUnused(ctx); releaseErr != nil {
			t.Error(releaseErr)
		}
		t.Fatal("incomplete wire handshake accepted a reservation")
	}
	requireError(t, reserveErr, ErrOffline)
}

func assertHandshakeAvailable(t *testing.T, ctx context.Context, f *routedFixture) {
	t.Helper()
	after, snapshotErr := f.hub.Snapshot("device-one")
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	if !after.Online || !after.RoutingReady {
		t.Fatal("complete wire handshake did not advertise online routing session")
	}
	if len(after.Capabilities.Projects) != 1 || after.Capabilities.Projects[0].Ready {
		t.Fatal("wire online state changed the reported execution readiness")
	}
	reservation, reserveErr := f.hub.Reserve(ctx, "device-one", inspect(t))
	if reserveErr != nil {
		t.Fatal(reserveErr)
	}
	if releaseErr := reservation.ReleaseUnused(ctx); releaseErr != nil {
		t.Fatal(releaseErr)
	}
}

func TestSnapshotClosingReadySessionIsOffline(t *testing.T) {
	// Keep the stopped session registered to cover the interval before retirement.
	s := newSession(t.Context(), Settings{}, time.Now, &budget{}, make(chan *Received))
	t.Cleanup(s.cancel)
	s.mode = domain.Regular
	s.routingReady = true
	close(s.ready)
	s.stop(fail(ErrOffline, nil))
	hub := &Server{sessions: map[domain.DeviceID]*session{"device-one": s}}
	snapshot, err := hub.Snapshot("device-one")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Online || snapshot.RoutingReady {
		t.Fatal("closing session advertised online or routing ready")
	}
}
