package transport

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// forwardedWriteGate owns one test-controlled return boundary below TLS. Bytes
// reach the real peer before Write is held; only the test releases this gate.
type forwardedWriteGate struct {
	net.Conn
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	// The test sets failure while Write is held, before releasing that gate.
	failure error
}

func (g *forwardedWriteGate) Write(data []byte) (int, error) {
	n, err := g.Conn.Write(data)
	if err == nil && g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
		if g.failure != nil {
			return n, g.failure
		}
	}
	return n, err
}

func (g *forwardedWriteGate) unblock() { g.once.Do(func() { close(g.release) }) }

type heldResponse struct {
	fixture       *fixture
	client        *Client
	reservation   *Reservation
	gate          *forwardedWriteGate
	cancelPublish context.CancelFunc
}

func newHeldResponse(t *testing.T) *heldResponse {
	t.Helper()
	return newHeldResponseWithReply(t, replyRenewalForJoin)
}

func newHeldResponseWithReply(t *testing.T, reply func(*testing.T, *heldResponse, *Received, context.Context)) *heldResponse {
	t.Helper()
	// testing.Context cancels before cleanups; this explicit test-owned lifetime
	// must instead end after its socket/write owners have actually joined.
	publish, cancelPublish := context.WithCancel(context.WithoutCancel(t.Context()))
	// Register first: failure cleanup must release the gate and join the write,
	// client, and hub before cancelling the original publish authority.
	t.Cleanup(cancelPublish)
	f := newFixture(t, Settings{HeartbeatInterval: time.Hour, OfflineTimeout: 2 * time.Hour})
	base, ok := f.http.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected fixture HTTP transport")
	}
	owned := base.Clone()
	t.Cleanup(owned.CloseIdleConnections)
	var connection atomic.Pointer[forwardedWriteGate]
	owned.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := base.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		gate := &forwardedWriteGate{Conn: conn, entered: make(chan struct{}), release: make(chan struct{})}
		connection.Store(gate)
		return gate, nil
	}
	f.http = &http.Client{Transport: owned}
	client := f.dial(t)
	gate := connection.Load()
	if gate == nil {
		t.Fatal("fixture did not acquire a real TCP connection")
	}
	held := &heldResponse{fixture: f, client: client, gate: gate, cancelPublish: cancelPublish}
	t.Cleanup(func() { held.cleanup(t) })

	// The handshake is complete; fixture heartbeats are delayed one hour.
	// This gate assumes the next raw Write delivers the complete small control.
	// The peer-receipt watchdog below fails if that assumption does not hold.
	gate.armed.Store(true)
	reservation, err := client.Reserve(publish, renewalFrame(t))
	if err != nil {
		t.Fatal(err)
	}
	held.reservation = reservation
	if err = reservation.Publish(publish, nil); err != nil {
		t.Fatal(err)
	}
	watchdog, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-gate.entered:
	case <-watchdog.Done():
		t.Fatal("real socket write did not enter its post-forwarding gate")
	}
	received, err := f.hub.Receive(watchdog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = received.Claim(watchdog); err != nil {
		t.Fatal(err)
	}
	reply(t, held, received, watchdog)
	select {
	case <-reservation.done:
	case <-watchdog.Done():
		t.Fatal("real peer reply was not processed while original Write was held")
	}
	select {
	case <-reservation.job.done:
		t.Fatal("original writer escaped its held return boundary")
	default:
	}
	return held
}

func (h *heldResponse) cleanup(t *testing.T) {
	t.Helper()
	h.gate.unblock()
	if h.reservation == nil {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	if err := h.reservation.ReleaseUnused(cleanup); err != nil {
		t.Error("release unused gated reservation:", err)
	}
	select {
	case <-h.reservation.job.done:
	case <-cleanup.Done():
		t.Error("gated original writer did not join")
	}
}

func replyRenewalForJoin(t *testing.T, held *heldResponse, received *Received, ctx context.Context) {
	t.Helper()
	result := protocol.RenewalResult{DeviceID: "device-one", RenewalID: strings.Repeat("a", 32), Epoch: "epoch-one", Generation: 1, CertificateDERBase64: base64.StdEncoding.EncodeToString(held.fixture.certificate.Raw)}
	if err := received.ReplyRenewal(ctx, result); err != nil {
		t.Fatal(err)
	}
}

func TestAwaitResponseMustJoinOriginalWriteBeforeSuccess(t *testing.T) {
	held := newHeldResponse(t)
	assertHeldWriteObservationExpires(t, held)
	joinHeldWriteAndCheckBudget(t, held)
}

func assertHeldWriteObservationExpires(t *testing.T, held *heldResponse) {
	t.Helper()
	observer, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	// r.done is already closed. The original publish context stays live and the
	// real writer remains held throughout this separate observation lifetime.
	_, err := held.reservation.Await(observer)
	requireError(t, err, ErrExpired)
	select {
	case <-held.reservation.job.done:
		t.Fatal("observation cancellation released the original writer")
	default:
	}
	s := held.reservation.session
	s.mu.Lock()
	_, pending := s.pending[held.reservation.metadata.RequestID]
	_, writing := s.jobs[held.reservation.job]
	responseBytes, taken := held.reservation.responseBytes, held.reservation.taken
	s.mu.Unlock()
	if pending || !writing || responseBytes != 0 || !taken {
		t.Fatal("expired observation failed to release its response or retained no writer owner")
	}
}

func joinHeldWriteAndCheckBudget(t *testing.T, held *heldResponse) {
	t.Helper()
	held.gate.unblock()
	watchdog, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-held.reservation.job.done:
	case <-watchdog.Done():
		t.Fatal("released writer did not finish")
	}
	s := held.reservation.session
	s.mu.Lock()
	s.budget.mu.Lock()
	deviceBytes, globalBytes := s.bytes, s.budget.used
	s.budget.mu.Unlock()
	s.mu.Unlock()
	if deviceBytes != 0 || globalBytes != 0 {
		t.Fatal("joined write retained request or response byte accounting")
	}
}

func TestAwaitCompletedCapacityErrorMustJoinOriginalWrite(t *testing.T) {
	var releasePressure func()
	held := newHeldResponseWithReply(t, func(t *testing.T, held *heldResponse, received *Received, ctx context.Context) {
		t.Helper()
		s := held.reservation.session
		s.mu.Lock()
		pressure := DeviceQueueBytes - ProtectedDeviceBytes - s.bytes
		acquired := s.budget.acquire(s, pressure, ordinaryTraffic)
		s.mu.Unlock()
		if !acquired {
			t.Fatal("could not reserve response capacity pressure")
		}
		var once sync.Once
		releasePressure = func() {
			once.Do(func() {
				s.mu.Lock()
				s.budget.release(s, pressure)
				s.mu.Unlock()
			})
		}
		t.Cleanup(releasePressure)
		replyRenewalForJoin(t, held, received, ctx)
	})
	s := held.reservation.session
	s.mu.Lock()
	completedErr := held.reservation.err
	s.mu.Unlock()
	requireError(t, completedErr, ErrCapacity)
	assertHeldWriteObservationExpires(t, held)
	releasePressure()
	joinHeldWriteAndCheckBudget(t, held)
}

func TestAwaitCancellationDuringHeldWriteAllowsSessionShutdown(t *testing.T) {
	held := newHeldResponse(t)
	held.reservation.session.cancel()
	assertHeldWriteObservationExpires(t, held)
	joinHeldWriteAndCheckBudget(t, held)
	if err := held.client.Close(); err != nil {
		t.Fatal("cancelled session owners did not close:", err)
	}
}

func TestSessionTeardownDiscardsReplyBeforeAwait(t *testing.T) {
	held := newHeldResponse(t)
	s := held.reservation.session
	s.cancel()
	held.gate.unblock()
	waitClosed(t, s)
	select {
	case <-held.reservation.job.done:
	default:
		t.Fatal("session teardown finished before its originating writer joined")
	}
	observer, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	frame, err := held.reservation.Await(observer)
	requireError(t, err, ErrOffline)
	if !reflect.DeepEqual(frame, protocol.Frame{}) {
		t.Fatal("session teardown delivered a retained reply")
	}
}

func TestJoinedWriteAllowsCallerCancelAndNextControlOnSameSession(t *testing.T) {
	held := newHeldResponse(t)
	generation := held.client.Generation()
	held.gate.unblock()
	watchdog, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-held.reservation.job.done:
	case <-watchdog.Done():
		t.Fatal("released original writer did not join")
	}
	if _, err := held.reservation.Await(watchdog); err != nil {
		t.Fatal(err)
	}
	held.cancelPublish()
	second, err := held.client.Reserve(watchdog, renewalFrame(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = second.Publish(watchdog, nil); err != nil {
		t.Fatal(err)
	}
	received, err := held.fixture.hub.Receive(watchdog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = received.Claim(watchdog); err != nil {
		t.Fatal(err)
	}
	replyRenewalForJoin(t, held, received, watchdog)
	if _, err = second.Await(watchdog); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.job.done:
	case <-watchdog.Done():
		t.Fatal("second control writer did not join")
	}
	if second.Frame().Connection != generation || held.client.Generation() != generation {
		t.Fatal("next control changed the authenticated session generation")
	}
}
