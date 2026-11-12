package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestTransferSnapshotCountsActualFramesAfterAwait(t *testing.T) {
	f := newFixture(t, Settings{})
	conn, _ := f.raw(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r, err := f.hub.Reserve(ctx, "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if before := r.TransferSnapshot(); before.WriteState != WriteNotStarted || before.ResponseKnown || before.EncodedResponseFrameBytes != 0 {
		t.Fatal("reserved frame claimed an observed write or response")
	}
	if err = r.Publish(ctx, allowed); err != nil {
		t.Fatal(err)
	}
	_, requestBytes, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.DecodeFrame(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	reply := request
	reply.Type = protocol.Response
	reply.Payload = payload(t, protocol.Reply{Operation: protocol.ContextInspect, Body: payload(t, struct {
		OK bool `json:"ok"`
	}{true})})
	responseBytes, err := protocol.EncodeFrame(reply)
	if err != nil {
		t.Fatal(err)
	}
	// Valid insignificant whitespace makes raw received length differ from any
	// re-encoding of the decoded reply. It is part of this actual WSS message.
	responseBytes = append(append([]byte(" \n"), responseBytes...), '\n')
	if err = conn.Write(ctx, websocket.MessageText, responseBytes); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Await(ctx); err != nil {
		t.Fatal(err)
	}
	want := TransferSnapshot{WriteState: WriteCompleted, EncodedRequestFrameBytes: len(requestBytes), EncodedResponseFrameBytes: len(responseBytes), ResponseKnown: true}
	if got := r.TransferSnapshot(); got != want {
		t.Fatalf("frame measurements after response consumption: got %+v want %+v", got, want)
	}
	r.session.mu.Lock()
	retained := r.responseBytes != 0 || len(r.response.Payload) != 0
	r.session.mu.Unlock()
	if retained {
		t.Fatal("measurement retained the consumed response buffer")
	}
}

type queuedTransfer struct {
	client      *Client
	reservation *Reservation
	ctx         context.Context
	unblock     func()
}

func newQueuedTransfer(t *testing.T, denial error) queuedTransfer {
	t.Helper()
	f := newFixture(t, Settings{})
	client := f.dial(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	r, err := f.hub.Reserve(ctx, "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	guard := func(call context.Context, _ Metadata) error {
		close(entered)
		select {
		case <-release:
			return denial
		case <-call.Done():
			return call.Err()
		}
	}
	if err = r.Publish(ctx, guard); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("writer did not enter its pre-write guard")
	}
	return queuedTransfer{client: client, reservation: r, ctx: ctx, unblock: unblock}
}

func replyToQueuedTransfer(t *testing.T, held queuedTransfer) {
	t.Helper()
	held.unblock()
	received, err := held.client.Receive(held.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = received.Claim(held.ctx); err != nil {
		t.Fatal(err)
	}
	if err = received.Reply(held.ctx, protocol.Reply{Operation: protocol.ContextInspect, Body: payload(t, struct {
		OK bool `json:"ok"`
	}{true})}); err != nil {
		t.Fatal(err)
	}
}

func TestTransferSnapshotQueuedGuardCannotProveUnsent(t *testing.T) {
	held := newQueuedTransfer(t, nil)
	r := held.reservation
	r.session.mu.Lock()
	writeStarted := r.job.writeStarted
	r.session.mu.Unlock()
	if writeStarted {
		t.Fatal("physical write escaped its pre-write guard")
	}
	// The old test checked only the physical fact above. A published writer can
	// still progress later, so that fact cannot establish a definite unsent state.
	if got := r.TransferSnapshot(); got.WriteState != WriteAttemptedUnknown || got.ResponseKnown {
		t.Fatal("unsettled publication was classified as definitely unsent")
	}
	replyToQueuedTransfer(t, held)
	if _, err := r.Await(held.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTransferSnapshotCancelledQueuedObserverCannotProveUnsent(t *testing.T) {
	held := newQueuedTransfer(t, nil)
	observer, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := held.reservation.Await(observer)
	requireError(t, err, ErrExpired)
	before := held.reservation.TransferSnapshot()
	// The separate publication authority is still live. Prove an actual later
	// peer request/reply rather than treating cancellation as a writer join.
	replyToQueuedTransfer(t, held)
	for _, done := range []<-chan struct{}{held.reservation.job.done, held.reservation.done} {
		select {
		case <-done:
		case <-held.ctx.Done():
			t.Fatal("late original exchange did not settle")
		}
	}
	if before.WriteState != WriteAttemptedUnknown || before.ResponseKnown {
		t.Fatal("cancelled observer incorrectly proved the unsettled publication unsent despite an actual later exchange")
	}
	if got := held.reservation.TransferSnapshot(); got.WriteState != WriteCompleted || !got.ResponseKnown {
		t.Fatal("late original write/reply did not retain its qualified measurements")
	}
}

func TestTransferSnapshotSettledGuardDenialProvesUnsent(t *testing.T) {
	held := newQueuedTransfer(t, ErrForbidden)
	held.unblock()
	_, err := held.reservation.Await(held.ctx)
	requireError(t, err, ErrForbidden)
	if got := held.reservation.TransferSnapshot(); got.WriteState != WriteNotStarted || got.ResponseKnown || got.EncodedResponseFrameBytes != 0 {
		t.Fatal("settled pre-write denial did not retain definite unsent evidence")
	}
}

func TestTransferSnapshotReplyCannotCompleteHeldWriteOrDisappearOnAbandon(t *testing.T) {
	held := newHeldResponse(t)
	before := held.reservation.TransferSnapshot()
	if before.WriteState != WriteAttemptedUnknown || !before.ResponseKnown || before.EncodedResponseFrameBytes <= 0 {
		t.Fatal("peer reply was promoted to completion of the held original write")
	}
	assertHeldWriteObservationExpires(t, held)
	if after := held.reservation.TransferSnapshot(); after != before {
		t.Fatalf("abandoning response changed retained measurements: before %+v after %+v", before, after)
	}
	joinHeldWriteAndCheckBudget(t, held)
	after := held.reservation.TransferSnapshot()
	if after.WriteState != WriteCompleted || after.EncodedResponseFrameBytes != before.EncodedResponseFrameBytes || !after.ResponseKnown {
		t.Fatal("original writer join lost measurements or failed to settle local write")
	}
}

func TestTransferSnapshotFailedOriginalWriteRemainsUnknownDespiteReply(t *testing.T) {
	held := newHeldResponse(t)
	held.gate.failure = errors.New("controlled_socket_write_failure")
	held.gate.unblock()
	select {
	case <-held.reservation.job.done:
	case <-time.After(5 * time.Second):
		t.Fatal("failed original write did not join")
	}
	got := held.reservation.TransferSnapshot()
	if got.WriteState != WriteAttemptedUnknown || !got.ResponseKnown || got.EncodedResponseFrameBytes <= 0 {
		t.Fatal("a validated reply hid the failed original write or lost its size")
	}
}
