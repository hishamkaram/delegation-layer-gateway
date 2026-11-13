package transport

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func protectedControl(t *testing.T, op protocol.Operation) protocol.Frame {
	t.Helper()
	task := capacityTask()
	var body any = protocol.TaskControl{Task: task}
	if op == protocol.Cancel {
		body = protocol.Cancellation{Task: task, CancellationID: strings.Repeat("c", 32)}
	}
	f := inspect(t)
	f.Payload = payload(t, protocol.Command{Operation: op, Project: "project-one", Body: payload(t, body)})
	return f
}

func capacityTask() protocol.TaskBinding {
	return protocol.TaskBinding{TaskID: strings.Repeat("a", 32), Context: protocol.ContextBinding{Root: protocol.WireContextGuard("root"), Project: protocol.WireContextGuard("project")}, Origin: protocol.Origin{GatewayID: "gateway-one", AdmissionGeneration: "origin-one", OperationID: "operation-one", PrincipalRef: "principal-one", RequestSHA256: strings.Repeat("b", 64)}}
}

func TestAbandonedOrdinaryCorrelationsPreserveProtectedRequestAndReply(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	count := 0
	for count < QueueFrames+1 {
		if !abandonOrdinary(t, f, client) {
			break
		}
		count++
	}
	if count != QueueFrames-ProtectedFrames {
		t.Fatalf("ordinary correlations=%d", count)
	}
	for _, op := range []protocol.Operation{protocol.FenceAbsent, protocol.Cancel} {
		protectedOperationRoundTrip(t, f, client, op)
	}
	f.hub.mu.Lock()
	s := f.hub.sessions["device-one"]
	f.hub.mu.Unlock()
	s.mu.Lock()
	pending := len(s.pending)
	s.mu.Unlock()
	if pending != count {
		t.Fatal("Await cancellation freed unanswered ordinary correlation")
	}
}

func abandonOrdinary(t *testing.T, f *fixture, client *Client) bool {
	t.Helper()
	r, reserveErr := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if errors.Is(reserveErr, ErrCapacity) {
		return false
	}
	if reserveErr != nil {
		t.Fatal(reserveErr)
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
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, awaitErr := r.Await(ctx)
	requireError(t, awaitErr, ErrExpired)
	return true
}

func TestByteHeadroomPreservesTotalBounds(t *testing.T) {
	var b budget
	s := &session{}
	if !b.acquire(s, DeviceQueueBytes-ProtectedDeviceBytes, ordinaryTraffic) {
		t.Fatal("ordinary device limit unavailable")
	}
	if b.acquire(s, 1, ordinaryTraffic) {
		t.Fatal("ordinary acquired protected device headroom")
	}
	for range ProtectedDeviceBytes / MaxProtectedFrameBytes {
		if !b.acquire(s, MaxProtectedFrameBytes, protectedTraffic) {
			t.Fatal("protected device headroom unavailable")
		}
	}
	if b.acquire(s, 1, protectedTraffic) {
		t.Fatal("total device limit exceeded")
	}
	b.release(s, DeviceQueueBytes)
	if b.acquire(s, MaxProtectedFrameBytes+1, protectedTraffic) {
		t.Fatal("oversized protected frame acquired bytes")
	}
	var sessions []*session
	for remaining := GlobalQueueBytes - ProtectedGlobalBytes; remaining > 0; {
		current := &session{}
		sessions = append(sessions, current)
		size := min(remaining, DeviceQueueBytes-ProtectedDeviceBytes)
		if !b.acquire(current, size, ordinaryTraffic) {
			t.Fatal("ordinary global limit unavailable")
		}
		remaining -= size
	}
	if b.acquire(&session{}, 1, ordinaryTraffic) {
		t.Fatal("ordinary acquired protected global headroom")
	}
	protected := &session{}
	for range ProtectedGlobalBytes / MaxProtectedFrameBytes {
		if !b.acquire(protected, MaxProtectedFrameBytes, protectedTraffic) {
			t.Fatal("protected global headroom unavailable")
		}
	}
	if b.acquire(&session{}, 1, protectedTraffic) {
		t.Fatal("total global limit exceeded")
	}
	for _, current := range sessions {
		b.release(current, current.bytes)
	}
	b.release(protected, protected.bytes)
	if b.used != 0 {
		t.Fatal("byte reservations leaked")
	}
}

func admissionSized(t *testing.T, s *session, size int) protocol.Frame {
	t.Helper()
	makeFrame := func(brief string) protocol.Frame {
		task := capacityTask()
		admission := protocol.Admission{Task: task, Provider: "fixture", Permission: "read-only", BudgetSeconds: 1, Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}, Brief: brief}
		f := inspect(t)
		f.Payload = payload(t, protocol.Command{Operation: protocol.Admit, Project: "project-one", Body: payload(t, admission)})
		s.mu.Lock()
		f.RequestID = "g:" + strconv.FormatUint(s.sequence+1, 10)
		f.Generation = wireGeneration(s.generation)
		s.mu.Unlock()
		return f
	}
	one := makeFrame("x")
	encoded, err := protocol.EncodeFrame(one)
	if err != nil {
		t.Fatal(err)
	}
	length := 1 + size - len(encoded)
	if length < 1 || length > 256<<10 {
		t.Fatal("invalid sized admission fixture")
	}
	return makeFrame(strings.Repeat("x", length))
}

func gatewaySession(t *testing.T, f *fixture) *session {
	t.Helper()
	f.hub.mu.Lock()
	defer f.hub.mu.Unlock()
	s := f.hub.sessions["device-one"]
	if s == nil {
		t.Fatal("missing ready session")
	}
	return s
}

func protectedRoundTrip(t *testing.T, f *fixture, client *Client) {
	t.Helper()
	protectedOperationRoundTrip(t, f, client, protocol.Cancel)
}

func protectedOperationRoundTrip(t *testing.T, f *fixture, client *Client, op protocol.Operation) {
	t.Helper()
	r, err := f.hub.Reserve(t.Context(), "device-one", protectedControl(t, op))
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
	if _, claimErr := received.Claim(t.Context()); claimErr != nil {
		t.Fatal(claimErr)
	}
	if replyErr := received.Reply(t.Context(), protocol.Reply{Operation: op, Error: &protocol.Failure{Code: "pending", Retryable: true}}); replyErr != nil {
		t.Fatal(replyErr)
	}
	if _, awaitErr := r.Await(t.Context()); awaitErr != nil {
		t.Fatal(awaitErr)
	}
}

func TestOrdinaryInboundBytesLeaveProtectedRequestAndResponseRoom(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	s := gatewaySession(t, f)
	for remaining := DeviceQueueBytes - ProtectedDeviceBytes; remaining > 0; {
		size := min(200<<10, remaining)
		r, err := f.hub.Reserve(t.Context(), "device-one", admissionSized(t, s, size))
		if err != nil {
			t.Fatal(err)
		}
		if r.Frame().EncodedFrameBytes != size {
			t.Fatal("sized frame fixture mismatch")
		}
		if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
			t.Fatal(publishErr)
		}
		if _, receiveErr := client.Receive(t.Context()); receiveErr != nil {
			t.Fatal(receiveErr)
		} // retained unclaimed bytes
		remaining -= size
	}
	client.session.mu.Lock()
	used := client.session.bytes
	client.session.mu.Unlock()
	if used != DeviceQueueBytes-ProtectedDeviceBytes {
		t.Fatal("ordinary inbound byte limit not reached")
	}
	// At exactly the ordinary byte limit, this response requires inherited
	// protected class on send; a normal response allocation cannot fit.
	protectedRoundTrip(t, f, client)
}

func rangeFrame(t *testing.T) protocol.Frame {
	t.Helper()
	task := capacityTask()
	task.SpecSHA256 = strings.Repeat("d", 64)
	request := protocol.RangeRequest{Task: task, Descriptor: protocol.Descriptor{SHA256: strings.Repeat("e", 64), Length: 1 << 30}, Limit: 65536}
	f := inspect(t)
	f.Payload = payload(t, protocol.Command{Operation: protocol.ResultChunk, Project: "project-one", Body: payload(t, request)})
	return f
}

func sizedRangeReply(t *testing.T, received *Received, available int) protocol.Reply {
	t.Helper()
	makeReply := func(n int) protocol.Reply {
		result := protocol.ResultRange{Descriptor: protocol.Descriptor{SHA256: strings.Repeat("e", 64), Length: 1 << 30}, DataBase64: base64.StdEncoding.EncodeToString(make([]byte, n)), NextOffset: int64(n)}
		return protocol.Reply{Operation: protocol.ResultChunk, Body: payload(t, result)}
	}
	size := func(reply protocol.Reply) int {
		request := received.Frame()
		response := protocol.Frame{Version: protocol.Version, Type: protocol.Response, RequestID: request.RequestID, Generation: request.Generation, OperationID: request.OperationID, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload(t, reply)}
		data, err := protocol.EncodeFrame(response)
		if err != nil {
			t.Fatal(err)
		}
		return len(data)
	}
	n := min(48<<10, available*3/4)
	for attempts := 0; attempts < 4 && n >= 0; attempts++ {
		reply := makeReply(n)
		encodedSize := size(reply)
		if encodedSize <= available {
			return reply
		}
		// Base64 grows in four-byte groups. Remove the whole measured excess
		// at once instead of repeatedly encoding nearly identical large values.
		n -= ((encodedSize - available + 3) / 4) * 3
	}
	t.Fatal("no range response fits fixture budget")
	return protocol.Reply{}
}

// Retain completed ordinary response buffers without calling Await. The peer
// uses real typed, bounded result ranges. The final frame leaves at most sixteen
// bytes, too little for any ordinary request; protected capacity remains unused.
func fillResponses(t *testing.T, f *fixture, client *Client, target int) {
	t.Helper()
	s := gatewaySession(t, f)
	for index := 0; index < QueueFrames; index++ {
		s.mu.Lock()
		used := s.bytes
		s.mu.Unlock()
		if used >= target-16 {
			return
		}
		r, err := f.hub.Reserve(t.Context(), "device-one", rangeFrame(t))
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
		select {
		case <-r.job.done:
		case <-t.Context().Done():
			t.Fatal("request writer did not settle")
		}
		s.mu.Lock()
		used = s.bytes
		s.mu.Unlock()
		reply := sizedRangeReply(t, received, target-used)
		if _, claimErr := received.Claim(t.Context()); claimErr != nil {
			t.Fatal(claimErr)
		}
		if replyErr := received.Reply(t.Context(), reply); replyErr != nil {
			t.Fatal(replyErr)
		}
		select {
		case <-r.done:
		case <-t.Context().Done():
			t.Fatal("response was not received")
		}
		s.mu.Lock()
		responseErr := r.err
		s.mu.Unlock()
		if responseErr != nil {
			t.Fatal(responseErr)
		}
	}
	t.Fatal("response fixture exceeded bounded correlation count")
}

func TestOrdinaryResponseBytesPreserveProtectedRoundTrip(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	fillResponses(t, f, client, DeviceQueueBytes-ProtectedDeviceBytes)
	_, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	requireError(t, err, ErrCapacity)
	protectedRoundTrip(t, f, client)
}

func TestSharedOrdinaryResponseBytesPreserveProtectedRoundTrip(t *testing.T) {
	var shared budget
	var last *fixture
	var lastClient *Client
	remaining := GlobalQueueBytes - ProtectedGlobalBytes
	for remaining > 0 {
		f := newFixture(t, Settings{})
		client := f.dial(t)
		s := gatewaySession(t, f)
		// Fixture servers use independent credential stores. Their live sessions
		// share the exact production budget owner to exercise aggregate pressure.
		s.mu.Lock()
		if s.bytes != 0 {
			t.Fatal("fixture already owns queued bytes")
		}
		s.budget = &shared
		s.mu.Unlock()
		target := min(DeviceQueueBytes-ProtectedDeviceBytes, remaining)
		fillResponses(t, f, client, target)
		s.mu.Lock()
		used := s.bytes
		s.mu.Unlock()
		remaining -= used
		last, lastClient = f, client
		if remaining <= 16*9 {
			break
		}
	}
	if last == nil {
		t.Fatal("missing shared sessions")
	}
	_, err := last.hub.Reserve(t.Context(), "device-one", inspect(t))
	requireError(t, err, ErrCapacity)
	protectedRoundTrip(t, last, lastClient)
}

func TestSharedOrdinaryReservationBytesPreserveProtectedRoundTrip(t *testing.T) {
	var shared budget
	remaining := GlobalQueueBytes - ProtectedGlobalBytes
	var last *fixture
	var lastClient *Client
	for remaining > 0 {
		f := newFixture(t, Settings{})
		client := f.dial(t)
		s := gatewaySession(t, f)
		s.mu.Lock()
		s.budget = &shared
		s.mu.Unlock()
		target := min(DeviceQueueBytes-ProtectedDeviceBytes, remaining)
		for target > 0 {
			size := min(200<<10, target)
			r, err := f.hub.Reserve(t.Context(), "device-one", admissionSized(t, s, size))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if releaseErr := r.Release(); releaseErr != nil {
					t.Error(releaseErr)
				}
			})
			if r.Frame().EncodedFrameBytes != size {
				t.Fatal("sized reservation fixture mismatch")
			}
			target -= size
			remaining -= size
		}
		last, lastClient = f, client
	}
	_, err := last.hub.Reserve(t.Context(), "device-one", inspect(t))
	requireError(t, err, ErrCapacity)
	protectedRoundTrip(t, last, lastClient)
}

func TestProtectedClassRequiresStrictTypedControl(t *testing.T) {
	f := newFixture(t, Settings{})
	f.dial(t)
	frame := protectedControl(t, protocol.Cancel)
	frame.Payload = payload(t, protocol.Command{Operation: protocol.Cancel, Project: "project-one", Body: payload(t, protocol.TaskControl{Task: capacityTask()})})
	_, err := f.hub.Reserve(t.Context(), "device-one", frame)
	requireError(t, err, ErrProtocol)
	frame.Payload = payload(t, protocol.Command{Operation: protocol.FenceAbsent, Project: "project-one", Body: payload(t, struct {
		Task    protocol.TaskBinding `json:"task"`
		Padding string               `json:"padding"`
	}{capacityTask(), strings.Repeat("x", MaxProtectedFrameBytes)})})
	_, err = f.hub.Reserve(t.Context(), "device-one", frame)
	requireError(t, err, ErrProtocol)
}
