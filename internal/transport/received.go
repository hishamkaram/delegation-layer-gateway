package transport

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// MaxSessionRequests bounds allocations and replay memory. Reconnect creates a new generation;
// reaching this bound closes this wire session, never replays an admission.
const MaxSessionRequests = 4096

// Received is unaccepted until Claim. The adapter acquires its own control slot
// first, then Claims immediately before CLI. Claimed work/cleanup belongs to the
// adapter and is not cancelled when this session disconnects.
type Received struct {
	encodedBytes int
	call         protocol.ControlCall
	class        trafficClass
	session      *session
	frame        protocol.Frame
	deadline     time.Time
	operation    protocol.Operation
	renewalID    string
	size         int
	claimed      bool
	released     bool
	replied      bool
}

func (r *Received) Deadline() time.Time { return r.deadline }
func (r *Received) Frame() protocol.Frame {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	f := r.frame
	f.Payload = bytes.Clone(f.Payload)
	return f
}

func (r *Received) Claim(ctx context.Context) (protocol.Frame, error) {
	s := r.session
	if checkErr := s.check(ctx); checkErr != nil {
		return protocol.Frame{}, checkErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.released || r.claimed || s.closing {
		return protocol.Frame{}, fail(ErrOffline, nil)
	}
	if !s.now().Before(r.deadline) {
		r.discardLocked()
		return protocol.Frame{}, fail(ErrExpired, nil)
	}
	if r.frame.Generation != wireGeneration(s.generation) {
		return protocol.Frame{}, fail(ErrProtocol, nil)
	}
	r.claimed = true
	r.released = true
	s.budget.release(s, r.size)
	r.size = 0
	delete(s.received, r)
	frame := r.frame
	r.frame.Payload = nil
	return frame, nil
}

// Discard releases an unclaimed request when the adapter cannot accept it.
func (r *Received) Discard() error {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.claimed {
		return fail(ErrConflict, nil)
	}
	r.discardLocked()
	return nil
}

// Reject declines an unclaimed control without acquiring a CLI permit. It is
// only for resource saturation, never an alternate task/authorization outcome.
func (r *Received) Reject(ctx context.Context, failure protocol.Failure) error {
	if failure.Code != "resource_limit" || failure.Validate() != nil {
		return fail(ErrProtocol, nil)
	}
	s := r.session
	if checkErr := s.check(ctx); checkErr != nil {
		return checkErr
	}
	reply := protocol.Reply{Operation: r.operation, Error: &failure}
	payload, err := r.replyPayload(reply, protocol.ControlNotClaimed)
	if err != nil {
		return fail(ErrProtocol, err)
	}
	return r.unclaimedResponse(ctx, payload)
}

func (r *Received) unclaimedResponse(ctx context.Context, payload []byte) error {
	s := r.session
	if checkErr := s.check(ctx); checkErr != nil {
		return checkErr
	}
	s.mu.Lock()
	if r.frame.Type != protocol.Request || r.claimed || r.replied || r.released || s.closing {
		s.mu.Unlock()
		return fail(ErrConflict, nil)
	}
	if r.frame.Generation != wireGeneration(s.generation) {
		s.mu.Unlock()
		return fail(ErrProtocol, nil)
	}
	if !s.now().Before(r.deadline) {
		r.discardLocked()
		s.mu.Unlock()
		return fail(ErrExpired, nil)
	}
	r.replied = true
	frame := protocol.Frame{Version: s.wireVersion, Type: protocol.Response, RequestID: r.frame.RequestID, Generation: r.frame.Generation, OperationID: r.frame.OperationID, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload}
	r.discardLocked()
	s.mu.Unlock()
	return s.sendClass(ctx, frame, r.class)
}

func (r *Received) discardLocked() {
	if r.released {
		return
	}
	s := r.session
	s.budget.release(s, r.size)
	r.size = 0
	r.frame.Payload = nil
	r.released = true
	delete(s.received, r)
}

func (s *session) receive(frame protocol.Frame, size int, at time.Time) error {
	operation, renewalID, err := s.inbound(frame)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return fail(ErrOffline, nil)
	}
	class := ordinaryTraffic
	if operation == protocol.Cancel || operation == protocol.FenceAbsent {
		class = protectedTraffic
	}
	ordinary := 0
	for r := range s.received {
		if r.class == ordinaryTraffic {
			ordinary++
		}
	}
	if !hasCountCapacity(len(s.received), ordinary, class) || len(s.seen) >= MaxSessionRequests {
		return fail(ErrCapacity, nil)
	}
	if checkErr := s.recordPeerIDLocked(frame.RequestID); checkErr != nil {
		return checkErr
	}
	if !s.budget.acquire(s, size, class) {
		return fail(ErrCapacity, nil)
	}
	r := &Received{encodedBytes: size, call: controlCall(frame, operation), class: class, session: s, frame: frame, deadline: frame.Deadline(at), operation: operation, renewalID: renewalID, size: size}
	s.received[r] = struct{}{}
	select {
	case s.incoming <- r:
		return nil
	default:
		s.budget.release(s, size)
		r.size = 0
		r.released = true
		delete(s.received, r)
		return fail(ErrCapacity, nil)
	}
}

func (s *session) recordPeerIDLocked(id string) error {
	prefix := "g:"
	if s.gateway {
		prefix = "d:"
	}
	if !strings.HasPrefix(id, prefix) {
		return fail(ErrProtocol, nil)
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(id, prefix), 10, 64)
	if err != nil || n == 0 || id != prefix+strconv.FormatUint(n, 10) {
		return fail(ErrProtocol, err)
	}
	if _, exists := s.seen[n]; exists {
		return fail(ErrProtocol, nil)
	}
	s.seen[n] = struct{}{}
	return nil
}

func (s *session) inbound(frame protocol.Frame) (protocol.Operation, string, error) {
	if s.gateway {
		renewal, err := renewalFromFrame(frame, s.ref)
		if err != nil {
			return "", "", err
		}
		return "", renewal.RenewalID, nil
	}
	command, err := protocol.DecodeCommandVersion(frame, s.wireVersion)
	if err != nil {
		return "", "", fail(ErrProtocol, err)
	}
	if s.mode == domain.RecoveryOnly && !command.Operation.AllowedRecoveryOnly() {
		return "", "", fail(ErrForbidden, nil)
	}
	if _, classErr := commandClass(command); classErr != nil {
		return "", "", classErr
	}
	return command.Operation, "", nil
}

func renewalFromFrame(frame protocol.Frame, ref domain.CredentialRef) (protocol.Renewal, error) {
	var renewal protocol.Renewal
	if frame.Type != protocol.RenewCertificate || frame.OperationID != "" || protocol.DecodeStrict(frame.Payload, &renewal, protocol.MaxFrameBytes) != nil {
		return protocol.Renewal{}, fail(ErrProtocol, nil)
	}
	if _, err := renewal.CSR(); err != nil || renewal.DeviceID != string(ref.Device) || renewal.CredentialGeneration != ref.Generation {
		return protocol.Renewal{}, fail(ErrProtocol, err)
	}
	return renewal, nil
}

// Reply serves nonproduction low-level sessions without a routing owner. Strict
// sessions must use ReplyControl so semantic success cannot omit CLI ownership.
func (r *Received) Reply(ctx context.Context, reply protocol.Reply) error {
	if r.session.strictRouting {
		return fail(ErrProtocol, nil)
	}
	if r.frame.Type != protocol.Request || reply.ValidateVersion(r.session.wireVersion) != nil || reply.Operation != r.operation {
		return fail(ErrProtocol, nil)
	}
	payload, err := protocol.Encode(reply, protocol.MaxFrameBytes)
	if err != nil {
		return fail(ErrProtocol, err)
	}
	return r.reply(ctx, protocol.Response, payload)
}

func (r *Received) ControlCall() protocol.ControlCall {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	return r.call
}

func (r *Received) replyPayload(reply protocol.Reply, disposition protocol.ControlDisposition) ([]byte, error) {
	if !r.session.strictRouting {
		return protocol.Encode(reply, protocol.MaxFrameBytes)
	}
	response := protocol.ControlResponse{Completion: protocol.ControlCompletion{ProcessBoot: r.session.processBoot, Call: r.call, Disposition: disposition}, Reply: reply}
	if response.ValidateVersion(r.session.wireVersion) != nil {
		return nil, fail(ErrProtocol, nil)
	}
	return protocol.Encode(response, protocol.MaxFrameBytes)
}

func (r *Received) ReplyControl(ctx context.Context, reply protocol.Reply, completion protocol.ControlCompletion) error {
	if !r.session.strictRouting || r.frame.Type != protocol.Request || reply.Operation != r.operation || completion.Call != r.call || completion.ProcessBoot != r.session.processBoot {
		return fail(ErrProtocol, nil)
	}
	response := protocol.ControlResponse{Completion: completion, Reply: reply}
	if response.ValidateVersion(r.session.wireVersion) != nil {
		return fail(ErrProtocol, nil)
	}
	payload, encodeErr := protocol.Encode(response, protocol.MaxFrameBytes)
	if encodeErr != nil {
		return fail(ErrProtocol, encodeErr)
	}
	if completion.Disposition == protocol.ControlNotClaimed {
		return r.unclaimedResponse(ctx, payload)
	}
	return r.reply(ctx, protocol.Response, payload)
}

func (r *Received) ReplyRenewal(ctx context.Context, result protocol.RenewalResult) error {
	s := r.session
	if r.frame.Type != protocol.RenewCertificate || result.Validate() != nil || result.DeviceID != string(s.ref.Device) || result.RenewalID != r.renewalID {
		return fail(ErrProtocol, nil)
	}
	if result.Error == nil && (result.Epoch != string(s.ref.Epoch) || result.Generation != s.ref.Generation) {
		return fail(ErrProtocol, nil)
	}
	payload, err := protocol.Encode(result, protocol.MaxFrameBytes)
	if err != nil {
		return fail(ErrProtocol, err)
	}
	return r.reply(ctx, protocol.RenewCertificateResult, payload)
}

func (r *Received) reply(ctx context.Context, kind protocol.Kind, payload []byte) error {
	s := r.session
	s.mu.Lock()
	if !r.claimed || r.replied {
		s.mu.Unlock()
		return fail(ErrConflict, nil)
	}
	r.replied = true
	frame := protocol.Frame{Version: s.wireVersion, Type: kind, RequestID: r.frame.RequestID, Generation: r.frame.Generation, OperationID: r.frame.OperationID, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload}
	s.mu.Unlock()
	return s.sendClass(ctx, frame, r.class)
}

func (s *session) send(ctx context.Context, frame protocol.Frame) error {
	return s.sendClass(ctx, frame, ordinaryTraffic)
}

func (s *session) sendClass(ctx context.Context, frame protocol.Frame, class trafficClass) error {
	if checkErr := s.check(ctx); checkErr != nil {
		return checkErr
	}
	encoded, err := protocol.EncodeFrameVersion(frame, s.wireVersion)
	if err != nil {
		return fail(ErrProtocol, err)
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return fail(ErrOffline, nil)
	}
	if !s.jobCapacity(class) || !s.budget.acquire(s, len(encoded), class) {
		s.mu.Unlock()
		return fail(ErrCapacity, nil)
	}
	job := &writeJob{class: class, data: encoded, ctx: ctx, metadata: Metadata{Credential: s.ref, Connection: s.generation, RequestID: frame.RequestID, OperationID: frame.OperationID, EncodedFrameBytes: len(encoded)}, deadline: s.now().Add(protocol.MaxTTL), done: make(chan struct{})}
	s.jobs[job] = struct{}{}
	select {
	case s.writeQueue <- job:
	default:
		s.finishJobLocked(job, fail(ErrCapacity, nil))
		s.mu.Unlock()
		return fail(ErrCapacity, nil)
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return fail(ErrExpired, ctx.Err())
	case <-job.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return job.err
	}
}

// Metadata returns the original authenticated socket binding, even after Claim
// or a later credential/session supersession. Registry remains its validity owner.
func (r *Received) Metadata() Metadata {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	return Metadata{Credential: s.ref, Connection: s.generation, ProcessBoot: s.processBoot, Call: r.call, RequestID: r.frame.RequestID, OperationID: r.frame.OperationID, EncodedFrameBytes: r.encodedBytes}
}
