package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Reservation owns one pre-accounted wire buffer and its correlated reply.
// Publish is one-shot and must follow the application's durable possible-send
// commit. Await cancellation is only observation cancellation, never a socket
// or Delegate cancellation.
type Reservation struct {
	armed                bool
	unpublishedAttempted bool
	unusedRelease        bool
	unusedPayload        []byte
	releaseErr           error
	releaseDone          chan struct{}
	session              *session
	metadata             Metadata
	job                  *writeJob
	binding              replyBinding
	used                 bool
	finished             bool
	abandoned            bool
	taken                bool
	response             protocol.Frame
	responseBytes        int
	// Unlike responseBytes (live buffer accounting), this immutable observation
	// survives consumption without keeping the response payload alive.
	observedResponseBytes int
	err                   error
	done                  chan struct{}
}

type replyBinding struct {
	class     trafficClass
	operation protocol.Operation
	kind      protocol.Kind
	renewalID string
}

func (r *Reservation) Frame() Metadata { return r.metadata }

func (s *session) reserve(ctx context.Context, frame protocol.Frame) (*Reservation, error) {
	if checkErr := s.check(ctx); checkErr != nil {
		return nil, checkErr
	}
	select {
	case <-s.ready:
	default:
		return nil, fail(ErrOffline, nil)
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil, fail(ErrOffline, nil)
	}
	id, err := s.nextIDLocked()
	if err != nil {
		s.mu.Unlock()
		s.stop(err)
		return nil, err
	}
	defer s.mu.Unlock()
	frame.RequestID = id
	frame.Generation = wireGeneration(s.generation)
	frame.Payload = bytes.Clone(frame.Payload)
	binding, err := s.outbound(frame)
	if err != nil {
		return nil, err
	}
	if s.gateway && s.strictRouting && !s.routingAck.AllowsControl(binding.operation) {
		return nil, fail(ErrNotReady, nil)
	}
	if !s.jobCapacity(binding.class) || !s.correlationCapacity(binding.class) {
		return nil, fail(ErrCapacity, nil)
	}
	encoded, err := protocol.EncodeFrameVersion(frame, s.wireVersion)
	if err != nil {
		return nil, fail(ErrProtocol, err)
	}
	var wireFrame protocol.Frame
	if decodeErr := json.Unmarshal(encoded, &wireFrame); decodeErr != nil {
		return nil, fail(ErrProtocol, decodeErr)
	}
	if !s.budget.acquire(s, len(encoded), binding.class) {
		return nil, fail(ErrCapacity, nil)
	}
	metadata := Metadata{ProcessBoot: s.processBoot, Call: controlCall(wireFrame, binding.operation), Credential: s.ref, Connection: s.generation, RequestID: id, OperationID: frame.OperationID, EncodedFrameBytes: len(encoded)}
	job := &writeJob{class: binding.class, data: encoded, metadata: metadata, deadline: s.now().Add(time.Duration(frame.TTLMillis) * time.Millisecond), done: make(chan struct{})}
	r := &Reservation{session: s, metadata: metadata, job: job, binding: binding, done: make(chan struct{})}
	job.reservation = r
	s.jobs[job] = struct{}{}
	return r, nil
}

func (s *session) outbound(frame protocol.Frame) (replyBinding, error) {
	if s.gateway {
		command, err := protocol.DecodeCommandVersion(frame, s.wireVersion)
		if err != nil {
			return replyBinding{}, fail(ErrProtocol, err)
		}
		if s.mode == domain.RecoveryOnly && !command.Operation.AllowedRecoveryOnly() {
			return replyBinding{}, fail(ErrForbidden, nil)
		}
		class, classErr := commandClass(command)
		if classErr != nil {
			return replyBinding{}, classErr
		}
		return replyBinding{class: class, operation: command.Operation, kind: protocol.Response}, nil
	}
	renewal, err := renewalFromFrame(frame, s.ref)
	if err != nil {
		return replyBinding{}, err
	}
	return replyBinding{kind: protocol.RenewCertificateResult, renewalID: renewal.RenewalID}, nil
}

func (r *Reservation) Publish(ctx context.Context, guard SendGuard) error {
	s := r.session
	s.mu.Lock()
	if r.used {
		s.mu.Unlock()
		return fail(ErrConflict, nil)
	}
	r.used = true
	var rejection error
	switch {
	case s.closing:
		rejection = fail(ErrOffline, nil)
	case s.gateway && guard == nil:
		rejection = fail(ErrForbidden, nil)
	case s.gateway && s.strictRouting && !r.armed:
		rejection = fail(ErrForbidden, nil)
	case ctx.Err() != nil:
		rejection = fail(ErrExpired, ctx.Err())
	}
	if rejection != nil {
		s.mu.Unlock()
		return s.finishUnsent(ctx, r.job, rejection)
	}
	r.job.ctx = ctx
	r.job.guard = guard
	s.pending[r.metadata.RequestID] = r
	select {
	case s.writeQueue <- r.job:
		s.mu.Unlock()
		return nil
	default:
		s.mu.Unlock()
		return s.finishUnsent(ctx, r.job, fail(ErrCapacity, nil))
	}
}

func (r *Reservation) Release() error {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.used || r.armed {
		return fail(ErrConflict, nil)
	}
	r.used = true
	s.finishJobLocked(r.job, fail(ErrConflict, nil))
	return nil
}

func (r *Reservation) Await(ctx context.Context) (protocol.Frame, error) {
	s := r.session
	s.mu.Lock()
	used := r.used
	abandoned := r.abandoned
	previousErr := r.err
	writeDone := r.job.done
	s.mu.Unlock()
	if !used {
		return protocol.Frame{}, fail(ErrConflict, nil)
	}
	if abandoned {
		return protocol.Frame{}, previousErr
	}
	// A peer can reply before the originating Write finishes unwinding. Join
	// that writer, including its cancellation cleanup, before delivering any
	// completed response. The writer needs s.mu to publish its completion.
	for _, done := range []<-chan struct{}{r.done, writeDone} {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			defer s.mu.Unlock()
			r.abandoned = true
			r.err = fail(ErrExpired, ctx.Err())
			if r.finished && !r.taken {
				s.consumePendingLocked(r)
			}
			return protocol.Frame{}, r.err
		case <-done:
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.taken {
		return protocol.Frame{}, fail(ErrConflict, nil)
	}
	if checkErr := ctx.Err(); checkErr != nil {
		s.consumePendingLocked(r)
		return protocol.Frame{}, fail(ErrExpired, checkErr)
	}
	frame, err := r.response, r.err
	s.consumePendingLocked(r)
	return frame, err
}

func (s *session) finishPendingLocked(r *Reservation, frame protocol.Frame, err error) {
	if r.finished {
		return
	}
	r.finished = true
	if !r.abandoned {
		r.response = frame
		r.err = err
	}
	close(r.done)
	if r.abandoned {
		s.consumePendingLocked(r)
	}
}

func (s *session) consumePendingLocked(r *Reservation) {
	r.taken = true
	s.releasePendingLocked(r)
}

func (s *session) releasePendingLocked(r *Reservation) {
	if r.responseBytes != 0 {
		s.budget.release(s, r.responseBytes)
		r.responseBytes = 0
	}
	r.response = protocol.Frame{}
	delete(s.pending, r.metadata.RequestID)
}

func (s *session) response(ctx context.Context, frame protocol.Frame, size int) error {
	s.mu.Lock()
	r, completion, checkErr := s.validateResponseLocked(frame, size)
	if checkErr == nil {
		r.observedResponseBytes = size
	}
	s.mu.Unlock()
	if checkErr != nil {
		return checkErr
	}
	if completion != nil {
		if completeErr := s.completeRouting(ctx, *completion); completeErr != nil {
			return completeErr
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.finished || s.pending[frame.RequestID] != r {
		return nil
	}
	if r.abandoned {
		s.finishPendingLocked(r, protocol.Frame{}, nil)
		return nil
	}
	if !s.budget.acquire(s, size, r.binding.class) {
		s.finishPendingLocked(r, protocol.Frame{}, fail(ErrCapacity, nil))
		return nil
	}
	r.responseBytes = size
	s.finishPendingLocked(r, frame, nil)
	return nil
}

func (s *session) validateResponseLocked(frame protocol.Frame, size int) (*Reservation, *protocol.ControlCompletion, error) {
	r := s.pending[frame.RequestID]
	if r == nil || r.finished || r.binding.kind != frame.Type || r.metadata.OperationID != frame.OperationID {
		return nil, nil, fail(ErrProtocol, nil)
	}
	if r.binding.class == protectedTraffic && size > MaxProtectedFrameBytes {
		return nil, nil, fail(ErrProtocol, nil)
	}
	completion, checkErr := r.validateResponse(frame)
	return r, completion, checkErr
}

// completeRouting runs before delivery, even when the observer abandoned Await.
// It never runs under the session mutex or treats socket loss as settlement.
func (s *session) completeRouting(ctx context.Context, completion protocol.ControlCompletion) error {
	call, cancel := context.WithTimeout(ctx, s.settings.WriteTimeout)
	defer cancel()
	if completeErr := s.routing.CompleteRouting(call, s.ref, s.generation, completion, s.now()); completeErr != nil {
		s.mu.Lock()
		s.routingReady = false
		s.mu.Unlock()
		wrapped := fail(ErrNotReady, completeErr)
		s.stop(wrapped)
		return wrapped
	}
	return nil
}

func (r *Reservation) validateResponse(frame protocol.Frame) (*protocol.ControlCompletion, error) {
	if frame.Type != protocol.Response {
		return nil, r.validateRenewal(frame)
	}
	if r.session.strictRouting {
		var response protocol.ControlResponse
		if decodeErr := protocol.DecodeStrict(frame.Payload, &response, protocol.MaxFrameBytes); decodeErr != nil {
			return nil, fail(ErrProtocol, decodeErr)
		}
		if response.ValidateVersion(r.session.wireVersion) != nil || response.Reply.Operation != r.binding.operation || response.Completion.ProcessBoot != r.metadata.ProcessBoot || response.Completion.Call != r.metadata.Call {
			return nil, fail(ErrProtocol, nil)
		}
		return &response.Completion, nil
	}
	var reply protocol.Reply
	if decodeErr := protocol.DecodeStrict(frame.Payload, &reply, protocol.MaxFrameBytes); decodeErr != nil {
		return nil, fail(ErrProtocol, decodeErr)
	}
	if checkErr := reply.ValidateVersion(r.session.wireVersion); checkErr != nil || reply.Operation != r.binding.operation {
		return nil, fail(ErrProtocol, checkErr)
	}
	return nil, nil
}

func (r *Reservation) validateRenewal(frame protocol.Frame) error {
	var renewal protocol.RenewalResult
	if checkErr := protocol.DecodeStrict(frame.Payload, &renewal, protocol.MaxFrameBytes); checkErr != nil {
		return fail(ErrProtocol, checkErr)
	}
	if renewal.Validate() != nil || renewal.DeviceID != string(r.metadata.Credential.Device) || renewal.RenewalID != r.binding.renewalID {
		return fail(ErrProtocol, nil)
	}
	if renewal.Error == nil && (renewal.Epoch != string(r.metadata.Credential.Epoch) || renewal.Generation != r.metadata.Credential.Generation) {
		return fail(ErrProtocol, nil)
	}
	return nil
}
