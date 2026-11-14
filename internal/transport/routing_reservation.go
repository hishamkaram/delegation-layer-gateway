package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// Routing returns a pre-publication immutable snapshot. Exact payload bytes are
// decoded from the sole encoded buffer; transport keeps no second payload copy.
func (r *Reservation) Routing() (routing.Request, error) {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.used || r.job.finished || !s.strictRouting || !s.gateway {
		return routing.Request{}, fail(ErrConflict, nil)
	}
	return r.routingLocked()
}

func (r *Reservation) routingLocked() (routing.Request, error) {
	s := r.session
	data := r.job.data
	if len(data) == 0 {
		if len(r.unusedPayload) == 0 {
			return routing.Request{}, fail(ErrConflict, nil)
		}
		return routing.Request{WireVersion: s.wireVersion, Credential: s.ref, ProcessBoot: r.metadata.ProcessBoot, Call: r.metadata.Call, Payload: bytes.Clone(r.unusedPayload), Now: s.now()}, nil
	}
	frame, decodeErr := protocol.DecodeFrameVersion(data, s.wireVersion)
	if decodeErr != nil {
		return routing.Request{}, fail(ErrProtocol, decodeErr)
	}
	return routing.Request{WireVersion: s.wireVersion, Credential: s.ref, ProcessBoot: r.metadata.ProcessBoot, Call: r.metadata.Call, Payload: frame.Payload, Now: s.now()}, nil
}

// ArmRouting is called only after the durable routing acquisition commits. An
// already-closed but never-published buffer retains exact proof for explicit
// ReleaseUnused; socket cleanup itself never makes a durable release decision.
func (r *Reservation) ArmRouting(input routing.Request) error {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.used || r.armed || !s.strictRouting || s.routing == nil {
		return fail(ErrConflict, nil)
	}
	hash := domain.Hash(input.Payload)
	if input.ProtocolVersion() != s.wireVersion || input.Credential != r.metadata.Credential || input.ProcessBoot != r.metadata.ProcessBoot || input.Call != r.metadata.Call || hex.EncodeToString(hash[:]) != input.Call.RequestSHA256 || input.Now.IsZero() {
		return fail(ErrProtocol, nil)
	}
	r.armed = true
	if r.job.finished || s.closing {
		r.unusedPayload = bytes.Clone(input.Payload)
		return fail(ErrOffline, nil)
	}
	return nil
}

func (s *session) unpublished(ctx context.Context, input routing.Request) error {
	call, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.settings.WriteTimeout)
	defer cancel()
	input.Now = s.now()
	if releaseErr := s.routing.ReleaseUnpublishedRouting(call, input); releaseErr != nil {
		s.mu.Lock()
		s.routingReady = false
		s.mu.Unlock()
		wrapped := fail(ErrNotReady, releaseErr)
		s.stop(wrapped)
		return wrapped
	}
	return nil
}

// finishUnsent is invoked only by the publishing buffer or its writer, never
// generic socket/job teardown. writeStarted means publication may have happened.
func (s *session) finishUnsent(ctx context.Context, job *writeJob, cause error) error {
	s.mu.Lock()
	var input routing.Request
	var proofErr error
	r := job.reservation
	release := r != nil && r.armed && !job.writeStarted && !r.unpublishedAttempted && len(job.data) != 0
	if release {
		r.unpublishedAttempted = true
		input, proofErr = r.routingLocked()
	}
	s.mu.Unlock()
	var releaseErr error
	if release && proofErr == nil {
		releaseErr = s.unpublished(ctx, input)
	}
	result := errors.Join(cause, proofErr, releaseErr)
	s.mu.Lock()
	s.finishJobLocked(job, result)
	s.mu.Unlock()
	return result
}

// ReleaseUnused declines only an unpublished buffer. A used request remains
// owned by its writer/correlated response; observation cancellation cannot free it.
func (r *Reservation) ReleaseUnused(ctx context.Context) error {
	s := r.session
	s.mu.Lock()
	if r.used {
		if !r.unusedRelease {
			s.mu.Unlock()
			return nil
		}
		done := r.releaseDone
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		defer s.mu.Unlock()
		return r.releaseErr
	}
	r.used = true
	r.unusedRelease = true
	r.releaseDone = make(chan struct{})
	var input routing.Request
	var proofErr error
	release := r.armed && !r.unpublishedAttempted && !r.job.writeStarted
	if release {
		r.unpublishedAttempted = true
		input, proofErr = r.routingLocked()
	}
	s.mu.Unlock()
	var releaseErr error
	if release && proofErr == nil {
		releaseErr = s.unpublished(ctx, input)
	}
	result := errors.Join(proofErr, releaseErr)
	s.mu.Lock()
	r.releaseErr = result
	r.unusedPayload = nil
	s.finishJobLocked(r.job, fail(ErrConflict, result))
	close(r.releaseDone)
	s.mu.Unlock()
	return result
}
