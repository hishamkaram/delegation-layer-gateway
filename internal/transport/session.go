package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type session struct {
	wireVersion            int
	routing                RoutingAuthority
	strictRouting          bool
	processBoot            string
	routingReady           bool
	routingAck             protocol.ControlInventoryAck
	ctx                    context.Context
	cancel                 context.CancelFunc
	conn                   *websocket.Conn
	ref                    domain.CredentialRef
	certificate            *x509.Certificate
	generation             domain.ConnectionGeneration
	gateway                bool
	mode                   domain.CredentialMode
	store                  CredentialChecker
	now                    func() time.Time
	settings               Settings
	budget                 *budget
	incoming               chan *Received
	writeQueue             chan *writeJob
	done                   chan struct{}
	ready                  chan struct{}
	stopOnce               sync.Once
	mu                     sync.Mutex
	err                    error
	closeErr               error
	closing                bool
	sequence               uint64
	bytes                  int
	jobs                   map[*writeJob]struct{}
	pending                map[string]*Reservation
	received               map[*Received]struct{}
	seen                   map[uint64]struct{}
	capabilities           []byte
	capabilitiesObservedAt time.Time
	lastSeen               time.Time
}

type writeJob struct {
	writeStarted bool
	class        trafficClass
	data         []byte
	ctx          context.Context
	guard        SendGuard
	metadata     Metadata
	deadline     time.Time
	done         chan struct{}
	err          error
	finished     bool
	reservation  *Reservation
}

func (s *session) jobCapacity(class trafficClass) bool {
	ordinary := 0
	for job := range s.jobs {
		if job.class == ordinaryTraffic {
			ordinary++
		}
	}
	return hasCountCapacity(len(s.jobs), ordinary, class)
}

func (s *session) correlationCapacity(class trafficClass) bool {
	total, ordinary := 0, 0
	for _, r := range s.pending {
		total++
		if r.binding.class == ordinaryTraffic {
			ordinary++
		}
	}
	for job := range s.jobs {
		if r := job.reservation; r != nil && s.pending[r.metadata.RequestID] == nil {
			total++
			if r.binding.class == ordinaryTraffic {
				ordinary++
			}
		}
	}
	return hasCountCapacity(total, ordinary, class)
}

func newSession(ctx context.Context, config Settings, now func() time.Time, b *budget, incoming chan *Received) *session {
	owned, cancel := context.WithCancel(ctx)
	return &session{wireVersion: protocol.Version, ctx: owned, cancel: cancel, settings: config, now: now, budget: b, incoming: incoming, writeQueue: make(chan *writeJob, QueueFrames), done: make(chan struct{}), ready: make(chan struct{}), jobs: make(map[*writeJob]struct{}), pending: make(map[string]*Reservation), received: make(map[*Received]struct{}), seen: make(map[uint64]struct{})}
}

func (s *session) stop(reason error) {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.err = reason
		conn := s.conn
		s.mu.Unlock()
		s.cancel()
		if conn != nil {
			if closeErr := conn.CloseNow(); closeErr != nil {
				s.recordCloseError(closeErr)
			}
		}
	})
}

func (s *session) recordCloseError(err error) {
	if errors.Is(err, net.ErrClosed) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeErr = fail(ErrOffline, err)
}
func (s *session) closeFailure() error { s.mu.Lock(); defer s.mu.Unlock(); return s.closeErr }

func (s *session) check(ctx context.Context) error {
	if checkErr := ctx.Err(); checkErr != nil {
		return fail(ErrOffline, checkErr)
	}
	now := s.now()
	if s.certificate == nil || now.Before(s.certificate.NotBefore) || !now.Before(s.certificate.NotAfter) {
		return fail(ErrForbidden, nil)
	}
	if s.store == nil {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, s.settings.WriteTimeout)
	defer cancel()
	credential, err := s.store.CheckCredential(call, s.ref, now)
	if err != nil {
		return fail(ErrForbidden, err)
	}
	if credential.Ref != s.ref || credential.Mode != s.mode || credential.PublicKeyHash != domain.Hash(s.certificate.RawSubjectPublicKeyInfo) {
		return fail(ErrForbidden, nil)
	}
	return nil
}

func (s *session) run(ctx context.Context) {
	// Handshake/request deadlines do not own an established socket. Session
	// cancellation remains authoritative, while caller values remain inherited.
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	join := s.joinCancellation(cancel)
	defer join()
	var workers sync.WaitGroup
	workers.Go(s.writer)
	workers.Go(s.heartbeat)
	err := s.reader(ctx)
	s.stop(err)
	workers.Wait()
	join()
	s.finish()
}

func (s *session) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = fail(ErrOffline, nil)
	}
	for job := range s.jobs {
		s.finishJobLocked(job, s.err)
	}
	for _, pending := range s.pending {
		s.finishPendingLocked(pending, protocol.Frame{}, s.err)
		pending.err = s.err
		s.releasePendingLocked(pending)
	}
	for received := range s.received {
		s.budget.release(s, received.size)
		received.size = 0
		received.frame.Payload = nil
		received.released = true
		delete(s.received, received)
	}
	s.capabilities = nil
	s.seen = nil
	close(s.done)
}

func (s *session) writer() {
	for {
		if s.ctx.Err() != nil {
			return
		}
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.writeQueue:
			err := s.write(job)
			if err != nil {
				err = s.finishUnsent(s.ctx, job, err)
			} else {
				s.mu.Lock()
				s.finishJobLocked(job, nil)
				s.mu.Unlock()
			}
			if err != nil && s.ctx.Err() != nil {
				return
			}
		}
	}
}

func (s *session) write(job *writeJob) error {
	s.mu.Lock()
	finished := job.finished
	s.mu.Unlock()
	if finished {
		return fail(ErrConflict, nil)
	}
	if checkErr := job.ctx.Err(); checkErr != nil {
		return fail(ErrExpired, checkErr)
	}
	if !s.now().Before(job.deadline) {
		return fail(ErrExpired, nil)
	}
	ctx, cancel := s.writeContext(job.ctx)
	defer cancel()
	if checkErr := s.check(ctx); checkErr != nil {
		s.stop(checkErr)
		return checkErr
	}
	if job.guard != nil {
		if checkErr := job.guard(ctx, job.metadata); checkErr != nil {
			return fail(ErrForbidden, checkErr)
		}
	}
	if checkErr := s.check(ctx); checkErr != nil {
		s.stop(checkErr)
		return checkErr
	}
	if checkErr := job.ctx.Err(); checkErr != nil {
		return fail(ErrExpired, checkErr)
	}
	if !s.now().Before(job.deadline) {
		return fail(ErrExpired, nil)
	}
	s.mu.Lock()
	if job.finished || s.closing {
		s.mu.Unlock()
		return fail(ErrOffline, nil)
	}
	job.writeStarted = true
	data := job.data
	s.mu.Unlock()
	if checkErr := s.conn.Write(ctx, websocket.MessageText, data); checkErr != nil {
		wrapped := fail(ErrOffline, checkErr)
		s.stop(wrapped)
		return wrapped
	}
	return nil
}

// Queued guards retain only their originating request's values and deadline.
// Socket shutdown also cancels the write; cleanup joins the cancellation hook.
func (s *session) writeContext(request context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(request, s.settings.WriteTimeout)
	return ctx, s.joinCancellation(cancel)
}

func (s *session) joinCancellation(cancel context.CancelFunc) context.CancelFunc {
	joined := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() {
		cancel()
		close(joined)
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-joined
			}
			cancel()
		})
	}
}

func (s *session) finishJobLocked(job *writeJob, err error) {
	if job.finished {
		return
	}
	job.finished = true
	job.err = err
	s.budget.release(s, len(job.data))
	job.data = nil
	job.guard = nil
	job.ctx = nil
	delete(s.jobs, job)
	close(job.done)
	if err != nil && job.reservation != nil {
		s.finishPendingLocked(job.reservation, protocol.Frame{}, err)
	}
}

func (s *session) heartbeat() {
	ticker := time.NewTicker(s.settings.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(s.ctx, s.settings.OfflineTimeout-s.settings.HeartbeatInterval)
			err := s.check(ctx)
			if err == nil {
				err = s.conn.Ping(ctx)
			}
			cancel()
			if err != nil {
				s.stop(fail(ErrOffline, err))
				return
			}
			s.mu.Lock()
			s.lastSeen = s.now()
			s.mu.Unlock()
		}
	}
}

func (s *session) reader(ctx context.Context) error {
	for {
		kind, data, err := s.conn.Read(ctx)
		if err != nil {
			return fail(ErrOffline, err)
		}
		if kind != websocket.MessageText {
			return fail(ErrProtocol, nil)
		}
		received := s.now()
		if checkErr := s.check(ctx); checkErr != nil {
			return checkErr
		}
		frame, err := protocol.DecodeFrameVersion(data, s.wireVersion)
		if err != nil || frame.Generation != wireGeneration(s.generation) {
			return fail(ErrProtocol, err)
		}
		s.mu.Lock()
		s.lastSeen = received
		s.mu.Unlock()
		if checkErr := s.route(ctx, frame, data, received); checkErr != nil {
			return checkErr
		}
	}
}

func (s *session) route(ctx context.Context, frame protocol.Frame, data []byte, received time.Time) error {
	switch frame.Type {
	case protocol.Response, protocol.RenewCertificateResult:
		return s.response(ctx, frame, len(data))
	case protocol.Capabilities:
		if !s.gateway {
			return fail(ErrProtocol, nil)
		}
		if checkErr := validateCapabilityPayload(frame.Payload, s.wireVersion); checkErr != nil {
			return fail(ErrProtocol, checkErr)
		}
		s.mu.Lock()
		s.capabilities = bytes.Clone(frame.Payload)
		s.capabilitiesObservedAt = received
		s.mu.Unlock()
		return nil
	case protocol.Request, protocol.RenewCertificate:
		return s.receive(frame, len(data), received)
	case protocol.Hello, protocol.RoutingInventory, protocol.RoutingInventoryAck:
		return fail(ErrProtocol, nil)
	default:
		return fail(ErrProtocol, nil)
	}
}

func wireGeneration(g domain.ConnectionGeneration) protocol.Generation {
	return protocol.Generation{BootEpoch: string(g.BootEpoch), Counter: g.Counter}
}

func (s *session) nextIDLocked() (string, error) {
	if s.closing || s.sequence >= MaxSessionRequests {
		s.closing = true
		return "", fail(ErrOffline, nil)
	}
	s.sequence++
	prefix := "d:"
	if s.gateway {
		prefix = "g:"
	}
	return prefix + strconv.FormatUint(s.sequence, 10), nil
}
