package connector

import (
	"context"
	"sync"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

type (
	control interface {
		Frame() protocol.Frame
		Claim(context.Context) (protocol.Frame, error)
		ReplyControl(context.Context, protocol.Reply, protocol.ControlCompletion) error
		ControlCall() protocol.ControlCall
		Reject(context.Context, protocol.Failure) error
		Discard() error
	}
	peer interface {
		next(context.Context) (control, error)
		report(context.Context, protocol.CapabilityReport) error
		generation() domain.ConnectionGeneration
		boot() string
		// close joins transport work before returning a cleanup diagnostic.
		// Native task closure remains a separate authoritative observation.
		close() error
	}
	clientPeer struct{ client *transport.Client }
)

func (p clientPeer) next(ctx context.Context) (control, error) { return p.client.Receive(ctx) }
func (p clientPeer) report(ctx context.Context, r protocol.CapabilityReport) error {
	return p.client.ReportCapabilities(ctx, r)
}

func (p clientPeer) generation() domain.ConnectionGeneration { return p.client.Generation() }
func (p clientPeer) boot() string                            { return p.client.ProcessBoot() }
func (p clientPeer) close() error                            { return p.client.Close() }

type (
	connection struct {
		peer   peer
		cancel context.CancelFunc
		ctx    context.Context
	}
	job struct {
		call       protocol.ControlCall
		control    control
		frame      protocol.Frame
		command    protocol.Command
		generation uint64
		connection *connection
		lost       bool
		held       permit
	}
)

// Service owns fixed control workers across network attachments. A disconnect
// cancels only intake/observation; accepted subprocesses retain their own owner.
type Service struct {
	inventoryMu sync.Mutex
	transition  sync.Mutex
	routing     routingState
	owner       context.Context
	adapter     *Adapter
	ordinary    chan *job
	urgent      chan *job
	stop        chan struct{}
	done        chan struct{}
	stopOnce    sync.Once
	mu          sync.Mutex
	closing     bool
	connection  *connection
	socket      peer
	active      map[*job]struct{}
	lastError   string
	workers     sync.WaitGroup
	intake      sync.WaitGroup
}
type ServiceStatus struct {
	Adapter            Status
	UnobservedControls int
	Ready              bool
	LastError          string
}

func NewService(owner context.Context, adapter *Adapter, config ServiceConfig) (*Service, error) {
	if owner == nil || adapter == nil || !checkedServiceConfig(config) {
		return nil, ErrConfiguration
	}
	s := &Service{routing: routingState{config: config, calls: make(map[protocol.ControlCall]bool), nudge: make(chan struct{}, 1)}, owner: owner, adapter: adapter, ordinary: make(chan *job, 4), urgent: make(chan *job, 2), stop: make(chan struct{}), done: make(chan struct{}), active: make(map[*job]struct{})}
	for range 4 {
		s.workers.Go(func() { s.worker(owner, s.ordinary) })
	}
	for range 2 {
		s.workers.Go(func() { s.worker(owner, s.urgent) })
	}
	s.workers.Go(func() { s.monitor(owner) })
	go func() { s.workers.Wait(); s.intake.Wait(); close(s.done) }()
	return s, nil
}

func (s *Service) Status() ServiceStatus {
	status := ServiceStatus{Adapter: s.adapter.Status()}
	status.Ready = status.Adapter.Ready
	s.mu.Lock()
	status.LastError = s.lastError
	for j := range s.active {
		if j.lost {
			status.UnobservedControls++
			status.Ready = false
		}
	}
	s.mu.Unlock()
	s.transition.Lock()
	status.Ready = status.Ready && s.routing.acked && s.routing.ack.Ready && s.routing.ack.CredentialMode == string(domain.Regular) && !s.routing.dirty && !s.routing.fencing
	s.transition.Unlock()
	return status
}

func (s *Service) capabilities() protocol.CapabilityReport {
	report := s.adapter.Capabilities()
	if !s.Status().Ready {
		for i := range report.Projects {
			report.Projects[i].Ready = false
		}
	}
	return report
}

func (s *Service) Attach(ctx context.Context, client *transport.Client) error {
	if client == nil {
		return ErrConfiguration
	}
	return s.attach(ctx, clientPeer{client: client})
}

func (s *Service) attach(ctx context.Context, p peer) error {
	intake, cancel := context.WithCancel(ctx)
	attached := &connection{peer: p, cancel: cancel, ctx: intake}
	s.transition.Lock()
	if !s.attachAllowedLocked(p) {
		s.transition.Unlock()
		cancel()
		return ErrConflict
	}
	s.mu.Lock()
	if s.closing || s.connection != nil || s.owner.Err() != nil {
		s.mu.Unlock()
		s.transition.Unlock()
		cancel()
		return ErrConflict
	}
	s.connection = attached
	s.socket = p
	s.routing.attachmentStarted = true
	s.intake.Add(1)
	s.mu.Unlock()
	s.transition.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		if s.connection == attached {
			s.connection = nil
		}
		for j := range s.active {
			if j.connection == attached {
				j.lost = true
			}
		}
		s.mu.Unlock()
		s.intake.Done()
	}()
	if err := p.report(intake, s.capabilities()); err != nil {
		return ErrPending
	}
	for {
		incoming, err := p.next(intake)
		if err != nil {
			return ErrPending
		}
		if acceptErr := s.queueIncoming(intake, attached, incoming); acceptErr != nil {
			return acceptErr
		}
	}
}

func (s *Service) refuse(ctx context.Context, incoming control) error {
	if rejectErr := incoming.Reject(ctx, protocol.Failure{Code: "resource_limit", Retryable: true}); rejectErr != nil {
		s.recordError("rejection_unavailable")
		s.requireReconcile()
		if discardErr := incoming.Discard(); discardErr != nil {
			return ErrPending
		}
	}
	return nil
}

func (s *Service) queueIncoming(ctx context.Context, attached *connection, incoming control) error {
	frame := incoming.Frame()
	command, decodeErr := protocol.DecodeCommand(frame)
	if decodeErr != nil {
		if discardErr := incoming.Discard(); discardErr != nil {
			return ErrPending
		}
		return nil
	}
	held, acquireErr := s.adapter.limits.acquire(command.Operation)
	if acquireErr != nil {
		return s.refuse(ctx, incoming)
	}
	frame.Payload = nil
	j := &job{call: incoming.ControlCall(), control: incoming, frame: frame, command: command, generation: s.adapter.Generation(), connection: attached, held: held}
	lane := s.ordinary
	if command.Operation == protocol.Cancel || command.Operation == protocol.FenceAbsent {
		lane = s.urgent
	}
	if !s.enqueue(j, lane) {
		held.release()
		return s.refuse(ctx, incoming)
	}
	return nil
}

func (s *Service) enqueue(j *job, lane chan<- *job) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	select {
	case lane <- j:
		return true
	default:
		return false
	}
}

func (s *Service) worker(owner context.Context, lane <-chan *job) {
	for {
		select {
		case <-s.stop:
			s.drain(lane)
			return
		case j := <-lane:
			s.perform(owner, j)
		}
	}
}

func (s *Service) drain(lane <-chan *job) {
	for {
		select {
		case j := <-lane:
			j.held.release()
			if err := j.control.Discard(); err != nil {
				s.recordError("discard_unavailable")
			}
		default:
			return
		}
	}
}

func (s *Service) perform(owner context.Context, j *job) {
	s.mu.Lock()
	s.active[j] = struct{}{}
	s.mu.Unlock()
	ctx, cancel := detachedControl(owner, s.adapter.snapshot().ControlTimeout)
	defer cancel()
	claimed := false
	accept := func(call context.Context) error {
		if owner.Err() != nil || j.connection.ctx.Err() != nil {
			return ErrPending
		}
		frame, err := s.claimControl(call, j)
		if err == nil {
			claimed = true
			if frame.RequestID != j.frame.RequestID || frame.Generation != j.frame.Generation || frame.OperationID != j.frame.OperationID {
				return ErrConflict
			}
		}
		return err
	}
	reply := s.adapter.execute(ctx, j.command, acceptance{generation: j.generation, operationID: j.frame.OperationID, claim: accept, held: &j.held})
	completion := s.completion(j, claimed)
	s.mu.Lock()
	delete(s.active, j)
	s.mu.Unlock()
	response, cancelResponse := context.WithTimeout(context.WithoutCancel(owner), 5*time.Second)
	if replyErr := j.control.ReplyControl(response, reply, completion); replyErr != nil {
		s.recordError("reply_unavailable")
		s.requireReconcile()
		if !claimed {
			if discardErr := j.control.Discard(); discardErr != nil {
				s.recordError("discard_unavailable")
			}
		}
	}

	cancelResponse()
}
func (s *Service) recordError(code string) { s.mu.Lock(); s.lastError = code; s.mu.Unlock() }

func (s *Service) stopIntake() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		if s.connection != nil {
			s.connection.cancel()
		}
		s.mu.Unlock()
		close(s.stop)
	})
}

func (s *Service) monitor(owner context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-owner.Done():
			s.stopIntake()
			return
		case <-s.stop:
			return
		case <-ticker.C:
			if cleanupErr := s.adapter.RetryCleanup(); cleanupErr != nil {
				s.recordError("cleanup_pending")
			}
			s.settleRetained()
			s.mu.Lock()
			attached := s.connection
			s.mu.Unlock()
			if attached == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.WithoutCancel(owner), 5*time.Second)
			if err := attached.peer.report(ctx, s.capabilities()); err != nil {
				s.recordError("capability_unavailable")
			}
			cancel()
		}
	}
}

func (s *Service) Close(ctx context.Context) error {
	s.stopIntake()
	select {
	case <-ctx.Done():
		return ErrPending
	case <-s.done:
		if s.adapter.Status().Active != 0 {
			return ErrPending
		}
		return nil
	}
}
