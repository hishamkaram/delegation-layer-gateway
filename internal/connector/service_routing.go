package connector

import (
	"context"
	"encoding/hex"
	"io"
	"sort"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type ServiceConfig struct {
	ProcessBoot string
	Random      io.Reader
}

type routingState struct {
	attachmentStarted bool
	fencing           bool
	config            ServiceConfig
	inventory         *protocol.ControlInventory
	ack               protocol.ControlInventoryAck
	acked             bool
	dirty             bool
	claimsStarted     bool
	calls             map[protocol.ControlCall]bool // true retains a returned control's cleanup
	nudge             chan struct{}
}

func checkedServiceConfig(config ServiceConfig) bool {
	decoded, decodeErr := hex.DecodeString(config.ProcessBoot)
	return decodeErr == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == config.ProcessBoot && config.Random != nil
}

func cloneInventory(value protocol.ControlInventory) protocol.ControlInventory {
	value.Active = append([]protocol.ControlCall(nil), value.Active...)
	return value
}

// Inventory freezes new claims, joins old socket intake/reader ownership, and
// returns one immutable complete census for this generation. It never joins or
// cancels accepted CLI controls; those remain represented in the active set.
func (s *Service) Inventory(ctx context.Context, generation domain.ConnectionGeneration) (protocol.ControlInventory, error) {
	if ctx.Err() != nil || generation.Validate() != nil {
		return protocol.ControlInventory{}, ErrPending
	}
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()
	wire := protocol.Generation{BootEpoch: string(generation.BootEpoch), Counter: generation.Counter}
	s.transition.Lock()
	state := &s.routing
	if state.inventory != nil && state.inventory.Generation == wire {
		if state.claimsStarted {
			s.transition.Unlock()
			return protocol.ControlInventory{}, ErrConflict
		}
		snapshot := cloneInventory(*state.inventory)
		s.transition.Unlock()
		return snapshot, nil
	}
	// The explicit fence stays set while socket/intake joins run outside the
	// transition mutex. Intake capability reporting may itself read that mutex.
	state.acked = false
	state.dirty = true
	state.fencing = true
	s.transition.Unlock()
	fenceErr := s.fenceOldIntake()
	s.transition.Lock()
	defer s.transition.Unlock()
	state.fencing = false
	if fenceErr != nil {
		return protocol.ControlInventory{}, fenceErr
	}
	if ctx.Err() != nil {
		return protocol.ControlInventory{}, ErrPending
	}
	if s.adapter.Status().Active == 0 {
		s.clearRetainedLocked()
	}
	barrier := make([]byte, 16)
	if _, randomErr := io.ReadFull(state.config.Random, barrier); randomErr != nil {
		return protocol.ControlInventory{}, ErrPending
	}
	inventory := protocol.ControlInventory{PolicyVersion: protocol.RoutingPolicyVersion, ProcessBoot: state.config.ProcessBoot, BarrierID: hex.EncodeToString(barrier), Generation: wire, Complete: true}
	for call := range state.calls {
		inventory.Active = append(inventory.Active, call)
	}
	sort.Slice(inventory.Active, func(i, j int) bool { return callLess(inventory.Active[i], inventory.Active[j]) })
	if inventory.Validate() != nil {
		return protocol.ControlInventory{}, ErrEvidence
	}
	state.inventory = &inventory
	state.dirty = false
	state.claimsStarted = false
	state.attachmentStarted = false
	select {
	case <-state.nudge:
	default:
	}
	return cloneInventory(inventory), nil
}

func callLess(a, b protocol.ControlCall) bool {
	if a.Generation.BootEpoch != b.Generation.BootEpoch {
		return a.Generation.BootEpoch < b.Generation.BootEpoch
	}
	if a.Generation.Counter != b.Generation.Counter {
		return a.Generation.Counter < b.Generation.Counter
	}
	return a.RequestID < b.RequestID
}

// The routing fence is set under transition before joining; new attachments and
// claims remain denied while the mutex is released for these joins.
func (s *Service) fenceOldIntake() error {
	s.mu.Lock()
	old := s.connection
	socket := s.socket
	closing := s.closing
	if old != nil {
		old.cancel()
	}
	s.mu.Unlock()
	if closing || s.owner.Err() != nil {
		return ErrPending
	}
	if socket != nil {
		if closeErr := socket.close(); closeErr != nil {
			s.recordError("prior_socket_cleanup")
			return ErrPending
		}
		s.intake.Wait()
		s.mu.Lock()
		s.socket = nil
		s.mu.Unlock()
	}
	return nil
}

func (s *Service) Acknowledge(ctx context.Context, ack protocol.ControlInventoryAck) error {
	if ctx.Err() != nil || ack.Validate() != nil {
		return ErrEvidence
	}
	s.transition.Lock()
	defer s.transition.Unlock()
	inventory := s.routing.inventory
	if s.routing.fencing || inventory == nil || ack.ProcessBoot != inventory.ProcessBoot || ack.BarrierID != inventory.BarrierID || ack.Generation != inventory.Generation {
		return ErrConflict
	}
	s.routing.ack = ack
	s.routing.acked = true
	if s.routing.dirty {
		return ErrPending
	}
	return nil
}

// NeedsReconcile signals a concrete local ownership transition. It coalesces;
// callers reconnect and perform a new fenced census, never periodically guess.
func (s *Service) NeedsReconcile() <-chan struct{} { return s.routing.nudge }

func (s *Service) dirtyLocked() {
	s.routing.dirty = true
	select {
	case s.routing.nudge <- struct{}{}:
	default:
	}
}
func (s *Service) requireReconcile() { s.transition.Lock(); s.dirtyLocked(); s.transition.Unlock() }

func (s *Service) attachAllowedLocked(p peer) bool {
	g := p.generation()
	wire := protocol.Generation{BootEpoch: string(g.BootEpoch), Counter: g.Counter}
	return !s.routing.fencing && !s.routing.attachmentStarted && s.routing.acked && s.routing.ack.Generation == wire && p.boot() == s.routing.config.ProcessBoot
}

func (s *Service) allowsControlLocked(operation protocol.Operation) bool {
	return !s.routing.fencing && s.routing.acked && !s.routing.dirty && s.routing.ack.AllowsControl(operation)
}

func (s *Service) claimControl(ctx context.Context, j *job) (protocol.Frame, error) {
	s.transition.Lock()
	defer s.transition.Unlock()
	if s.owner.Err() != nil || j.connection.ctx.Err() != nil || !s.allowsControlLocked(j.command.Operation) {
		return protocol.Frame{}, ErrPending
	}
	if len(s.routing.calls) >= protocol.MaxActiveControls {
		return protocol.Frame{}, ErrCapacity
	}
	s.routing.calls[j.call] = false
	s.routing.claimsStarted = true
	frame, claimErr := j.control.Claim(ctx)
	if claimErr != nil {
		delete(s.routing.calls, j.call)
		s.dirtyLocked()
		return protocol.Frame{}, claimErr
	}
	return frame, nil
}

func (s *Service) completion(j *job, claimed bool) protocol.ControlCompletion {
	s.transition.Lock()
	defer s.transition.Unlock()
	disposition := protocol.ControlNotClaimed
	if claimed {
		disposition = protocol.ControlSettled
		if s.adapter.Status().CleanupPending != 0 {
			disposition = protocol.ControlPending
			s.routing.calls[j.call] = true
		} else {
			delete(s.routing.calls, j.call)
		}
	}
	if !claimed || s.routing.inventory == nil || j.call.Generation != s.routing.inventory.Generation {
		s.dirtyLocked()
	}
	return protocol.ControlCompletion{ProcessBoot: s.routing.config.ProcessBoot, Call: j.call, Disposition: disposition}
}

func (s *Service) clearRetainedLocked() bool {
	changed := false
	for call, retained := range s.routing.calls {
		if retained {
			delete(s.routing.calls, call)
			changed = true
		}
	}
	return changed
}

func (s *Service) settleRetained() {
	if s.adapter.Status().Active != 0 {
		return
	}
	s.transition.Lock()
	defer s.transition.Unlock()
	if s.clearRetainedLocked() {
		s.dirtyLocked()
	}
}
