package transport

import (
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type ConnectionState string

const (
	ConnectionEstablished ConnectionState = "established"
	ConnectionClosed      ConnectionState = "closed"
	ConnectionFailed      ConnectionState = "failed"
)

// ConnectionObservation reports only the captured authenticated connection.
// Zero identity fields explicitly mean verification/allocation was not observed.
// Duration covers local connection observation, never Native task execution.
type ConnectionObservation struct {
	State      ConnectionState
	Credential domain.CredentialRef
	Generation domain.ConnectionGeneration
	Duration   time.Duration
}

// ActiveConnections samples ready, non-closing sessions owned by this Hub.
// It is a bounded gauge, never execution readiness or Delegate task capacity.
func (h *Hub) ActiveConnections() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return 0
	}
	var active uint64
	for _, s := range h.sessions {
		s.mu.Lock()
		select {
		case <-s.ready:
			if !s.closing {
				active++
			}
		default:
		}
		s.mu.Unlock()
	}
	return active
}

// Admission to this existing join group is serialized with Close. Failed
// registrations otherwise have no registered session worker to own callbacks.
func (h *Hub) beginConnectionObservation() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil {
		return false
	}
	h.workers.Add(1)
	return true
}

func (h *Hub) observeConnection(started time.Time, state ConnectionState, s *session) {
	if h.config.ConnectionObserved == nil {
		return
	}
	value := ConnectionObservation{State: state}
	if s != nil {
		s.mu.Lock()
		value.Credential, value.Generation = s.ref, s.generation
		s.mu.Unlock()
	}
	// Sample before the observer's own recording work. This is elapsed local
	// connection observation, not network latency or a provider/task deadline.
	value.Duration = time.Since(started)
	h.config.ConnectionObserved(value)
}
