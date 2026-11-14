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

// ActiveConnections samples ready, non-closing sessions owned by this Server.
// It is a bounded gauge, never execution readiness or Delegate task capacity.
func (h *Server) ActiveConnections() uint64 {
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
