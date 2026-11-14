package devicehub

import (
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func (h *Hub) observeConnection(started time.Time, state transport.ConnectionState, peer *transport.InboundSession) {
	if h.config.ConnectionObserved == nil {
		return
	}
	value := transport.ConnectionObservation{State: state}
	if peer != nil {
		snapshot, err := peer.Snapshot()
		if err == nil {
			value.Credential, value.Generation = snapshot.Credential, snapshot.Generation
		}
	}

	// Sample before the observer's own recording work. This is elapsed local
	// connection observation, not network latency or a provider/task deadline.
	value.Duration = time.Since(started)
	h.config.ConnectionObserved(value)
}
