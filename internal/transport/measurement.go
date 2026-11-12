package transport

// WriteState conservatively reports local publication/writer observation. A
// completed write does not prove peer receipt, admission or task completion.
type WriteState string

const (
	// WriteNotStarted is unpublished or settled without invoking Write.
	WriteNotStarted WriteState = "not_started"
	// WriteAttemptedUnknown includes published work whose writer may progress
	// after the observer returns, even before the physical Write has started.
	WriteAttemptedUnknown WriteState = "attempted_unknown"
	WriteCompleted        WriteState = "write_completed"
)

// TransferSnapshot contains encoded WebSocket text-message lengths, excluding
// WebSocket framing, TLS, TCP and HTTP overhead. Request length is the reserved
// frame size, not a count of partially written or peer-received bytes.
type TransferSnapshot struct {
	WriteState                WriteState
	EncodedRequestFrameBytes  int
	EncodedResponseFrameBytes int
	// ResponseKnown means a bound frame validated, including when later routing
	// settlement or buffer accounting fails. It never means application success.
	ResponseKnown bool
}

// TransferSnapshot samples the existing reservation owner without retaining
// payloads or changing publication, observation or cleanup authority.
func (r *Reservation) TransferSnapshot() TransferSnapshot {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	state := WriteNotStarted
	if r.job.writeStarted || r.job.ctx != nil && !r.job.finished {
		state = WriteAttemptedUnknown
		if r.job.writeStarted && r.job.finished && r.job.err == nil {
			state = WriteCompleted
		}
	}
	return TransferSnapshot{
		WriteState:                state,
		EncodedRequestFrameBytes:  r.metadata.EncodedFrameBytes,
		EncodedResponseFrameBytes: r.observedResponseBytes,
		ResponseKnown:             r.observedResponseBytes > 0,
	}
}
