package routing

import (
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// ControlClass is a closed observation vocabulary, not an executable command.
// PrepareClass has no wire operation; all other classes use the wire contract.
type ControlClass string

const PrepareClass ControlClass = "prepare"

func (c ControlClass) Validate() error {
	if c == PrepareClass {
		return nil
	}
	return protocol.Operation(c).Validate()
}

type ActorKind string

const (
	PrincipalActor  ActorKind = "principal"
	LocalAdminActor ActorKind = "local_admin"
)

type AuthorizationDecision string

const (
	NotEvaluated    AuthorizationDecision = "not_evaluated"
	Allowed         AuthorizationDecision = "allowed"
	DeniedOrMissing AuthorizationDecision = "denied_or_missing"
	DecisionUnknown AuthorizationDecision = "unknown"
)

func (d AuthorizationDecision) valid() bool {
	return d == NotEvaluated || d == Allowed || d == DeniedOrMissing || d == DecisionUnknown
}

type WriteState string

const (
	WriteNotStarted       WriteState = "not_started"
	WriteAttemptedUnknown WriteState = "attempted_unknown"
	WriteCompleted        WriteState = "write_completed"
)

type TransportOutcome string

const (
	NotAttempted   TransportOutcome = "not_attempted"
	NotSent        TransportOutcome = "not_sent"
	WriteUnknown   TransportOutcome = "write_unknown"
	WrittenNoReply TransportOutcome = "written_no_reply"
	ReplyReceived  TransportOutcome = "reply_received"
	ReplyInvalid   TransportOutcome = "reply_invalid"
)

// TransferSnapshot is an immutable observation of a transport-owned exchange.
// Frame lengths count encoded application messages, excluding WSS/TLS overhead.
// A reserved or attempted length never establishes bytes delivered to a peer.
type TransferSnapshot struct {
	WriteState                WriteState `json:"write_state"`
	EncodedRequestFrameBytes  int        `json:"request_frame_bytes"`
	EncodedResponseFrameBytes int        `json:"response_frame_bytes"`
	ResponseKnown             bool       `json:"response_known"`
}

// ControlMetadata contains observations only. No field authorizes a send or
// describes Native task success. Duration ends before Recorder persistence.
type ControlMetadata struct {
	Class         ControlClass                `json:"class"`
	Actor         ActorKind                   `json:"actor"`
	Authorization AuthorizationDecision       `json:"authorization"`
	Recheck       AuthorizationDecision       `json:"recheck"`
	Transport     TransportOutcome            `json:"transport"`
	DurationNS    int64                       `json:"control_observation_duration_ns"`
	Connection    domain.ConnectionGeneration `json:"connection,omitzero"`
	Request       domain.RequestID            `json:"request_id,omitempty"`
	TransferSnapshot
}

func (m ControlMetadata) Validate() error {
	if m.Class.Validate() != nil || (m.Actor != PrincipalActor && m.Actor != LocalAdminActor) || !m.Authorization.valid() || !m.Recheck.valid() || m.DurationNS < 0 {
		return domain.ErrInvalid
	}
	if !m.validIdentity() || !m.validMeasurements() || !m.validTransport() {
		return domain.ErrInvalid
	}
	return nil
}

func (m ControlMetadata) validIdentity() bool {
	return (m.Connection == (domain.ConnectionGeneration{}) || m.Connection.Validate() == nil) && (m.Request == "" || domain.Token(string(m.Request)) == nil)
}

func (m ControlMetadata) validMeasurements() bool {
	validBytes := m.EncodedRequestFrameBytes >= 0 && m.EncodedRequestFrameBytes <= protocol.MaxFrameBytes && m.EncodedResponseFrameBytes >= 0 && m.EncodedResponseFrameBytes <= protocol.MaxFrameBytes
	knownResponse := m.ResponseKnown == (m.EncodedResponseFrameBytes > 0)
	validWrite := m.WriteState == WriteNotStarted || m.WriteState == WriteAttemptedUnknown || m.WriteState == WriteCompleted
	return validBytes && knownResponse && validWrite && (m.WriteState == WriteNotStarted || m.EncodedRequestFrameBytes > 0)
}

func (m ControlMetadata) validTransport() bool {
	switch m.Transport {
	case NotAttempted, NotSent:
		return m.WriteState == WriteNotStarted && !m.ResponseKnown
	case WriteUnknown:
		return m.WriteState == WriteAttemptedUnknown
	case WrittenNoReply:
		return m.WriteState == WriteCompleted && !m.ResponseKnown
	case ReplyReceived, ReplyInvalid:
		return m.WriteState == WriteCompleted && m.ResponseKnown
	default:
		return false
	}
}
