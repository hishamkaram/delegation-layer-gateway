package protocol

import (
	"encoding/json"
	"time"
)

const (
	Version       = 1
	Subprotocol   = "delegate-gateway.v1"
	MaxFrameBytes = 1 << 20
	// Admission must leave routing headroom for two cancellation/fence calls.
	MaxAdmissionFrameBytes = MaxFrameBytes - (64 << 10)
	MaxTTL                 = 30 * time.Second
)

type Kind string

const (
	Hello                  Kind = "hello"
	RoutingInventory       Kind = "control_inventory"
	RoutingInventoryAck    Kind = "control_inventory_ack"
	Capabilities           Kind = "capabilities"
	Request                Kind = "request"
	Response               Kind = "response"
	RenewCertificate       Kind = "renew_certificate"
	RenewCertificateResult Kind = "renew_certificate_result"
)

func (k Kind) Validate() error {
	switch k {
	case Hello, Capabilities, Request, Response, RenewCertificate, RenewCertificateResult, RoutingInventory, RoutingInventoryAck:
		return nil
	default:
		return ErrInvalid
	}
}

type Generation struct {
	BootEpoch string `json:"boot_epoch"`
	Counter   uint64 `json:"counter"`
}

func (g Generation) Validate() error {
	if !identifier(g.BootEpoch) || g.Counter == 0 {
		return ErrInvalid
	}
	return nil
}

// Frame carries one typed payload. DecodeFrame validates only the common
// envelope; its consumer must decode the payload into the type selected by Kind.
// Generation is assigned by Gateway, including the initial hello response.
type Frame struct {
	Version     int             `json:"version"`
	Type        Kind            `json:"type"`
	RequestID   string          `json:"request_id"`
	Generation  Generation      `json:"connection_generation"`
	OperationID string          `json:"operation_id,omitempty"`
	TTLMillis   int64           `json:"ttl_ms"`
	Payload     json.RawMessage `json:"payload"`
}

func (f Frame) Validate() error {
	if f.Version != Version || f.Type.Validate() != nil || !identifier(f.RequestID) || f.Generation.Validate() != nil {
		return ErrInvalid
	}
	if f.OperationID != "" && !identifier(f.OperationID) {
		return ErrInvalid
	}
	if f.TTLMillis < 1 || f.TTLMillis > MaxTTL.Milliseconds() || len(f.Payload) == 0 || string(f.Payload) == "null" {
		return ErrInvalid
	}
	return nil
}

func DecodeFrame(data []byte) (Frame, error) {
	var frame Frame
	if err := DecodeStrict(data, &frame, MaxFrameBytes); err != nil {
		return Frame{}, err
	}
	if err := frame.Validate(); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

// EncodeFrame performs the actual encoded-byte limit check before the caller
// may reserve durable possible-send accounting or queue a transmission.
func EncodeFrame(frame Frame) ([]byte, error) {
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	data, err := Encode(frame, MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	if _, err = DecodeFrame(data); err != nil {
		return nil, err
	}
	return data, nil
}

// Deadline records receipt on the local monotonic clock. It never interprets
// the TTL as task closure or as elapsed time since the remote sender wrote.
func (f Frame) Deadline(received time.Time) time.Time {
	return received.Add(time.Duration(f.TTLMillis) * time.Millisecond)
}

type Operation string

const (
	ContextInspect  Operation = "context_inspect"
	Admit           Operation = "admit"
	Resolve         Operation = "resolve"
	ResumeExisting  Operation = "resume_existing"
	FenceAbsent     Operation = "fence_absent"
	Status          Operation = "status"
	Collect         Operation = "collect"
	ResultChunk     Operation = "result_chunk"
	Cancel          Operation = "cancel"
	OriginBarrier   Operation = "origin_barrier"
	OriginInventory Operation = "origin_inventory"
	OriginReopen    Operation = "origin_reopen"
)

func (o Operation) Validate() error {
	switch o {
	case ContextInspect, Admit, Resolve, ResumeExisting, FenceAbsent, Status, Collect, ResultChunk, Cancel, OriginBarrier, OriginInventory, OriginReopen:
		return nil
	default:
		return ErrInvalid
	}
}

func (o Operation) Administrative() bool {
	return o == OriginBarrier || o == OriginInventory || o == OriginReopen
}

func (o Operation) AllowedRecoveryOnly() bool {
	switch o {
	case ContextInspect, Resolve, FenceAbsent, Status, Collect, ResultChunk, Cancel, OriginBarrier, OriginInventory:
		return true
	case Admit, ResumeExisting, OriginReopen:
		return false
	default:
		return false
	}
}

// Command separates its typed operation body from the common device-local alias.
// Bodies never contain executable names, local paths, environment or raw argv.
type Command struct {
	Operation Operation       `json:"operation"`
	Project   string          `json:"project"`
	Body      json.RawMessage `json:"body"`
}

func DecodeCommand(frame Frame) (Command, error) {
	var command Command
	if frame.Type != Request {
		return command, ErrInvalid
	}
	if err := DecodeStrict(frame.Payload, &command, MaxFrameBytes); err != nil {
		return command, err
	}
	if command.Operation.Validate() != nil || !identifier(command.Project) || len(command.Body) == 0 || string(command.Body) == "null" {
		return Command{}, ErrInvalid
	}
	return command, nil
}
