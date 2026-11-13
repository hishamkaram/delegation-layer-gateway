package protocol

import "strconv"

const (
	RoutingPolicyVersion = 1
	MaxActiveControls    = 6
)

// ControlCall is immutable routing identity, not a Delegate task record. Digest
// binds the exact encoded Command payload; paths, briefs and results are absent.
type ControlCall struct {
	Generation    Generation `json:"generation"`
	RequestID     string     `json:"request_id"`
	OperationID   string     `json:"operation_id,omitempty"`
	Operation     Operation  `json:"operation"`
	RequestSHA256 string     `json:"request_sha256"`
}

func (c ControlCall) Validate() error {
	return c.ValidateVersion(WireVersion2)
}

func (c ControlCall) ValidateVersion(version int) error {
	if c.Generation.Validate() != nil || c.Operation.ValidateVersion(version) != nil || !lowerHex(c.RequestSHA256, 64) || (c.OperationID != "" && !identifier(c.OperationID)) {
		return ErrInvalid
	}
	if len(c.RequestID) < 3 || len(c.RequestID) > 128 || c.RequestID[:2] != "g:" {
		return ErrInvalid
	}
	number, err := strconv.ParseUint(c.RequestID[2:], 10, 64)
	if err != nil || number == 0 || "g:"+strconv.FormatUint(number, 10) != c.RequestID {
		return ErrInvalid
	}
	return nil
}

// ControlInventory is sent during the new authenticated generation handshake,
// after old intake has joined and all old unclaimed controls are fenced. New
// claims remain paused until Gateway durably reconciles and acknowledges it.
type ControlInventory struct {
	PolicyVersion int           `json:"policy_version"`
	ProcessBoot   string        `json:"process_boot"`
	BarrierID     string        `json:"barrier_id"`
	Generation    Generation    `json:"generation"`
	Complete      bool          `json:"complete"`
	Active        []ControlCall `json:"active"`
}

func (r ControlInventory) Validate() error {
	return r.ValidateVersion(WireVersion2)
}

func (r ControlInventory) ValidateVersion(version int) error {
	if !r.validHeader(version) {
		return ErrInvalid
	}
	seen := make(map[ControlCall]bool)
	for _, call := range r.Active {
		if call.ValidateVersion(version) != nil || call.Generation == r.Generation || seen[call] {
			return ErrInvalid
		}
		for previous := range seen {
			if previous.Generation == call.Generation && previous.RequestID == call.RequestID {
				return ErrInvalid
			}
		}
		seen[call] = true
	}
	return nil
}

func (r ControlInventory) validHeader(version int) bool {
	return (version == Version || version == WireVersion2) && r.PolicyVersion == RoutingPolicyVersion && lowerHex(r.ProcessBoot, 32) && lowerHex(r.BarrierID, 32) && r.Generation.Validate() == nil && r.Complete && len(r.Active) <= MaxActiveControls
}

type ControlDisposition string

const (
	ControlNotClaimed ControlDisposition = "not_claimed"
	ControlPending    ControlDisposition = "pending"
	ControlSettled    ControlDisposition = "settled"
)

// Settled means every owned CLI Wait, I/O join and cleanup is complete. It says
// nothing about whether Delegate execution continues or its outcome is accepted.
// NotClaimed is irrevocable: this call key can never start a CLI later.
type ControlCompletion struct {
	ProcessBoot string             `json:"process_boot"`
	Call        ControlCall        `json:"call"`
	Disposition ControlDisposition `json:"disposition"`
}

func (c ControlCompletion) Validate() error {
	return c.ValidateVersion(WireVersion2)
}

func (c ControlCompletion) ValidateVersion(version int) error {
	if !lowerHex(c.ProcessBoot, 32) || c.Call.ValidateVersion(version) != nil {
		return ErrInvalid
	}
	switch c.Disposition {
	case ControlNotClaimed, ControlPending, ControlSettled:
		return nil
	}
	return ErrInvalid
}

// ScanConsumer counts full-payload/raw-manifest verification, including hidden
// scans in metadata task controls. Origin inventory scans history/preparation
// metadata, but does not open accepted payloads or sealed raw manifests.
func (o Operation) ScanConsumer() bool {
	switch o {
	case Admit, Resolve, ResumeExisting, FenceAbsent, Status, Collect, ResultChunk, Cancel:
		return true
	case ContextInspect, OriginBarrier, OriginInventory, OriginReopen, ResolveProject:
		return false
	}
	return false
}
func (o Operation) ProtectedControl() bool { return o == Cancel || o == FenceAbsent }

// ControlInventoryAck confirms the exact census was durably reconciled. An
// online transport whose ack is not ready cannot claim regular CLI controls.
type ControlInventoryAck struct {
	CredentialMode string     `json:"credential_mode"`
	PolicyVersion  int        `json:"policy_version"`
	ProcessBoot    string     `json:"process_boot"`
	BarrierID      string     `json:"barrier_id"`
	Generation     Generation `json:"generation"`
	Ready          bool       `json:"ready"`
	Reason         string     `json:"reason,omitempty"`
}

func (a ControlInventoryAck) Validate() error {
	if (a.CredentialMode != "regular" && a.CredentialMode != "recovery_only") || a.PolicyVersion != RoutingPolicyVersion || !lowerHex(a.ProcessBoot, 32) || !lowerHex(a.BarrierID, 32) || a.Generation.Validate() != nil {
		return ErrInvalid
	}
	if a.Ready {
		if a.Reason != "" {
			return ErrInvalid
		}
		return nil
	}
	switch a.Reason {
	case "handshake_required", "process_changed", "recovery_pending", "capacity_exceeded":
		return nil
	}
	return ErrInvalid
}

// AllowsControl preserves the already-approved restricted recovery channel
// while ordinary execution readiness stays false. Registry separately requires
// protected local-admin authority and current resource limits for this path.
func (a ControlInventoryAck) AllowsControl(operation Operation) bool {
	if a.Validate() != nil || operation.Validate() != nil {
		return false
	}
	if a.Ready {
		return a.CredentialMode == "regular" || operation.AllowedRecoveryOnly()
	}
	return a.Reason == "recovery_pending" && a.CredentialMode == "recovery_only" && operation.AllowedRecoveryOnly()
}

// ControlResponse keeps transport resource closure separate from the semantic
// Delegate reply. A pending CLI cleanup never releases its routing permit.
type ControlResponse struct {
	Completion ControlCompletion `json:"completion"`
	Reply      Reply             `json:"reply"`
}

func (r ControlResponse) Validate() error {
	return r.ValidateVersion(WireVersion2)
}

func (r ControlResponse) ValidateVersion(version int) error {
	if r.Completion.ValidateVersion(version) != nil || r.Reply.ValidateVersion(version) != nil || r.Completion.Call.Operation != r.Reply.Operation {
		return ErrInvalid
	}
	if r.Completion.Disposition == ControlNotClaimed && r.Reply.Error == nil {
		return ErrInvalid
	}
	return nil
}
