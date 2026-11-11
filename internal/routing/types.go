// Package routing defines durable fleet-control resource identities. It owns no
// task outcomes, storage, network connections or mutable process state.
package routing

import (
	"encoding/hex"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Request carries the exact encoded Command transiently. Stores persist only
// its validated hash and immutable call/credential/process binding.
type Request struct {
	Credential  domain.CredentialRef
	ProcessBoot string
	Call        protocol.ControlCall
	Payload     []byte
	Now         time.Time
}

type Readiness struct {
	Ready       bool
	Reason      Reason
	ProcessBoot string
	Generation  domain.ConnectionGeneration
	Outstanding int
}

const (
	MaxOrdinaryPermits  = 32
	MaxProtectedPermits = 8
	MaxOrdinaryScans    = 3
	MaxProtectedScans   = 1
	MaxDeviceScans      = 1
	MaxRecoveryDevices  = 10000
)

type Reason string

const (
	HandshakeRequired Reason = "handshake_required"
	ProcessChanged    Reason = "process_changed"
	RecoveryPending   Reason = "recovery_pending"
	CapacityExceeded  Reason = "capacity_exceeded"
)

// Drain is protected local-admin evidence that prior-process CLI controls and
// cleanup were joined. It cannot release Delegate execution reservations.
type Drain struct {
	Device      domain.DeviceID
	Credential  domain.CredentialRef
	Recovery    domain.RecoveryID
	Scope       DrainScope
	PriorBoot   string
	CurrentBoot string
	Generation  domain.ConnectionGeneration
	Now         time.Time
}

type DrainScope string

const (
	KnownPriorBoot   DrainScope = "known_prior_boot"
	AllPriorControls DrainScope = "all_prior_controls"
)

type DrainDisposition string

const (
	Drained          DrainDisposition = "drained"
	AlreadySatisfied DrainDisposition = "already_satisfied"
)

type DrainTarget struct {
	Device      domain.DeviceID
	Recovery    domain.RecoveryID
	Credential  domain.CredentialRef
	ProcessBoot string
	Generation  domain.ConnectionGeneration
	Blocked     bool
	Covered     bool
}

type DrainResult struct {
	Disposition DrainDisposition
	Target      DrainTarget
}

func ValidProcessBoot(boot string) bool {
	decoded, err := hex.DecodeString(boot)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == boot
}

func (t DrainTarget) Validate() error {
	if t.Credential.Validate() != nil || t.Credential.Device != t.Device || !ValidProcessBoot(t.ProcessBoot) || t.Generation.Validate() != nil {
		return domain.ErrInvalid
	}
	if t.Recovery != "" && domain.RoutingToken(string(t.Recovery)) != nil {
		return domain.ErrInvalid
	}
	return nil
}

// ValidateBinding checks frozen operator expectations without granting authority
// or requiring a clock supplied by the network boundary.
func (d Drain) ValidateBinding() error {
	if (DrainTarget{Device: d.Device, Credential: d.Credential, Recovery: d.Recovery, ProcessBoot: d.CurrentBoot, Generation: d.Generation}).Validate() != nil {
		return domain.ErrInvalid
	}
	switch d.Scope {
	case KnownPriorBoot:
		if !ValidProcessBoot(d.PriorBoot) || d.PriorBoot == d.CurrentBoot {
			return domain.ErrInvalid
		}
	case AllPriorControls:
		if d.PriorBoot != "" {
			return domain.ErrInvalid
		}
	default:
		return domain.ErrInvalid
	}
	return nil
}
