package adminapi

import (
	"context"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// RoutingDrains leaves durable drain decisions with Registry.
type RoutingDrains interface {
	ReadRoutingDrainTarget(context.Context, domain.DeviceID, time.Time) (routing.DrainTarget, error)
	AttestRoutingDrained(context.Context, routing.Drain) (routing.DrainResult, error)
}

// GenerationDisconnector joins only the captured credential and connection.
// Retired means that connection is absent; it does not prove a reconnect.
type GenerationDisconnector interface {
	DisconnectGeneration(context.Context, domain.CredentialRef, domain.ConnectionGeneration) (ConnectionStatus, error)
}

type ConnectionStatus string

const (
	ConnectionJoined    ConnectionStatus = "joined"
	ConnectionRetired   ConnectionStatus = "retired"
	ConnectionUnchanged ConnectionStatus = "unchanged"
)

type RoutingTargetInput struct {
	DeviceID string `json:"device_id"`
}

func (i RoutingTargetInput) Validate() error {
	return domain.CredentialToken(i.DeviceID)
}

type CredentialBinding struct {
	DeviceID   string `json:"device_id"`
	Epoch      string `json:"epoch"`
	Generation uint64 `json:"generation"`
}

func (c CredentialBinding) credential() domain.CredentialRef {
	return domain.CredentialRef{Device: domain.DeviceID(c.DeviceID), Epoch: domain.CredentialEpoch(c.Epoch), Generation: c.Generation}
}

type RoutingDrainTarget struct {
	DeviceID    string              `json:"device_id"`
	RecoveryID  string              `json:"recovery_id"`
	Credential  CredentialBinding   `json:"credential"`
	ProcessBoot string              `json:"process_boot"`
	Connection  protocol.Generation `json:"connection"`
	Blocked     bool                `json:"blocked"`
	Covered     bool                `json:"covered"`
}

func (t RoutingDrainTarget) Validate() error {
	return (routing.DrainTarget{Device: domain.DeviceID(t.DeviceID), Recovery: domain.RecoveryID(t.RecoveryID), Credential: t.Credential.credential(), ProcessBoot: t.ProcessBoot, Generation: domain.ConnectionGeneration{BootEpoch: domain.BootEpoch(t.Connection.BootEpoch), Counter: t.Connection.Counter}, Blocked: t.Blocked, Covered: t.Covered}).Validate()
}

type RoutingDrainInput struct {
	DeviceID               string              `json:"device_id"`
	RecoveryID             string              `json:"recovery_id"`
	ExpectedCredential     CredentialBinding   `json:"expected_credential"`
	ExpectedProcessBoot    string              `json:"expected_process_boot"`
	ExpectedConnection     protocol.Generation `json:"expected_connection"`
	Scope                  routing.DrainScope  `json:"scope"`
	PriorBoot              string              `json:"prior_boot,omitempty"`
	PriorCLIJoinsConfirmed *bool               `json:"prior_cli_joins_confirmed"`
}

func (i RoutingDrainInput) drain() routing.Drain {
	return routing.Drain{Device: domain.DeviceID(i.DeviceID), Recovery: domain.RecoveryID(i.RecoveryID), Credential: i.ExpectedCredential.credential(), CurrentBoot: i.ExpectedProcessBoot, Generation: domain.ConnectionGeneration{BootEpoch: domain.BootEpoch(i.ExpectedConnection.BootEpoch), Counter: i.ExpectedConnection.Counter}, Scope: i.Scope, PriorBoot: i.PriorBoot}
}

func (i RoutingDrainInput) Validate() error {
	if i.PriorCLIJoinsConfirmed == nil || !*i.PriorCLIJoinsConfirmed {
		return domain.ErrInvalid
	}
	return i.drain().ValidateBinding()
}

type RoutingDrainResponse struct {
	Committed        bool                     `json:"committed"`
	Disposition      routing.DrainDisposition `json:"disposition"`
	Target           RoutingDrainTarget       `json:"target"`
	ConnectionStatus ConnectionStatus         `json:"connection_status"`
}

func (r RoutingDrainResponse) Validate() error {
	if r.Target.Validate() != nil {
		return domain.ErrInvalid
	}
	switch r.Disposition {
	case routing.Drained:
		if r.Committed && (r.ConnectionStatus == ConnectionJoined || r.ConnectionStatus == ConnectionRetired) {
			return nil
		}
	case routing.AlreadySatisfied:
		if !r.Committed && r.ConnectionStatus == ConnectionUnchanged && r.Target.Covered && !r.Target.Blocked {
			return nil
		}
	}
	return domain.ErrInvalid
}
