package adminapi

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func drainTarget(t routing.DrainTarget) RoutingDrainTarget {
	return RoutingDrainTarget{DeviceID: string(t.Device), RecoveryID: string(t.Recovery), Credential: CredentialBinding{DeviceID: string(t.Credential.Device), Epoch: string(t.Credential.Epoch), Generation: t.Credential.Generation}, ProcessBoot: t.ProcessBoot, Connection: protocol.Generation{BootEpoch: string(t.Generation.BootEpoch), Counter: t.Generation.Counter}, Blocked: t.Blocked, Covered: t.Covered}
}

func (h *Handler) routingDrainTarget(ctx context.Context, input RoutingTargetInput) (RoutingDrainTarget, error) {
	if err := input.Validate(); err != nil {
		return RoutingDrainTarget{}, err
	}
	if h.options.RoutingDrains == nil {
		return RoutingDrainTarget{}, domain.Reject(domain.Pending)
	}
	target, err := h.options.RoutingDrains.ReadRoutingDrainTarget(ctx, domain.DeviceID(input.DeviceID), h.options.Now())
	if err != nil {
		return RoutingDrainTarget{}, err
	}
	output := drainTarget(target)
	if output.Validate() != nil || output.DeviceID != input.DeviceID {
		return RoutingDrainTarget{}, domain.Reject(domain.EvidenceInvalid)
	}
	return output, nil
}

func (h *Handler) drainRouting(ctx context.Context, input RoutingDrainInput) (RoutingDrainResponse, error) {
	if err := input.Validate(); err != nil {
		return RoutingDrainResponse{}, err
	}
	if h.options.RoutingDrains == nil || h.options.GenerationDisconnector == nil {
		return RoutingDrainResponse{}, domain.Reject(domain.Pending)
	}
	drain := input.drain()
	drain.Now = h.options.Now()
	result, err := h.options.RoutingDrains.AttestRoutingDrained(ctx, drain)
	if err != nil {
		return RoutingDrainResponse{}, err
	}
	output := RoutingDrainResponse{Committed: result.Disposition == routing.Drained, Disposition: result.Disposition, Target: drainTarget(result.Target), ConnectionStatus: ConnectionUnchanged}
	switch result.Disposition {
	case routing.AlreadySatisfied:
		if output.Validate() != nil {
			return RoutingDrainResponse{}, domain.Reject(domain.EvidenceInvalid)
		}
	case routing.Drained:
		status, closeErr := h.options.GenerationDisconnector.DisconnectGeneration(ctx, drain.Credential, drain.Generation)
		if closeErr != nil {
			return RoutingDrainResponse{}, fail("disconnect_unconfirmed", closeErr)
		}
		output.ConnectionStatus = status
		if output.Validate() != nil {
			return RoutingDrainResponse{}, fail("disconnect_unconfirmed", domain.Reject(domain.EvidenceInvalid))
		}
	default:
		return RoutingDrainResponse{}, domain.Reject(domain.EvidenceInvalid)
	}
	return output, nil
}
