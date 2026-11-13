package workspaces

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// ListWorkspaces projects the bounded current transport report. It never lists
// local paths or claims that an advertised workspace can execute a task.
func (s *Service) ListWorkspaces(ctx context.Context, actor domain.Actor, device domain.DeviceID) (Inventory, error) {
	if err := s.authorize(ctx, actor, device, domain.InventoryRead); err != nil {
		return Inventory{}, err
	}
	result := Inventory{Device: device, Workspaces: []protocol.WorkspaceCapability{}}
	snapshot, err := s.snapshot(device)
	if err != nil {
		var offline *gateway.RemoteError
		if !errors.As(gateway.SoleError(err), &offline) || offline == nil || offline.Failure.Code != "device_offline" {
			return Inventory{}, err
		}
	} else {
		result.Online = true
		result.DelegateReady = snapshot.CapabilitiesV2.Root != nil
		result.ObservedAt = snapshot.ObservedAt
		result.Workspaces = append(result.Workspaces, snapshot.CapabilitiesV2.Workspaces...)
		if snapshot.CapabilitiesV2.ProjectBudget != nil {
			budget := *snapshot.CapabilitiesV2.ProjectBudget
			result.ProjectBudget = &budget
		}
	}
	if err = s.authorize(ctx, actor, device, domain.InventoryRead); err != nil {
		return Inventory{}, err
	}
	if err = ctx.Err(); err != nil {
		return Inventory{}, err
	}
	return result, nil
}
