package workspaces

import (
	"context"
	"errors"
	"slices"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// InventoryObservation retains a source only for newly requested temporary
// scopes. Workspace-only and offline inventory remain dated peer metadata.
type InventoryObservation struct {
	Value  Inventory
	Source *gateway.MetadataSource
}

// ListWorkspaces projects the bounded current transport report. It never lists
// local paths or claims that an advertised workspace can execute a task.
func (s *Service) ListWorkspaces(ctx context.Context, actor domain.Actor, device domain.DeviceID) (Inventory, error) {
	observed, err := s.ObserveWorkspaces(ctx, actor, device)
	return observed.Value, err
}

func (s *Service) ObserveWorkspaces(ctx context.Context, actor domain.Actor, device domain.DeviceID) (InventoryObservation, error) {
	authority, err := s.options.Store.AuthorizeOwnedDevice(ctx, domain.OwnedDeviceRequest{Actor: actor, Device: device, Scope: domain.InventoryRead})
	if err != nil {
		return InventoryObservation{}, err
	}
	result := Inventory{Device: device, Workspaces: []protocol.WorkspaceCapability{}, Scopes: []protocol.FilesystemScope{}}
	var source *gateway.MetadataSource
	snapshot, err := s.snapshot(device)
	if err != nil {
		if !soleDeviceOffline(err) {
			return InventoryObservation{}, err
		}
	} else {
		result = liveInventory(device, snapshot)
		if canDiscoverTemporary(snapshot, actor.Scopes, authority.Policy.Scopes) {
			original := binding(snapshot, domain.RootGuard(snapshot.CapabilitiesV2.Root.Root))
			if source, err = s.appendTemporaryScopes(ctx, actor, original, &result); err != nil {
				if parentErr := ctx.Err(); parentErr != nil {
					return InventoryObservation{}, parentErr
				}
				result.ScopeDiscoveryError = scopeDiscoveryFailure(err)
			}
		}
	}
	if source == nil {
		if err = s.authorize(ctx, actor, device, domain.InventoryRead); err != nil {
			return InventoryObservation{}, err
		}
	}
	if err = ctx.Err(); err != nil {
		return InventoryObservation{}, err
	}
	return InventoryObservation{Value: result, Source: source}, nil
}

func soleDeviceOffline(err error) bool {
	var offline *gateway.RemoteError
	return errors.As(gateway.SoleError(err), &offline) && offline != nil && offline.Failure.Code == "device_offline"
}

func liveInventory(device domain.DeviceID, snapshot gateway.LinkSnapshot) Inventory {
	result := Inventory{Device: device, Online: true, DelegateReady: snapshot.CapabilitiesV2.Root != nil, ObservedAt: snapshot.ObservedAt, Workspaces: append([]protocol.WorkspaceCapability{}, snapshot.CapabilitiesV2.Workspaces...), Scopes: []protocol.FilesystemScope{}}
	for _, workspace := range result.Workspaces {
		result.Scopes = append(result.Scopes, protocol.FilesystemScope{ID: workspace.ID, Name: workspace.Name, Kind: "workspace"})
	}
	if snapshot.CapabilitiesV2.ProjectBudget != nil {
		budget := *snapshot.CapabilitiesV2.ProjectBudget
		result.ProjectBudget = &budget
	}
	return result
}

func canDiscoverTemporary(snapshot gateway.LinkSnapshot, token, allowed domain.ScopeSet) bool {
	root := snapshot.CapabilitiesV2.Root
	return root != nil && slices.Contains(root.Features, protocol.FeatureFilesystem) && token.Has(domain.TaskDispatch) && token.Has(domain.TaskRead) && allowed.Has(domain.TaskDispatch) && allowed.Has(domain.TaskRead)
}

func (s *Service) appendTemporaryScopes(ctx context.Context, actor domain.Actor, original domain.OwnedRootBinding, result *Inventory) (*gateway.MetadataSource, error) {
	temporary, err := s.ObserveFilesystem(ctx, actor, result.Device, protocol.FilesystemScopes, protocol.FilesystemRequest{})
	if err != nil {
		return nil, err
	}
	if temporary.Source.Binding != original {
		return nil, domain.Reject(domain.Conflict)
	}
	if err = s.CheckMetadataObservation(ctx, actor, temporary.Source, domain.ScopeSet{domain.InventoryRead}); err != nil {
		return nil, err
	}
	result.Scopes = append(result.Scopes, temporary.Value.Scopes.Scopes...)
	return &temporary.Source, nil
}

// Discovery failure is optional inventory metadata. Only closed public codes
// survive; raw transport, storage, body and path diagnostics never enter it.
func scopeDiscoveryFailure(err error) string {
	cause := gateway.SoleError(err)
	var remote *gateway.RemoteError
	if errors.As(cause, &remote) && remote != nil && remote.Failure.Validate() == nil {
		return remote.Failure.Code
	}
	var policy *domain.Error
	if errors.As(cause, &policy) && policy != nil && (protocol.Failure{Code: string(policy.Code)}).Validate() == nil {
		return string(policy.Code)
	}
	if errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled) {
		return "timeout"
	}
	return "scope_discovery_failed"
}
