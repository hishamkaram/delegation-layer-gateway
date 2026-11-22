package mcpadapter

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (a *Adapter) registerWorkspaceTools() error {
	if a.options.Workspaces == nil {
		return nil
	}
	return errors.Join(
		register(a, "list_workspaces", "List approved workspace scopes and automatic system temporary scopes on the explicit owned device. Use returned scope IDs with list_directory/read_file and task selection. Whole temporary scopes need no manual approval. Inventory-only callers receive workspace metadata; file access requires dispatch and read authority.", []domain.Scope{domain.InventoryRead}, toolHints{ReadOnly: true, Idempotent: true}, a.workspaces),
		register(a, "resolve_project", "Legacy compatibility: retain an immutable project_alias for an existing directory within an approved workspace. Reuse the same pin request_id and selection; legacy pins retain their bounded storage contract. New work uses scope selection directly with get_capabilities and prepare_dispatch, without a permanent pin. Starts no task.", []domain.Scope{domain.TaskDispatch}, toolHints{Idempotent: true}, a.resolveProject),
	)
}

func (a *Adapter) workspaces(ctx context.Context, actor domain.Actor, input WorkspacesInput) (WorkspaceInventory, error) {
	observed, err := a.options.Workspaces.ObserveWorkspaces(ctx, actor, domain.DeviceID(input.DeviceID))
	if err != nil {
		return WorkspaceInventory{}, err
	}
	inventory := observed.Value
	if inventory.Device != domain.DeviceID(input.DeviceID) {
		return WorkspaceInventory{}, domain.Reject(domain.EvidenceInvalid)
	}
	if err = validateInventorySource(inventory, observed.Source); err != nil {
		return WorkspaceInventory{}, err
	}
	result := WorkspaceInventory{Scopes: inventory.Scopes, ScopeDiscoveryError: inventory.ScopeDiscoveryError, DeviceID: string(inventory.Device), Online: inventory.Online, DelegateReady: inventory.DelegateReady, Workspaces: inventory.Workspaces, ProjectBudget: inventory.ProjectBudget}
	if observed.Source != nil {
		source := *observed.Source
		result.metadataSource = &source
	}
	if !inventory.ObservedAt.IsZero() {
		result.ObservedAt = &inventory.ObservedAt
	}
	return result, nil
}

func validateInventorySource(inventory workspaces.Inventory, source *gateway.MetadataSource) error {
	if source != nil {
		if !metadataSourceMatches(*source, inventory.Device, protocol.FilesystemScopes) {
			return domain.Reject(domain.EvidenceInvalid)
		}
		return nil
	}
	for _, scope := range inventory.Scopes {
		if scope.Kind != "workspace" {
			return domain.Reject(domain.EvidenceInvalid)
		}
	}
	return nil
}

func (o WorkspaceInventory) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	if o.metadataSource == nil {
		return nil // Workspace-only and offline inventory remain dated metadata.
	}
	return a.options.Workspaces.CheckMetadataObservation(ctx, actor, *o.metadataSource, domain.ScopeSet{domain.InventoryRead})
}

func (i WorkspacesInput) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	_, err := a.options.Registry.AuthorizeOwnedDevice(ctx, domain.OwnedDeviceRequest{Actor: actor, Device: domain.DeviceID(i.DeviceID), Scope: domain.InventoryRead})
	return err
}

func (a *Adapter) resolveProject(ctx context.Context, actor domain.Actor, input ResolveProjectInput) (ResolvedProject, error) {
	request := input.request()
	if request.Validate() != nil || domain.CredentialToken(input.DeviceID) != nil {
		return ResolvedProject{}, domain.ErrInvalid
	}
	resolution, err := a.options.Workspaces.ResolveProject(ctx, actor, workspaces.ResolveInput{Device: domain.DeviceID(input.DeviceID), Request: request})
	if err != nil {
		return ResolvedProject{}, err
	}
	pin := resolution.Project
	return ResolvedProject{DeviceID: string(resolution.Device), RequestID: string(resolution.Request), ProjectAlias: string(pin.Handle), Workspace: protocol.WorkspaceBinding{ID: pin.Workspace.ID, Guard: pin.Workspace.Guard}, Context: protocol.ContextBinding{Root: string(pin.Context.Root), Project: string(pin.Context.Project)}}, nil
}

func (i ResolveProjectInput) request() protocol.ResolveProjectRequest {
	return protocol.ResolveProjectRequest{RequestID: i.RequestID, WorkspaceID: i.WorkspaceID, RelativePath: i.RelativePath}
}

func (i ResolveProjectInput) retainedRequestID() string {
	if i.request().Validate() != nil || domain.CredentialToken(i.DeviceID) != nil {
		return ""
	}
	return i.RequestID
}
