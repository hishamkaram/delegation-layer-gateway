package mcpadapter

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (a *Adapter) registerWorkspaceTools() error {
	if a.options.Workspaces == nil {
		return nil
	}
	return errors.Join(
		register(a, "list_workspaces", "List bounded dated approved workspaces on the explicit owned device. Names and policy revisions are observations; no local paths or execution readiness are returned.", []domain.Scope{domain.InventoryRead}, toolHints{ReadOnly: true, Idempotent: true}, a.workspaces),
		register(a, "resolve_project", "Pin an existing directory within an approved workspace on the explicit owned device. Retain request_id; retries must keep the same selection. Starts no task. Use returned project_alias for get_capabilities and prepare_dispatch; this immutable identity is not a readiness claim.", []domain.Scope{domain.TaskDispatch}, toolHints{Idempotent: true}, a.resolveProject),
	)
}

func (a *Adapter) workspaces(ctx context.Context, actor domain.Actor, input WorkspacesInput) (WorkspaceInventory, error) {
	inventory, err := a.options.Workspaces.ListWorkspaces(ctx, actor, domain.DeviceID(input.DeviceID))
	if err != nil {
		return WorkspaceInventory{}, err
	}
	result := WorkspaceInventory{DeviceID: string(inventory.Device), Online: inventory.Online, DelegateReady: inventory.DelegateReady, Workspaces: inventory.Workspaces, ProjectBudget: inventory.ProjectBudget}
	if !inventory.ObservedAt.IsZero() {
		result.ObservedAt = &inventory.ObservedAt
	}
	return result, nil
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
