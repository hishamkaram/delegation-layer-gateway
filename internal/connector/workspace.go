package connector

import (
	"context"
	"errors"
	"path/filepath"
	"slices"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type workspaceRequest struct {
	pin    ProjectPin
	policy WorkspacePolicy
}

func (a *Adapter) decodeRequest(ctx context.Context, cfg *configuration, command protocol.Command) (request, error) {
	if cfg.ProjectStore == nil {
		return decodeRequest(cfg, command)
	}
	if command.ValidateVersion(protocol.WireVersion2) != nil {
		return request{}, ErrEvidence
	}
	r := request{command: command, config: cfg}
	if command.Operation == protocol.ResolveProject {
		var body protocol.ResolveProjectRequest
		if protocol.DecodeStrict(command.Body, &body, protocol.MaxFrameBytes) != nil || body.Validate() != nil {
			return request{}, ErrEvidence
		}
		r.resolution = &body
		return r, nil
	}
	if command.Root != "" {
		return a.decodeRoot(ctx, r)
	}
	return a.decodePinned(ctx, r)
}

func (a *Adapter) decodeRoot(ctx context.Context, r request) (request, error) {
	snapshot, err := r.config.ProjectStore.Snapshot(ctx)
	if err != nil {
		return request{}, err
	}
	if !validRootSnapshot(snapshot) || r.command.Root != protocol.WireContextGuard(snapshot.RootContext) {
		return request{}, ErrConflict
	}
	r.project = Project{Root: snapshot.RootDirectory, RootToken: snapshot.RootContext}
	if err = r.decodeBody(); err != nil {
		return request{}, err
	}
	if r.command.Operation == protocol.ContextInspect && !r.rootOnly {
		return request{}, ErrConflict
	}
	return r, nil
}

func (a *Adapter) decodePinned(ctx context.Context, r request) (request, error) {
	pin, err := r.config.ProjectStore.LookupPin(ctx, r.command.Project)
	if err != nil {
		return request{}, err
	}
	if pin.Validate() != nil {
		return request{}, ErrEvidence
	}
	r.project = pin.Project
	r.workspace = &workspaceRequest{pin: pin}
	if err = r.decodeBody(); err != nil {
		return request{}, err
	}
	if r.command.Operation == protocol.ContextInspect {
		if r.rootOnly {
			return request{}, ErrConflict
		}
		if err = r.readCurrentPolicy(ctx); err != nil {
			return request{}, err
		}
		return r, nil
	}
	if r.task.Validate(r.command.Operation == protocol.ResumeExisting || r.command.Operation == protocol.ResultChunk) != nil || r.task.Context != pin.Project.wireContext() || r.task.Origin.GatewayID != string(r.config.GatewayID) {
		return request{}, ErrConflict
	}
	if r.command.Operation == protocol.Admit || r.command.Operation == protocol.ResumeExisting {
		if err = r.readCurrentPolicy(ctx); err != nil {
			return request{}, err
		}
		if !r.workspace.policy.Enabled {
			return request{}, ErrConflict
		}
	}
	return r, nil
}

func validRootSnapshot(value WorkspaceSnapshot) bool {
	return filepath.IsAbs(value.RootDirectory) && filepath.Clean(value.RootDirectory) == value.RootDirectory && digest(value.RootContext)
}

func (r *request) readCurrentPolicy(ctx context.Context) error {
	state, err := r.config.ProjectStore.Snapshot(ctx)
	if err != nil {
		return err
	}
	if state.RootDirectory != r.project.Root || state.RootContext != r.project.RootToken {
		return ErrConflict
	}
	for _, workspace := range state.Workspaces {
		if workspace.ID == r.workspace.pin.Request.WorkspaceID && workspace.NativeContext == r.workspace.pin.WorkspaceContext {
			r.workspace.policy = workspace
			if workspace.Enabled {
				r.project.Providers = clonePolicies(workspace.Providers)
			}
			return nil
		}
	}
	return ErrConflict
}

func (r request) matchesWorkspace(value *workspaceConstraint) bool {
	if r.workspace == nil {
		return value == nil
	}
	return value != nil && value.Token == r.workspace.pin.WorkspaceContext && value.RelativeProject == r.workspace.pin.Request.RelativePath
}

// The lease serializes the current local ceiling with CLI Start. Native still
// owns guarded admission; the lease never spans Wait or a task's execution.
func (r request) startGuard(ctx context.Context) (func() error, error) {
	lease, err := r.config.ProjectStore.Lock(ctx)
	if err != nil {
		return nil, err
	}
	if err = r.checkStartPolicy(lease); err != nil {
		return nil, errors.Join(err, lease.Close())
	}
	return lease.Close, nil
}

func (r request) checkStartPolicy(lease WorkspaceLease) error {
	state := lease.Snapshot()
	if state.RootDirectory != r.project.Root || state.RootContext != r.project.RootToken {
		return ErrConflict
	}
	current, err := lease.CurrentWorkspace(r.workspace.pin.Request.WorkspaceID)
	if err != nil {
		return err
	}
	if !current.Enabled || current.NativeContext != r.workspace.pin.WorkspaceContext {
		return ErrConflict
	}
	options := r.startOptions
	if r.admission != nil {
		value := admissionOptions(*r.admission)
		options = &value
	}
	if options == nil {
		return ErrEvidence
	}
	r.project.Providers = current.Providers
	if !r.optionsAllowed(*options) {
		return ErrConflict
	}
	return nil
}

func (a *Adapter) resolveProject(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	if pin, found, err := r.config.ProjectStore.LookupResolution(ctx, *r.resolution); err != nil {
		return failed(r.command.Operation, err)
	} else if found {
		return resolvedReply(r, pin)
	}
	lease, err := r.config.ProjectStore.Lock(ctx)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	state := lease.Snapshot()
	workspace, policyErr := lease.CurrentWorkspace(r.resolution.WorkspaceID)
	closeErr := lease.Close()
	if err = errors.Join(policyErr, closeErr); err != nil {
		return failed(r.command.Operation, err)
	}
	if !workspace.Enabled || !validRootSnapshot(state) || r.command.Root != protocol.WireContextGuard(state.RootContext) {
		return failed(r.command.Operation, ErrConflict)
	}
	return a.inspectResolution(ctx, r, owner, state, workspace)
}

func (a *Adapter) inspectResolution(ctx context.Context, r request, owner *controlOwner, state WorkspaceSnapshot, workspace WorkspacePolicy) protocol.Reply {
	pin := ProjectPin{Request: *r.resolution, WorkspaceContext: workspace.NativeContext, Project: Project{Alias: r.resolution.RequestID, Root: state.RootDirectory, RootToken: state.RootContext, Directory: filepath.Join(workspace.Directory, filepath.FromSlash(r.resolution.RelativePath))}}
	inspection := r
	inspection.command.Operation = protocol.ContextInspect
	inspection.project = pin.Project
	inspection.workspace = &workspaceRequest{pin: pin, policy: workspace}
	response, err := a.inspect(ctx, inspection, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	c := response.Connector
	if c == nil || c.ContractVersion != protocol.NativeContractVersion || c.RootToken != state.RootContext || !protocol.NativeFeaturesCompatible(c.Features) || !slices.Contains(c.Features, protocol.WorkspaceFeature) || !inspection.matchesWorkspace(c.WorkspaceConstraint) || !validNativeProjectToken(c.ProjectToken) {
		return failed(r.command.Operation, ErrEvidence)
	}
	pin.Project.ProjectToken = c.ProjectToken
	lease, err := r.config.ProjectStore.Lock(ctx)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	committed, commitErr := lease.CommitResolution(pin)
	if err = errors.Join(commitErr, lease.Close()); err != nil {
		return failed(r.command.Operation, err)
	}
	return resolvedReply(r, committed)
}

func resolvedReply(r request, pin ProjectPin) protocol.Reply {
	if pin.Validate() != nil || pin.Request != *r.resolution || r.command.Root != pin.WireIdentity().Context.Root {
		return failed(r.command.Operation, ErrConflict)
	}
	return bodyReply(r.command.Operation, protocol.ResolveProjectReply{RequestID: pin.Request.RequestID, RelativePathSHA256: briefHash(pin.Request.RelativePath), Project: pin.WireIdentity()})
}
