package connector

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type scopedRequest struct {
	selection protocol.FileSelection
	scope     filesystemScope
}

func (a *Adapter) decodeOperationRoute(ctx context.Context, r request) (request, error) {
	if r.task.Validate(r.command.Operation == protocol.ResumeExisting || r.command.Operation == protocol.ResultChunk) != nil || r.command.Project != r.task.Origin.OperationID || r.task.Origin.GatewayID != string(r.config.GatewayID) {
		return request{}, ErrConflict
	}
	if r.task.Origin.Binding != "" && r.validateCompactIntent() != nil {
		return request{}, ErrEvidence
	}
	state, err := r.config.ProjectStore.Snapshot(ctx)
	if err != nil {
		return request{}, err
	}
	if !validRootSnapshot(state) || r.task.Context.Root != protocol.WireContextGuard(state.RootContext) {
		return request{}, ErrConflict
	}
	r.project = Project{Alias: r.command.Project, Root: state.RootDirectory, RootToken: state.RootContext}
	r.scoped = &scopedRequest{selection: r.task.Route.Selection}
	return r, nil
}

func (a *Adapter) decodeSelection(ctx context.Context, r request) (request, error) {
	state, err := r.config.ProjectStore.Snapshot(ctx)
	if err != nil {
		return request{}, err
	}
	if !validRootSnapshot(state) || r.command.Root != protocol.WireContextGuard(state.RootContext) {
		return request{}, ErrConflict
	}
	r.project = Project{Root: state.RootDirectory, RootToken: state.RootContext}
	r.scoped = &scopedRequest{selection: r.selection.Selection}
	return r, nil
}

func (a *Adapter) bindScopedProject(ctx context.Context, r request, owner *controlOwner) (request, error) {
	state, err := r.config.ProjectStore.Snapshot(ctx)
	if err != nil {
		return r, err
	}
	if !validRootSnapshot(state) || state.RootDirectory != r.project.Root || state.RootContext != r.project.RootToken {
		return r, ErrConflict
	}
	scope, err := selectFilesystemScope(state, r.scoped.selection.ScopeID)
	if err != nil {
		return r, err
	}
	if scope.Kind != "workspace" {
		directory, lookupErr := a.automaticScopeDirectory(ctx, r, owner, scope.Kind)
		if lookupErr != nil {
			return r, lookupErr
		}
		scope.Directory = directory
	}
	path, err := r.scoped.selection.Path()
	if err != nil {
		return r, ErrEvidence
	}
	copy := *r.scoped
	copy.scope = scope
	copy.selection.RelativePath = path
	r.scoped = &copy
	r.project.Directory = filepath.Join(scope.Directory, filepath.FromSlash(path))
	if scope.Kind != "workspace" {
		token, tokenErr := a.automaticScopeToken(ctx, r, owner)
		if tokenErr != nil {
			return r, tokenErr
		}
		r.scoped.scope.ExpectedWorkspace = token
	}
	if r.task.Route.Version == 1 && protocol.WireContextGuard(r.scoped.scope.ExpectedWorkspace) != r.task.Route.WorkspaceGuard {
		return r, ErrConflict
	}
	return r, nil
}

// Native supplies both the automatic scope path and its opaque path token.
// Inspect the approved root, then let Native resolve the selected child beneath
// that root. Inspecting a joined child would discard the scope constraint.
func (a *Adapter) automaticScopeToken(ctx context.Context, r request, owner *controlOwner) (string, error) {
	inspection := r
	copy := *r.scoped
	copy.selection.RelativePath = "."
	copy.selection.RelativePathBase64 = ""
	inspection.scoped = &copy
	inspection.project.Directory = copy.scope.Directory
	response, err := a.inspect(ctx, inspection, owner)
	if err != nil {
		return "", err
	}
	c := response.Connector
	if c == nil || c.ContractVersion != protocol.NativeContractVersion || c.RootToken != r.project.RootToken || !protocol.NativeFeaturesCompatible(c.Features) || c.WorkspaceConstraint != nil || !validNativeProjectToken(c.ProjectToken) {
		return "", ErrEvidence
	}
	if !slices.Contains(c.Features, protocol.FeaturePathProject) {
		return "", ErrUnsupported
	}
	return c.ProjectToken, nil
}

func (a *Adapter) automaticScopeDirectory(ctx context.Context, r request, owner *controlOwner, kind string) (string, error) {
	data, err := protocol.Encode(cliFilesystemRequest{ExpectedRoot: r.project.RootToken, Scope: filesystemScope{}}, 64<<10)
	if err != nil {
		return "", ErrEvidence
	}
	path, err := owner.file("automatic-scopes.json", data)
	if err != nil {
		return "", err
	}
	call, err := r.common(ctx, "filesystem", "scopes", "--request", path)
	if err != nil {
		return "", err
	}
	call.directory = owner.temporary
	response, err := a.run(ctx, call)
	if err != nil {
		return "", err
	}
	if response.exitCode != 0 || response.Filesystem == nil || response.Filesystem.Scopes == nil {
		return "", ErrEvidence
	}
	for _, scope := range response.Filesystem.Scopes.Scopes {
		if scope.Kind == kind && filepath.IsAbs(scope.Directory) && filepath.Clean(scope.Directory) == scope.Directory {
			return scope.Directory, nil
		}
	}
	return "", ErrUnsupported
}

func (r request) scopedStartGuard(ctx context.Context) (func() error, error) {
	lease, err := r.config.ProjectStore.Lock(ctx)
	if err != nil {
		return nil, err
	}
	state := lease.Snapshot()
	if state.RootDirectory != r.project.Root || state.RootContext != r.project.RootToken {
		return nil, errors.Join(ErrConflict, lease.Close())
	}
	current, err := selectFilesystemScope(state, r.scoped.selection.ScopeID)
	if err == nil && current.Kind == "workspace" && current != r.scoped.scope {
		err = ErrConflict
	}
	if err != nil {
		return nil, errors.Join(err, lease.Close())
	}
	return lease.Close, nil
}

func requireRouteFeatures(features []string, filesystem bool) error {
	for _, feature := range []string{protocol.FeatureNativeOptions, protocol.FeatureProjectHashGuard} {
		if !slices.Contains(features, feature) {
			return ErrUnsupported
		}
	}
	if filesystem && !slices.Contains(features, protocol.FeatureFilesystem) {
		return ErrUnsupported
	}
	return nil
}

func (a *Adapter) executeRouted(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	if (r.command.Operation == protocol.Admit || r.command.Operation == protocol.ResumeExisting) && r.task.Origin.Binding == "" {
		// Native owns the prerequisite durable binding of the complete new intent.
		// Legacy receipts cannot authorize a Route1 execution or recovery.
		return protocol.Reply{Operation: r.command.Operation, Error: &protocol.Failure{Code: "delegate_upgrade_required", Stage: "admission"}}
	}
	root, err := a.verifiedRoot(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if err = requireRouteFeatures(root.Features, false); err != nil {
		return failed(r.command.Operation, err)
	}
	if r.task.Origin.Binding != "" && !slices.Contains(root.Features, protocol.FeatureOriginBinding) {
		return failed(r.command.Operation, ErrUnsupported)
	}
	if taskControl(r.command.Operation) {
		return a.executeTaskControl(ctx, r, owner)
	}
	return a.executeRoutedExecution(ctx, r, owner, root)
}

func (a *Adapter) executeRoutedExecution(ctx context.Context, r request, owner *controlOwner, root protocol.RootCapability) protocol.Reply {
	if r.command.Operation != protocol.Admit && r.command.Operation != protocol.Continue && r.command.Operation != protocol.ResumeExisting {
		return failed(r.command.Operation, ErrEvidence)
	}
	if r.command.Operation == protocol.Continue && !slices.Contains(root.Features, protocol.FeatureGuardedContinuation) {
		return failed(r.command.Operation, ErrUnsupported)
	}
	if !r.executionBudgetSupported(root.Features) {
		return failed(r.command.Operation, ErrUnsupported)
	}
	if a.Status().CleanupPending != 0 {
		return failed(r.command.Operation, ErrPending)
	}
	if r.command.Operation == protocol.ResumeExisting {
		// Recovery uses the canonical receipt's saved tokens. Its old approval
		// may be gone; Native alone decides existing-only recovery eligibility.
		if !root.OriginRegistered || root.Origin == nil || !root.Origin.AdmissionOpen {
			return failed(r.command.Operation, ErrConfiguration)
		}
		return a.resume(ctx, r, owner)
	}
	r, probe, err := a.bindRoutedProject(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if !originOpen(r, probe) {
		return failed(r.command.Operation, ErrConfiguration)
	}
	return a.invokeReply(ctx, r, owner)
}

func (a *Adapter) bindRoutedProject(ctx context.Context, r request, owner *controlOwner) (request, cliResponse, error) {
	r, err := a.bindScopedProject(ctx, r, owner)
	if err != nil {
		return r, cliResponse{}, err
	}
	probe, err := a.inspect(ctx, r, owner)
	if err != nil {
		return r, probe, err
	}
	if probe.Connector == nil || !r.matchesProjectToken(probe.Connector.ProjectToken) {
		return r, probe, ErrConflict
	}
	r.project.ProjectToken = probe.Connector.ProjectToken
	if !compatible(r, probe) {
		return r, probe, ErrEvidence
	}
	return r, probe, nil
}

func (a *Adapter) selectProject(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	root, err := a.verifiedRoot(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if err = requireRouteFeatures(root.Features, true); err != nil {
		return failed(r.command.Operation, err)
	}
	r, err = a.bindScopedProject(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	probe, err := a.inspect(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	c := probe.Connector
	if c == nil || c.RootToken != r.project.RootToken || !validNativeProjectToken(c.ProjectToken) || !protocol.NativeFeaturesCompatible(c.Features) || !r.matchesSelectedWorkspace(c.WorkspaceConstraint) {
		return failed(r.command.Operation, ErrEvidence)
	}
	providers, err := a.providerCatalog(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	result, err := selectionObservation(r, c, providers, a.now())
	if err != nil {
		return failed(r.command.Operation, err)
	}
	return a.publishMetadata(ctx, r, result)
}

func (r request) matchesSelectedWorkspace(constraint *workspaceConstraint) bool {
	if r.scoped.scope.ExpectedWorkspace == "" {
		return constraint == nil
	}
	return constraint != nil && constraint.Token == r.scoped.scope.ExpectedWorkspace && constraint.RelativeProject == r.scoped.selection.RelativePath
}

func selectionObservation(r request, c *cliConnector, providers []protocol.NativeProviderCapability, now time.Time) (protocol.SelectionObservation, error) {
	result := protocol.SelectionObservation{Selection: r.selection.Selection, Context: protocol.ContextBinding{Root: protocol.WireContextGuard(c.RootToken), Project: protocol.WireContextGuard(c.ProjectToken)}, Providers: providers, Features: protocol.RecognizedNativeFeatures(c.Features), ObservedAt: now}
	result.WorkspaceGuard = protocol.WireContextGuard(r.scoped.scope.ExpectedWorkspace)
	if c.OriginBarrier != nil {
		result.AdmissionGeneration = c.OriginBarrier.Generation
		result.AdmissionOpen = c.OriginBarrier.AdmissionOpen
	}
	if result.ValidateFor(*r.selection) != nil {
		return result, ErrEvidence
	}
	return result, nil
}

func (r request) executionBudgetSupported(features []string) bool {
	var budget string
	if r.command.Operation == protocol.Continue {
		budget = r.continuation.Overrides.Budget
	} else if r.admission != nil {
		budget = r.admission.Native.Budget
	}
	return budget != "unlimited" || slices.Contains(features, protocol.FeatureExecutionBudget)
}
