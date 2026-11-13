package workspaces

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func (s *Service) ResolveProject(ctx context.Context, actor domain.Actor, input ResolveInput) (result Resolution, err error) {
	if input.Request.Validate() != nil || domain.CredentialToken(string(input.Device)) != nil {
		return result, domain.ErrInvalid
	}
	if err = s.authorize(ctx, actor, input.Device, domain.TaskDispatch); err != nil {
		s.options.Controls.ObserveAuthorizationFailure(actor, protocol.ResolveProject, err)
		return result, err
	}
	resolution, found, err := s.lookup(ctx, actor, input)
	if err != nil {
		return result, err
	}
	if found && resolution.Pin != nil && resolution.Registered {
		return resolved(resolution), ctx.Err()
	}
	resolution, current, err := s.begin(ctx, actor, input, resolution, found)
	if err != nil {
		return result, err
	}
	if resolution.Pin == nil {
		if err = s.initialize(ctx, current); err != nil {
			return result, err
		}
		resolution, err = s.pin(ctx, actor, input.Request, resolution, current)
		if err != nil {
			return result, err
		}
	}
	return s.register(ctx, actor, resolution)
}

// lookup freezes comparison against Registry authority before examining the
// current transport cache. A completed pin does not depend on availability.
func (s *Service) lookup(ctx context.Context, actor domain.Actor, input ResolveInput) (domain.ProjectResolution, bool, error) {
	id := domain.ResolutionID(input.Request.RequestID)
	resolution, found, err := s.options.Store.LookupProjectResolution(ctx, actor, input.Device, id)
	if err != nil || !found {
		return resolution, found, err
	}
	if resolution.Validate() != nil || resolution.Request != id || resolution.Principal != actor.Principal || resolution.Device != input.Device {
		return resolution, found, domain.Reject(domain.EvidenceInvalid)
	}
	if resolution.Workspace.ID != input.Request.WorkspaceID || resolution.SelectorDigest != domain.Hash([]byte(input.Request.RelativePath)) {
		return resolution, found, domain.Reject(domain.Conflict)
	}
	return resolution, found, nil
}

func (s *Service) begin(ctx context.Context, actor domain.Actor, input ResolveInput, saved domain.ProjectResolution, found bool) (domain.ProjectResolution, domain.OwnedRootBinding, error) {
	snapshot, err := s.snapshot(input.Device)
	if err != nil {
		return saved, domain.OwnedRootBinding{}, err
	}
	if snapshot.CapabilitiesV2.Root == nil {
		return saved, domain.OwnedRootBinding{}, &gateway.RemoteError{Failure: protocol.Failure{Code: "device_not_ready", Retryable: true}}
	}
	root := domain.RootGuard(snapshot.CapabilitiesV2.Root.Root)
	current := binding(snapshot, root)
	if found {
		if saved.Root != root {
			return saved, current, domain.Reject(domain.Conflict)
		}
		return saved, current, nil
	}
	workspace, err := selectWorkspace(snapshot.CapabilitiesV2, input.Request.WorkspaceID)
	if err != nil {
		return saved, current, err
	}
	saved, err = s.options.Store.BeginProjectResolution(ctx, actor, domain.ProjectResolutionStart{Request: domain.ResolutionID(input.Request.RequestID), Binding: current, Workspace: workspace, SelectorDigest: domain.Hash([]byte(input.Request.RelativePath)), Now: s.options.Now()})
	return saved, current, err
}

func (s *Service) register(ctx context.Context, actor domain.Actor, resolution domain.ProjectResolution) (Resolution, error) {
	// A reconnect can win while the reply is being saved. Registration still
	// targets the same explicit device/root and checks its current generation.
	latest, err := s.snapshot(resolution.Device)
	if err != nil {
		return Resolution{}, err
	}
	if latest.CapabilitiesV2.Root == nil || latest.CapabilitiesV2.Root.Root != string(resolution.Root) {
		return Resolution{}, domain.Reject(domain.Conflict)
	}
	resolution, err = s.options.Store.RegisterResolvedProject(ctx, actor, domain.ProjectResolutionCheck{Request: resolution.Request, Binding: binding(latest, resolution.Root), Now: s.options.Now()})
	if err != nil {
		return Resolution{}, err
	}
	if !resolution.Registered || resolution.Pin == nil {
		return Resolution{}, domain.Reject(domain.EvidenceInvalid)
	}
	return resolved(resolution), ctx.Err()
}

func resolved(value domain.ProjectResolution) Resolution {
	return Resolution{Device: value.Device, Request: value.Request, Project: *value.Pin}
}

func selectWorkspace(report *protocol.CapabilityReportV2, id string) (domain.WorkspaceBinding, error) {
	if report.ProjectBudget != nil && (report.ProjectBudget.Used == report.ProjectBudget.Limit || report.ProjectBudget.BytesUsed == report.ProjectBudget.ByteLimit) {
		return domain.WorkspaceBinding{}, domain.Reject(domain.ResourceLimit)
	}
	for _, workspace := range report.Workspaces {
		if workspace.ID == id {
			return domain.WorkspaceBinding{ID: workspace.ID, Guard: workspace.Guard}, nil
		}
	}
	return domain.WorkspaceBinding{}, domain.Reject(domain.NotFound)
}

func (s *Service) initialize(ctx context.Context, current domain.OwnedRootBinding) error {
	initializer, err := s.options.Roots(ctx, current)
	if err != nil {
		return err
	}
	if initializer == nil {
		return domain.ErrInvalid
	}
	for range 4 {
		if err = ctx.Err(); err != nil {
			return err
		}
		progress, advanceErr := initializer.Advance(ctx)
		if advanceErr != nil {
			return advanceErr
		}
		if progress.Stage == domain.RootReady {
			return nil
		}
	}
	return domain.Reject(domain.Pending)
}

func (s *Service) pin(ctx context.Context, actor domain.Actor, request protocol.ResolveProjectRequest, resolution domain.ProjectResolution, current domain.OwnedRootBinding) (domain.ProjectResolution, error) {
	body, err := protocol.Encode(request, 64<<10)
	if err != nil {
		return domain.ProjectResolution{}, err
	}
	var pin domain.ProjectPin
	_, tx, err := s.options.Controls.Exchange(ctx, gateway.MetadataCall{
		Actor: actor, Device: resolution.Device, Operation: domain.OperationID(resolution.Request), Scope: domain.TaskDispatch,
		Command: protocol.Command{Operation: protocol.ResolveProject, Root: string(resolution.Root), Body: body},
		Authorize: func(call context.Context) error {
			return s.options.Store.CheckProjectResolution(call, actor, domain.ProjectResolutionCheck{Request: resolution.Request, Binding: current, Now: s.options.Now()}, domain.TaskDispatch)
		},
		Acquire: func(call context.Context, input routing.Request) error {
			return s.options.Store.AcquireProjectMetadata(call, actor, resolution.Request, domain.TaskDispatch, input)
		},
		Check: func(call context.Context, tx domain.Transmission) error {
			return s.check(call, actor, resolution.Request, resolution.Root, tx, domain.TaskDispatch)
		},
		Validate: func(reply protocol.Reply, _ domain.Transmission) error {
			var response protocol.ResolveProjectReply
			if protocol.DecodeStrict(reply.Body, &response, 64<<10) != nil || response.ValidateFor(request) != nil {
				return domain.Reject(domain.EvidenceInvalid)
			}
			pin = fromWire(response.Project)
			if pin.Workspace != resolution.Workspace || pin.Context.Root != resolution.Root {
				return domain.Reject(domain.EvidenceInvalid)
			}
			return nil
		},
	})
	if err != nil {
		return domain.ProjectResolution{}, err
	}
	current.Credential, current.Connection = tx.Credential, tx.Connection
	return s.options.Store.RecordProjectResolutionPin(ctx, actor, domain.ProjectResolutionPin{Request: resolution.Request, Binding: current, Pin: pin, Now: s.options.Now()})
}

func fromWire(pin protocol.ResolvedProject) domain.ProjectPin {
	return domain.ProjectPin{Handle: domain.ProjectAlias(pin.Handle), Workspace: domain.WorkspaceBinding{ID: pin.Workspace.ID, Guard: pin.Workspace.Guard}, Context: domain.ContextBinding{Root: domain.RootGuard(pin.Context.Root), Project: domain.ProjectGuard(pin.Context.Project)}}
}
