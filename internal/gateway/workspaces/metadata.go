package workspaces

import (
	"context"
	"crypto/rand"
	"slices"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// exchangeOwnedMetadata reuses the existing routing owner. Scope requirements
// follow the requested read/discovery operation, never execution-option policy.
// All authorizations and current root/credential/connection checks precede
// sending and releasing a validated response. No project or task is retained.
func (s *Service) exchangeOwnedMetadata(ctx context.Context, actor domain.Actor, device domain.DeviceID, operation protocol.Operation, body []byte, validate func(protocol.Reply, domain.RootGuard) error) (gateway.MetadataSource, error) {
	scopes, feature, err := metadataRequirements(operation)
	if err != nil {
		return gateway.MetadataSource{}, err
	}
	if actor.Validate() != nil || domain.CredentialToken(string(device)) != nil || validate == nil {
		return gateway.MetadataSource{}, domain.ErrInvalid
	}
	authorize := func(call context.Context) error {
		for _, scope := range scopes {
			if e := s.authorize(call, actor, device, scope); e != nil {
				return e
			}
		}
		return nil
	}
	if err = authorize(ctx); err != nil {
		s.options.Controls.ObserveAuthorizationFailure(actor, operation, err)
		return gateway.MetadataSource{}, err
	}
	snapshot, err := s.snapshot(device)
	if err != nil {
		return gateway.MetadataSource{}, err
	}
	if snapshot.CapabilitiesV2.Root == nil || !slices.Contains(snapshot.CapabilitiesV2.Root.Features, feature) {
		return gateway.MetadataSource{}, &gateway.RemoteError{Failure: protocol.Failure{Code: "connector_upgrade_required"}}
	}
	root := domain.RootGuard(snapshot.CapabilitiesV2.Root.Root)
	_, tx, err := s.options.Controls.Exchange(ctx, gateway.MetadataCall{
		Actor: actor, Device: device, Operation: domain.OperationID("metadata-" + rand.Text()), Scope: scopes[len(scopes)-1],
		Command: protocol.Command{Operation: operation, Root: string(root), Body: body}, Authorize: authorize,
		Acquire: func(call context.Context, input routing.Request) error {
			return s.options.Store.AcquireWorkspaceMetadata(call, actor, scopes, input)
		},
		Check: func(call context.Context, tx domain.Transmission) error {
			current, e := s.liveBinding(root, tx)
			if e != nil {
				return e
			}
			return s.options.Store.CheckWorkspaceMetadata(call, actor, scopes, current, s.options.Now())
		},
		Validate: func(reply protocol.Reply, _ domain.Transmission) error { return validate(reply, root) },
	})
	if err != nil {
		return gateway.MetadataSource{}, err
	}
	source := gateway.MetadataSource{Binding: domain.OwnedRootBinding{Route: domain.RootRoute{Device: device, Root: root}, Credential: tx.Credential, Connection: tx.Connection}, Operation: operation}
	// Exchange has returned, including reservation cleanup and its synchronous
	// routing observer. Recheck the original source after all those callbacks.
	if err = s.CheckMetadataObservation(ctx, actor, source, nil); err != nil {
		return gateway.MetadataSource{}, err
	}
	return source, nil
}

// CheckMetadataObservation checks the original source against current live
// transport and Registry authority. It never rebases evidence onto a newer peer.
func (s *Service) CheckMetadataObservation(ctx context.Context, actor domain.Actor, source gateway.MetadataSource, additionalScopes domain.ScopeSet) error {
	if ctx == nil {
		return domain.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if source.Validate() != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	scopes, err := metadataObservationScopes(source.Operation, additionalScopes)
	if err != nil {
		return err
	}
	current, err := s.liveBinding(source.Binding.Route.Root, domain.Transmission{Credential: source.Binding.Credential, Connection: source.Binding.Connection})
	if err != nil {
		return err
	}
	if err = s.options.Store.CheckWorkspaceMetadata(ctx, actor, scopes, current, s.options.Now()); err != nil {
		return err
	}
	// The one Registry transaction checked every scope and the original binding.
	// Observe current in-memory presence afterward; no later authorization I/O
	// can invalidate this final root/credential/connection comparison.
	if _, err = s.liveBinding(source.Binding.Route.Root, domain.Transmission{Credential: source.Binding.Credential, Connection: source.Binding.Connection}); err != nil {
		return err
	}
	return ctx.Err()
}

func metadataObservationScopes(operation protocol.Operation, additional domain.ScopeSet) (domain.ScopeSet, error) {
	scopes, _, err := metadataRequirements(operation)
	if err != nil || additional.Validate() != nil {
		return nil, domain.ErrInvalid
	}
	for _, scope := range additional {
		if !scope.IsTask() {
			return nil, domain.ErrInvalid
		}
		if !scopes.Has(scope) {
			scopes = append(scopes, scope)
		}
	}
	return scopes, nil
}

func metadataRequirements(operation protocol.Operation) (domain.ScopeSet, string, error) {
	switch operation {
	case protocol.FilesystemScopes, protocol.ListDirectory, protocol.ReadFile, protocol.InspectFile, protocol.InspectGit:
		return domain.ScopeSet{domain.TaskDispatch, domain.TaskRead}, protocol.FeatureFilesystem, nil
	case protocol.SelectProject:
		return domain.ScopeSet{domain.TaskDispatch}, protocol.FeatureNativeOptions, nil
	case protocol.ProviderModels:
		return domain.ScopeSet{domain.TaskDispatch}, protocol.FeatureScopedModels, nil
	case protocol.ContextInspect, protocol.Admit, protocol.Continue, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen, protocol.ResolveProject:
		return nil, "", domain.ErrInvalid
	default:
		return nil, "", domain.ErrInvalid
	}
}
