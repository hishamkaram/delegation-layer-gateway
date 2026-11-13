package adminapi

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func rootLookup(input RootInput) (domain.RootInitializationLookup, error) {
	lookup := domain.RootInitializationLookup{Route: domain.Destination{Device: domain.DeviceID(input.DeviceID), Project: domain.ProjectAlias(input.ProjectAlias)}, ExpectedContext: domain.ContextBinding{Root: domain.RootGuard(input.RootGuard), Project: domain.ProjectGuard(input.ProjectGuard)}}
	if lookup.Route.Validate() != nil || lookup.ExpectedContext.Validate() != nil {
		return lookup, domain.ErrInvalid
	}
	return lookup, nil
}

func (input RootInput) Validate() error {
	_, err := rootLookup(input)
	return err
}

func rootProjection(p domain.RootInitializationProgress) RootProgress {
	return RootProgress{GatewayID: string(p.GatewayID), DeviceID: string(p.Route.Device), ProjectAlias: string(p.Route.Project), RecoveryID: string(p.RecoveryID), Generation: string(p.Generation), Stage: p.Stage}
}

func (h *Handler) initializeRoot(ctx context.Context, input RootInput) (RootProgress, error) {
	lookup, err := rootLookup(input)
	if err != nil {
		return RootProgress{}, err
	}
	if h.options.Roots == nil {
		return RootProgress{}, domain.Reject(domain.Pending)
	}
	progress, err := h.options.Roots.Advance(ctx, lookup)
	return rootProjection(progress), err
}

func (h *Handler) rootProgress(ctx context.Context, input RootInput) (RootProgress, error) {
	lookup, err := rootLookup(input)
	if err != nil {
		return RootProgress{}, err
	}
	if h.options.Roots == nil {
		return RootProgress{}, domain.Reject(domain.Pending)
	}
	progress, err := h.options.Roots.Progress(ctx, lookup)
	return rootProjection(progress), err
}

func (h *Handler) abandonRoot(ctx context.Context, input RootAbandonInput) (Mutation, error) {
	if domain.RoutingToken(input.RecoveryID) != nil {
		return Mutation{}, domain.ErrInvalid
	}
	if h.options.Roots == nil {
		return Mutation{}, domain.Reject(domain.Pending)
	}
	err := h.options.Roots.Abandon(ctx, domain.RecoveryID(input.RecoveryID))
	return Mutation{Committed: err == nil}, err
}
