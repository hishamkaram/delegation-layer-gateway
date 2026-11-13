package recovery

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// The phase driver has one durable state machine. These adapters vary only
// address selection and the final live attestation: project for legacy v1,
// exact namespace root for owner initialization on v2.
type initializationNamespace interface {
	inspect(context.Context, domain.RootInitializationLookup) (namespaceInspection, domain.Transmission, error)
	barrier(context.Context, domain.RootInitializationLookup, domain.BarrierPreparation) (protocol.OriginStateReport, error)
	inventory(context.Context, domain.RootInitializationLookup, domain.BarrierPlan, string) (protocol.OriginInventoryReport, error)
	reopen(context.Context, domain.RootInitializationLookup, domain.ReopenTarget) (protocol.OriginStateReport, error)
	ready(context.Context, domain.RootInitializationProgress) error
}

type namespaceInspection struct {
	Generation string
	Recovery   domain.RecoveryID
}

type projectInitialization struct{ service *Service }

func (p projectInitialization) inspect(ctx context.Context, l domain.RootInitializationLookup) (namespaceInspection, domain.Transmission, error) {
	if l.RootRoute != nil || l.Validate() != nil {
		return namespaceInspection{}, domain.Transmission{}, domain.ErrInvalid
	}
	report, tx, err := p.service.Inspect(ctx, l.Route, l.ExpectedContext)
	return namespaceInspection{Generation: report.AdmissionGeneration}, tx, err
}

func (p projectInitialization) barrier(ctx context.Context, l domain.RootInitializationLookup, input domain.BarrierPreparation) (protocol.OriginStateReport, error) {
	return p.service.Barrier(ctx, l.Route, input)
}

func (p projectInitialization) inventory(ctx context.Context, l domain.RootInitializationLookup, plan domain.BarrierPlan, cursor string) (protocol.OriginInventoryReport, error) {
	return p.service.Inventory(ctx, l.Route, plan, cursor)
}

func (p projectInitialization) reopen(ctx context.Context, l domain.RootInitializationLookup, target domain.ReopenTarget) (protocol.OriginStateReport, error) {
	return p.service.Reopen(ctx, l.Route, l.ExpectedContext.Root, target)
}

func (p projectInitialization) ready(ctx context.Context, progress domain.RootInitializationProgress) error {
	project, _, err := p.service.Inspect(ctx, progress.Route, progress.Context)
	if err != nil {
		return err
	}
	if !project.AdmissionOpen || project.AdmissionGeneration != string(progress.Generation) {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

type rootInitialization struct{ service *Service }

func (r rootInitialization) inspect(ctx context.Context, l domain.RootInitializationLookup) (namespaceInspection, domain.Transmission, error) {
	if l.RootRoute == nil || l.Validate() != nil {
		return namespaceInspection{}, domain.Transmission{}, domain.ErrInvalid
	}
	report, tx, err := r.service.inspectRoot(ctx, controlRoute{root: l.RootRoute}, l.RootRoute.Root)
	if err != nil {
		return namespaceInspection{}, tx, err
	}
	if report.Origin == nil {
		return namespaceInspection{}, tx, nil
	}
	return namespaceInspection{Generation: report.Origin.Generation, Recovery: domain.RecoveryID(report.Origin.RecoveryID)}, tx, nil
}

func (r rootInitialization) barrier(ctx context.Context, l domain.RootInitializationLookup, input domain.BarrierPreparation) (protocol.OriginStateReport, error) {
	return r.service.barrier(ctx, controlRoute{root: l.RootRoute}, input)
}

func (r rootInitialization) inventory(ctx context.Context, l domain.RootInitializationLookup, plan domain.BarrierPlan, cursor string) (protocol.OriginInventoryReport, error) {
	report, _, err := r.service.inventoryRoute(ctx, controlRoute{root: l.RootRoute}, plan, cursor)
	return report, err
}

func (r rootInitialization) reopen(ctx context.Context, l domain.RootInitializationLookup, target domain.ReopenTarget) (protocol.OriginStateReport, error) {
	return r.service.reopen(ctx, controlRoute{root: l.RootRoute}, l.RootRoute.Root, target)
}

func (r rootInitialization) ready(ctx context.Context, progress domain.RootInitializationProgress) error {
	l := progress.Lookup()
	if l.RootRoute == nil {
		return domain.ErrInvalid
	}
	report, _, err := r.service.inspectRoot(ctx, controlRoute{root: l.RootRoute}, l.RootRoute.Root)
	if err != nil {
		return err
	}
	if report.Origin == nil || !report.Origin.AdmissionOpen || report.Origin.Generation != string(progress.Generation) || report.Origin.RecoveryID != string(progress.RecoveryID) {
		return domain.Reject(domain.Conflict)
	}
	return nil
}
