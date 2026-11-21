package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func observeRegistryBoundary(f *dispatchFixture) *[]RoutingObservation {
	var observations []RoutingObservation
	f.service.observer = RoutingObserverFunc(func(value RoutingObservation) { observations = append(observations, value) })
	return &observations
}

// Revoke at the final real-store transaction, after preliminary authorization.
// Execution ceilings were removed; current access remains authoritative.
type revokeAtRegistryPreparation struct {
	DispatchStore
	revoke func(context.Context) error
	fault  error
}

func (s revokeAtRegistryPreparation) Prepare(ctx context.Context, actor domain.Actor, input domain.Preparation) (domain.PreparedOperation, error) {
	if err := s.revoke(ctx); err != nil {
		return domain.PreparedOperation{}, err
	}
	prepared, err := s.DispatchStore.Prepare(ctx, actor, input)
	return prepared, errors.Join(err, s.fault)
}

func installPreparationRevocation(f *dispatchFixture, fault error) {
	f.service.store = revokeAtRegistryPreparation{DispatchStore: f.store, fault: fault, revoke: func(ctx context.Context) error {
		return f.store.RevokeGrant(ctx, domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination})
	}}
}

func assertRegistryBoundaryDenial(t *testing.T, values []RoutingObservation, principal domain.PrincipalID, class routing.ControlClass) {
	t.Helper()
	var denials []RoutingObservation
	for _, value := range values {
		if value.Control.Authorization == routing.DeniedOrMissing {
			denials = append(denials, value)
		}
	}
	if len(values) != 2 || len(denials) != 1 {
		t.Fatal("final policy refusal lost its distinct denial observation")
	}
	assertPrincipalOnlyRegistryDenial(t, denials[0], principal, class)
	if values[1].Control.Authorization != routing.Allowed || !values[1].Failed || values[1].Prepared {
		t.Fatal("final refusal erased the historical preliminary authorization")
	}
}

func assertPrincipalOnlyRegistryDenial(t *testing.T, denial RoutingObservation, principal domain.PrincipalID, class routing.ControlClass) {
	t.Helper()
	if denial.Principal != principal || denial.Control.Class != class || !denial.Failed || denial.Prepared || denial.Destination != (domain.Destination{}) || denial.Operation != "" {
		t.Fatal("final policy denial lost its class or enriched an unauthorized destination")
	}
	if denial.Control.Transport != routing.NotAttempted || denial.Control.Recheck != routing.NotEvaluated || denial.Control.Request != "" || denial.Control.Connection != (domain.ConnectionGeneration{}) || denial.Control.TransferSnapshot != (routing.TransferSnapshot{WriteState: routing.WriteNotStarted}) {
		t.Fatal("principal-only policy supplement invented a transport exchange")
	}
}

func assertNoRegistryBoundaryPreparation(t *testing.T, f *dispatchFixture) {
	t.Helper()
	operations, err := f.store.ListOperations(t.Context(), f.actor, domain.OperationPageRequest{})
	dispatchOK(t, err)
	if len(operations.Items) != 0 || f.link.reserves != 0 || f.link.writes != 0 || f.link.awaits != 0 || f.link.releases != 0 {
		t.Fatal("refused preparation committed an operation or touched transport")
	}
}

func TestPrepareFinalAccessRevocationHasPrincipalOnlyAudit(t *testing.T) {
	f := newDispatchFixture(t)
	installPreparationRevocation(f, nil)
	observations := observeRegistryBoundary(f)
	_, err := f.service.Prepare(t.Context(), f.actor, f.destination, f.request)
	dispatchCode(t, err, domain.NotFound)
	f.grant(t)
	assertNoRegistryBoundaryPreparation(t, f)
	assertRegistryBoundaryDenial(t, *observations, f.actor.Principal, routing.PrepareClass)
}

// Revoke through the real Registry immediately before its final transaction;
// this adapter does not simulate the authorization decision or rollback.
type revokeAtRegistryMark struct {
	DispatchStore
	revoke func(context.Context) error
	fault  error
}

func (s revokeAtRegistryMark) MarkPossibleSendRouted(ctx context.Context, actor domain.Actor, transmission domain.Transmission, request routing.Request) (domain.SendDecision, error) {
	if err := s.revoke(ctx); err != nil {
		return domain.SendDecision{}, err
	}
	decision, err := s.DispatchStore.MarkPossibleSendRouted(ctx, actor, transmission, request)
	return decision, errors.Join(err, s.fault)
}

func installRegistryMarkRevocation(f *dispatchFixture, fault error) {
	f.service.store = revokeAtRegistryMark{DispatchStore: f.store, fault: fault, revoke: func(ctx context.Context) error {
		return f.store.RevokeGrant(ctx, domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination})
	}}
}

func assertRegistryMarkRefusalUnsent(t *testing.T, f *dispatchFixture, operation domain.OperationID) {
	t.Helper()
	// Restore only read authority after the refusal to inspect the real saved row.
	f.grant(t)
	assertUnsent(t, f, operation)
	if f.link.reserves != 1 || f.link.releases != 1 {
		t.Fatal("final Registry refusal changed the original reservation/release ownership")
	}
}

func TestDispatchFinalRegistryDenialHasPrincipalOnlyAudit(t *testing.T) {
	f := newDispatchFixture(t)
	prepared := f.prepare(t)
	observations := observeRegistryBoundary(f)
	installRegistryMarkRevocation(f, nil)
	_, err := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	dispatchCode(t, err, domain.NotFound)
	assertRegistryMarkRefusalUnsent(t, f, prepared.Correlation.Operation)
	assertRegistryBoundaryDenial(t, *observations, f.actor.Principal, routing.ControlClass(protocol.Admit))
}

func TestDispatchAdvisoryCatalogDoesNotImposeExecutionCeiling(t *testing.T) {
	f := newDispatchFixture(t)
	prepared := f.prepare(t)
	f.link.snapshot.Capabilities.Projects[0].Providers[0].MaxBudgetSeconds = 30
	_, err := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	if err == nil {
		t.Fatal("controlled lost acknowledgement disappeared")
	}
	view := f.view(t, prepared.Correlation.Operation)
	if view.Delivery != domain.PossibleSend || !view.Reserved || f.link.writes != 1 || f.link.reserves != 1 || f.link.releases != 1 {
		t.Fatal("advisory catalog vetoed Native execution intent")
	}
}

func TestPrepareMissingConnectorProjectHasPrincipalOnlyAudit(t *testing.T) {
	f := newDispatchFixture(t)
	f.link.snapshot.Capabilities.Projects[0].Alias = "another-project"
	observations := observeRegistryBoundary(f)
	_, err := f.service.Prepare(t.Context(), f.actor, f.destination, f.request)
	dispatchCode(t, err, domain.NotFound)
	assertNoRegistryBoundaryPreparation(t, f)
	assertRegistryBoundaryDenial(t, *observations, f.actor.Principal, routing.PrepareClass)
}

func assertMixedRegistryRefusal(t *testing.T, values []RoutingObservation, err error) {
	t.Helper()
	requireAcceptanceFault(t, err)
	if len(values) != 1 || !values[0].Failed || values[0].Prepared || values[0].Control.Authorization != routing.Allowed {
		t.Fatal("mixed policy/storage failure became an authoritative denial or success")
	}
}

func TestMixedPreparationRegistryRefusalRemainsUnknown(t *testing.T) {
	f := newDispatchFixture(t)
	installPreparationRevocation(f, acceptanceFault())
	observations := observeRegistryBoundary(f)
	_, err := f.service.Prepare(t.Context(), f.actor, f.destination, f.request)
	dispatchCode(t, err, domain.NotFound)
	f.grant(t)
	assertNoRegistryBoundaryPreparation(t, f)
	assertMixedRegistryRefusal(t, *observations, err)
}

func TestMixedDispatchRegistryRefusalRemainsUnknown(t *testing.T) {
	f := newDispatchFixture(t)
	prepared := f.prepare(t)
	observations := observeRegistryBoundary(f)
	installRegistryMarkRevocation(f, acceptanceFault())
	_, err := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	dispatchCode(t, err, domain.NotFound)
	assertRegistryMarkRefusalUnsent(t, f, prepared.Correlation.Operation)
	assertMixedRegistryRefusal(t, *observations, err)
}
