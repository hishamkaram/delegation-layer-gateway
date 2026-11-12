package gateway

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func TestRoutingObservationUsesCommittedCorrelationAndCachedRetry(t *testing.T) {
	f := newDispatchFixture(t)
	var events []RoutingObservation
	f.service.observer = RoutingObserverFunc(func(value RoutingObservation) { events = append(events, value) })
	prepared := f.prepare(t)
	assertCommittedPreparation(t, f, events, prepared)
	_, firstErr := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	if firstErr == nil {
		t.Fatal("controlled lost reply disappeared")
	}
	_, retryErr := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	dispatchOK(t, retryErr)
	if len(events) != 3 || f.link.writes != 1 {
		t.Fatalf("retry changed exchange count: events=%d writes=%d", len(events), f.link.writes)
	}
	for _, event := range events[1:] {
		if event.Operation != prepared.Correlation.Operation || event.Destination != f.destination || event.Control.Class != routing.ControlClass(protocol.Admit) || event.Control.Authorization != routing.Allowed || event.Control.DurationNS < 0 {
			t.Fatalf("routing correlation changed: %+v", event)
		}
	}
	last := events[2]
	if last.Failed || last.Control.Transport != routing.NotAttempted || last.Control.WriteState != routing.WriteNotStarted || last.Control.Request != "" || last.Control.EncodedRequestFrameBytes != 0 {
		t.Fatalf("cached retry invented a transport exchange: %+v", last)
	}
}

func assertCommittedPreparation(t *testing.T, f *dispatchFixture, events []RoutingObservation, prepared domain.PreparedOperation) {
	t.Helper()
	if len(events) != 1 || !events[0].Prepared || events[0].Operation != prepared.Correlation.Operation || events[0].Destination != f.destination || events[0].Principal != f.actor.Principal || events[0].Control.Authorization != routing.Allowed {
		t.Fatalf("committed preparation metadata: %+v", events)
	}
}

func TestDeniedRoutingObservationDoesNotEnrichCallerOperation(t *testing.T) {
	f := newDispatchFixture(t)
	prepared := f.prepare(t)
	dispatchOK(t, f.store.RevokeGrant(t.Context(), domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination}))
	var events []RoutingObservation
	f.service.observer = RoutingObserverFunc(func(value RoutingObservation) { events = append(events, value) })
	_, err := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	dispatchCode(t, err, domain.NotFound)
	if len(events) != 1 || events[0].Control.Authorization != routing.DeniedOrMissing || events[0].Principal != f.actor.Principal || events[0].Operation != "" || events[0].Destination != (domain.Destination{}) || f.link.reserves != 0 {
		t.Fatalf("denial leaked correlation or sent: %+v", events)
	}
}

type failedPreparationStore struct {
	DispatchStore
	fault error
}

func (s failedPreparationStore) Prepare(ctx context.Context, actor domain.Actor, value domain.Preparation) (domain.PreparedOperation, error) {
	prepared, err := s.DispatchStore.Prepare(ctx, actor, value)
	return prepared, errors.Join(err, s.fault)
}

func TestPreparationErrorNeverPublishesSuccessFromPopulatedResult(t *testing.T) {
	f := newDispatchFixture(t)
	fault := errors.New("controlled commit or cleanup failure")
	f.service.store = failedPreparationStore{DispatchStore: f.store, fault: fault}
	var events []RoutingObservation
	f.service.observer = RoutingObserverFunc(func(value RoutingObservation) { events = append(events, value) })
	_, err := f.service.Prepare(t.Context(), f.actor, f.destination, f.request)
	if !errors.Is(err, fault) || len(events) != 1 || events[0].Prepared || !events[0].Failed || events[0].Operation != "" {
		t.Fatalf("populated failed preparation became success: %v %+v", err, events)
	}
}

func TestMixedPolicyFaultAndLateGuardRetainUncertainty(t *testing.T) {
	storage := errors.New("controlled storage fault")
	if AuthorizationObservation(errors.Join(domain.Reject(domain.NotFound), storage)) != routing.DecisionUnknown || AuthorizationObservation(errors.Join(domain.Reject(domain.NotFound), nil)) != routing.DeniedOrMissing {
		t.Fatal("policy classification discarded a distinct cause")
	}
	f := newDispatchFixture(t)
	var events []RoutingObservation
	f.service.observer = RoutingObserverFunc(func(value RoutingObservation) { events = append(events, value) })
	attempt := f.service.startObservation(f.actor, routing.ControlClass(protocol.Status))
	release, joined := make(chan struct{}), make(chan struct{})
	guardResult := make(chan error, 1)
	go func() {
		defer close(joined)
		<-release
		guardResult <- attempt.guard(func() error { return domain.Reject(domain.NotFound) })
	}()
	t.Cleanup(func() {
		close(release)
		<-joined
		dispatchCode(t, <-guardResult, domain.NotFound)
	})
	attempt.finish(context.Canceled)
	if len(events) != 1 || events[0].Control.Recheck != routing.NotEvaluated || !events[0].Failed {
		t.Fatalf("unrun guard became an authorization fact: %+v", events)
	}
}

type syntheticPolicyError struct{}

func (syntheticPolicyError) Error() string { return "controlled custom policy projection" }
func (syntheticPolicyError) As(target any) bool {
	policy, ok := target.(**domain.Error)
	if ok {
		*policy = &domain.Error{Code: domain.NotFound}
	}
	return ok
}

func TestOnlySolePolicyLeavesEstablishAuditDenial(t *testing.T) {
	for _, err := range []error{fmt.Errorf("controlled wrapper: %w", domain.Reject(domain.NotFound)), syntheticPolicyError{}} {
		if AuthorizationObservation(err) != routing.DecisionUnknown {
			t.Fatalf("wrapper/custom projection became authoritative denial: %T", err)
		}
	}
}
