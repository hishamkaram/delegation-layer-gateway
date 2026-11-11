package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func routingOutstandingFixture(t *testing.T, f *dispatchFixture) int {
	t.Helper()
	status, err := f.store.CheckRoutingReadiness(t.Context(), f.link.snapshot.Credential, f.link.snapshot.Connection, f.now)
	return dispatchMust(t, status, err).Outstanding
}

func TestUnusedReservationReleaseFailureIsReportedAndConservative(t *testing.T) {
	f := newDispatchFixture(t)
	operation := f.prepare(t)
	cleanupFailure := errors.New("controlled unused-buffer release failure")
	f.link.releaseError = cleanupFailure
	f.link.beforeWrite = func(ctx context.Context) error {
		return f.store.RevokeGrant(ctx, domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination})
	}
	_, err := f.service.Dispatch(t.Context(), f.actor, operation.Correlation.Operation)
	dispatchCode(t, err, domain.NotFound)
	if !errors.Is(err, cleanupFailure) || f.link.writes != 0 || f.link.releases != 1 || routingOutstandingFixture(t, f) != 1 {
		t.Fatal("unused release failure hidden or capacity guessed free")
	}
	f.grant(t)
	if view := f.view(t, operation.Correlation.Operation); !view.Reserved || view.Delivery != domain.PossibleSend {
		t.Fatal("cleanup failure fabricated task absence")
	}
}

func TestPublishedReservationReleaseFailureDoesNotEraseLostAck(t *testing.T) {
	f := newDispatchFixture(t)
	operation := f.prepare(t)
	cleanupFailure := errors.New("controlled used-buffer cleanup failure")
	f.link.releaseError = cleanupFailure
	_, err := f.service.Dispatch(t.Context(), f.actor, operation.Correlation.Operation)
	if !errors.Is(err, cleanupFailure) || !errors.Is(err, f.link.awaitError) {
		t.Fatalf("joined cleanup error lost: %v", err)
	}
	if routingOutstandingFixture(t, f) != 1 || !f.view(t, operation.Correlation.Operation).Reserved {
		t.Fatal("used reservation release freed uncertain resources")
	}
}

func TestLostAwaitRequiresExplicitFencedCensusBeforeAnotherScan(t *testing.T) {
	f := newDispatchFixture(t)
	operation := f.prepare(t)
	_, err := f.service.Dispatch(t.Context(), f.actor, operation.Correlation.Operation)
	if !errors.Is(err, f.link.awaitError) {
		t.Fatal(err)
	}
	_, err = f.service.Status(t.Context(), f.actor, operation.Correlation.Operation)
	dispatchCode(t, err, domain.ResourceLimit)
	if f.link.writes != 1 || routingOutstandingFixture(t, f) != 1 {
		t.Fatal("lost Await permitted another scan or freed CLI capacity")
	}
	generation, err := f.store.NextConnectionGeneration(t.Context(), f.link.snapshot.Credential, "fenced-reconnect", f.now)
	f.link.snapshot.Connection = dispatchMust(t, generation, err)
	f.reconcileRouting(t) // Controlled peer has joined the prior CLI and reports absence.
	if routingOutstandingFixture(t, f) != 0 || !f.view(t, operation.Correlation.Operation).Reserved {
		t.Fatal("census conflated routing cleanup with Delegate task closure")
	}
}
