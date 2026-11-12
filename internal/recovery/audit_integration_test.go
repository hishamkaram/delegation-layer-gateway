package recovery_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func TestAdministrativeControlAuditWaitsForTypedAcceptance(t *testing.T) {
	f := newRecoveryTLS(t)
	var events []gateway.RoutingObservation
	service, err := recovery.New(f.store, f.link, f.id, func() time.Time { return f.now }, gateway.RoutingObserverFunc(func(value gateway.RoutingObservation) { events = append(events, value) }))
	recoveryOK(t, err)
	expected := f.lookup.ExpectedContext
	expected.Root = domain.RootGuard(protocol.WireContextGuard("different-expected-root"))
	err = runRecoveryCall(t, f, []protocol.Operation{protocol.ContextInspect}, func(ctx context.Context) error {
		_, _, callErr := service.Inspect(ctx, f.lookup.Route, expected)
		return callErr
	}, false)
	var rejected *domain.Error
	if !errors.As(err, &rejected) || rejected.Code != domain.EvidenceInvalid {
		t.Fatal("typed root mismatch was not rejected")
	}
	if len(events) != 1 || !events[0].Failed || events[0].Control.Transport != routing.ReplyReceived || !events[0].Control.ResponseKnown {
		t.Fatal("audit finalized before typed root validation rejected the valid wire reply")
	}
}

type releasedControlLink struct {
	gateway.Link
	releases *atomic.Int64
}

func (l releasedControlLink) Reserve(ctx context.Context, device domain.DeviceID, operation domain.OperationID, command protocol.Command) (gateway.Reservation, error) {
	reservation, err := l.Link.Reserve(ctx, device, operation, command)
	if err != nil {
		return nil, err
	}
	return releasedControlReservation{Reservation: reservation, releases: l.releases}, nil
}

type releasedControlReservation struct {
	gateway.Reservation
	releases *atomic.Int64
}

func (r releasedControlReservation) Release(ctx context.Context) error {
	err := r.Reservation.Release(ctx)
	if err == nil {
		r.releases.Add(1)
	}
	return err
}

type failedDrainApplication struct {
	recovery.DrainStore
	fault    error
	releases *atomic.Int64
	applied  bool
}

func (s *failedDrainApplication) RecordAdministrativeObservation(context.Context, domain.AdministrativeObservation) (domain.AdministrativeTaskView, error) {
	s.applied = s.releases.Load() == 1
	return domain.AdministrativeTaskView{}, s.fault
}

func TestAdministrativeDrainAuditIncludesImmediateStoreFailure(t *testing.T) {
	f := newRecoveryTLS(t)
	key := prepareDrainTask(t, f)
	before, err := f.store.GetAdministrativeTask(f.ctx, key)
	recoveryOK(t, err)
	peer := drainReply{original: before}
	f.taskResponse = peer.response
	storage, cleanup := errors.New("controlled observation storage failure"), errors.New("controlled storage cleanup failure")
	var releases atomic.Int64
	store := &failedDrainApplication{DrainStore: f.store, fault: errors.Join(storage, cleanup), releases: &releases}
	var events []gateway.RoutingObservation
	service, err := recovery.New(f.store, releasedControlLink{Link: f.link, releases: &releases}, f.id, func() time.Time { return f.now }, gateway.RoutingObserverFunc(func(value gateway.RoutingObservation) { events = append(events, value) }))
	recoveryOK(t, err)
	drainer, err := recovery.NewDrainer(store, service, func() time.Time { return f.now })
	recoveryOK(t, err)
	var returned domain.AdministrativeTaskView
	err = runRecoveryCall(t, f, []protocol.Operation{protocol.Resolve}, func(ctx context.Context) error {
		var callErr error
		returned, callErr = drainer.Control(ctx, recovery.DrainRequest{Key: key, Route: f.lookup.Route, Action: domain.AdministrativeResolve})
		return callErr
	}, false)
	if !errors.Is(err, storage) || !errors.Is(err, cleanup) || !store.applied || releases.Load() != 1 {
		t.Fatal("immediate store fault changed cleanup ordering or error graph")
	}
	if returned.Binding != before.Binding || returned.Observation != nil {
		t.Fatal("failed application changed the returned task evidence")
	}
	if len(events) != 1 || !events[0].Failed || events[0].Control.Transport != routing.ReplyReceived || !events[0].Control.ResponseKnown {
		t.Fatal("valid reply masked the immediate store failure in final audit")
	}
}
