package recovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type testStore struct {
	admin      bool
	connection bool
	acquired   int
	adminCalls int
}

func (s *testStore) AuthorizeAdministrative(context.Context) error {
	s.adminCalls++
	if !s.admin {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

func (s *testStore) CheckConnection(context.Context, domain.CredentialRef, domain.ConnectionGeneration, time.Time) (domain.Credential, error) {
	if !s.connection {
		return domain.Credential{}, domain.Reject(domain.Forbidden)
	}
	return domain.Credential{}, nil
}

func (s *testStore) AcquireRouting(context.Context, routing.Request) error { s.acquired++; return nil }

type testLink struct {
	r        *testReservation
	reserved int
}

func (l *testLink) Snapshot(domain.DeviceID) (gateway.LinkSnapshot, error) {
	return gateway.LinkSnapshot{}, domain.ErrInvalid
}

func (l *testLink) Reserve(context.Context, domain.DeviceID, domain.OperationID, protocol.Command) (gateway.Reservation, error) {
	l.reserved++
	return l.r, nil
}

type testReservation struct {
	beforePublish func()
	beforeReply   func()
	reply         protocol.Reply
	sent          bool
	released      bool
	releaseCalls  int
	releaseErr    error
}

func (r *testReservation) Transmission() domain.Transmission {
	return domain.Transmission{Credential: domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}, Connection: domain.ConnectionGeneration{BootEpoch: "boot", Counter: 1}}
}

func (r *testReservation) TransferSnapshot() routing.TransferSnapshot {
	return routing.TransferSnapshot{WriteState: routing.WriteNotStarted}
}
func (r *testReservation) Routing() (routing.Request, error) { return routing.Request{}, nil }
func (r *testReservation) ArmRouting(routing.Request) error  { return nil }
func (r *testReservation) Publish(ctx context.Context, guard func(context.Context) error) error {
	if r.beforePublish != nil {
		r.beforePublish()
	}
	if err := guard(ctx); err != nil {
		return err
	}
	r.sent = true
	return nil
}

func (r *testReservation) Await(context.Context) (protocol.Reply, error) {
	if r.beforeReply != nil {
		r.beforeReply()
	}
	return r.reply, nil
}

func (r *testReservation) Release(context.Context) error {
	r.released = true
	r.releaseCalls++
	return r.releaseErr
}

func TestExchangeRequiresTypedConsumerBeforeEffects(t *testing.T) {
	store := &testStore{admin: true, connection: true}
	link := &testLink{}
	c := defaultClient(store, link, time.Now, gateway.RoutingObserverFunc(func(gateway.RoutingObservation) {}))
	command := protocol.Command{Operation: protocol.ContextInspect, Project: "project", Body: []byte(`{"gateway_id":"gateway"}`)}
	destination := domain.Destination{Device: "device", Project: "project"}
	guard := func(context.Context, domain.Transmission) error { return nil }
	_, _, err := c.exchange(t.Context(), destination, command, guard, nil)
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("missing typed consumer accepted")
	}
	_, _, err = c.exchangeWithOperation(t.Context(), destination, "operation", command, guard, nil)
	if !errors.Is(err, domain.ErrInvalid) || store.adminCalls != 0 || store.acquired != 0 || link.reserved != 0 {
		t.Fatal("missing typed consumer reached authority or transport")
	}
}

func TestExchangeConsumerFollowsExactlyOneSuccessfulRelease(t *testing.T) {
	for _, failRelease := range []bool{false, true} {
		t.Run(map[bool]string{false: "consumer_fault", true: "release_fault"}[failRelease], func(t *testing.T) {
			checkTypedConsumerRelease(t, failRelease)
		})
	}
}

func checkTypedConsumerRelease(t *testing.T, failRelease bool) {
	t.Helper()
	storage, cleanup := errors.New("controlled typed application failure"), errors.New("controlled release failure")
	reservation := &testReservation{reply: protocol.Reply{Operation: protocol.ContextInspect, Body: []byte(`{"value":true}`)}}
	if failRelease {
		reservation.releaseErr = cleanup
	}
	var events []gateway.RoutingObservation
	c := defaultClient(&testStore{admin: true, connection: true}, &testLink{r: reservation}, time.Now, gateway.RoutingObserverFunc(func(value gateway.RoutingObservation) { events = append(events, value) }))
	accepted := false
	_, _, err := c.exchange(t.Context(), domain.Destination{Device: "device", Project: "project"}, protocol.Command{Operation: protocol.ContextInspect, Project: "project", Body: []byte(`{"gateway_id":"gateway"}`)}, func(context.Context, domain.Transmission) error { return nil }, func(protocol.Reply, domain.Transmission) error {
		if reservation.releaseCalls != 1 || !reservation.released {
			t.Fatal("typed consumer preceded original reservation cleanup")
		}
		accepted = true
		return errors.Join(storage, context.Canceled)
	})
	if reservation.releaseCalls != 1 || len(events) != 1 || !events[0].Failed {
		t.Fatal("final observation escaped exactly-once cleanup or consumer failure")
	}
	if failRelease {
		if !errors.Is(err, cleanup) || accepted {
			t.Fatal("failed cleanup released a reply to its consumer")
		}
	} else if !accepted || !errors.Is(err, storage) || !errors.Is(err, context.Canceled) {
		t.Fatal("typed consumer error graph changed")
	}
}

// Changes at each I/O boundary must be checked before authoritative evidence is
// returned. Cleanup is required even when a queued guard rejects the send.
func TestExchangeAdministrativeAndConnectionFences(t *testing.T) {
	for _, phase := range []string{"initial", "queued", "response", "success"} {
		t.Run(phase, func(t *testing.T) {
			checkExchangePhase(t, phase)
		})
	}
}

func TestOriginReplyRejectsWrongNamespaceAndOpenState(t *testing.T) {
	for _, body := range []string{
		`{"gateway_id":"other","recovery_id":"recovery","generation":"generation","admission_open":true}`,
		`{"gateway_id":"gateway","recovery_id":"other","generation":"generation","admission_open":true}`,
		`{"gateway_id":"gateway","recovery_id":"recovery","generation":"other","admission_open":true}`,
		`{"gateway_id":"gateway","recovery_id":"recovery","generation":"generation","admission_open":false}`,
	} {
		if _, err := originReply(protocol.Reply{Body: []byte(body)}, "gateway", "recovery", "generation", true); err == nil {
			t.Fatal("conflicting namespace accepted")
		}
	}
	body := []byte(`{"gateway_id":"gateway","recovery_id":"recovery","generation":"generation","admission_open":true}`)
	if _, err := originReply(protocol.Reply{Body: body}, "gateway", "recovery", "generation", true); err != nil {
		t.Fatal(err)
	}
}

type reopenStore struct {
	*testStore
	valid  bool
	checks int
}

func (s *reopenStore) PrepareRecoveryBarrier(context.Context, domain.BarrierPreparation) (domain.BarrierPlan, error) {
	return domain.BarrierPlan{}, domain.ErrInvalid
}

func (s *reopenStore) CheckReopen(context.Context, domain.ReopenCheck) error {
	s.checks++
	if !s.valid {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func TestQueuedReopenRejectsInvalidatedInventoryApproval(t *testing.T) {
	store := &reopenStore{testStore: &testStore{admin: true, connection: true}, valid: true}
	reservation := &testReservation{beforePublish: func() { store.valid = false }}
	link := &testLink{r: reservation}
	service, err := New(store, link, "gateway", func() time.Time { return time.Unix(100, 0) }, gateway.RoutingObserverFunc(func(gateway.RoutingObservation) {}))
	if err != nil {
		t.Fatal(err)
	}
	service.wire.random = strings.NewReader(strings.Repeat("x", 16))
	target := domain.ReopenTarget{Destination: domain.RecoveryDestination{Recovery: "recovery", Device: "device", Root: domain.RootGuard(protocol.WireContextGuard("root"))}, Generation: "generation", Completeness: domain.Hash([]byte("receipt")), Revision: 1}
	_, err = service.Reopen(t.Context(), domain.Destination{Device: "device", Project: "project"}, target.Destination.Root, target)
	var denied *domain.Error
	if !errors.As(err, &denied) || denied.Code != domain.Conflict || store.checks != 2 || reservation.sent || !reservation.released {
		t.Fatalf("stale reopen reached wire: err=%v checks=%d sent=%v cleanup=%v", err, store.checks, reservation.sent, reservation.released)
	}
}

func checkExchangePhase(t *testing.T, phase string) {
	t.Helper()
	store := &testStore{admin: true, connection: true}
	reservation := &testReservation{reply: protocol.Reply{Operation: protocol.ContextInspect, Body: []byte(`{"value":true}`)}}
	link := &testLink{r: reservation}
	c := &client{observer: gateway.RoutingObserverFunc(func(gateway.RoutingObservation) {}), store: store, link: link, now: func() time.Time { return time.Unix(100, 0) }, random: strings.NewReader(strings.Repeat("x", 16))}
	switch phase {
	case "initial":
		store.admin = false
	case "queued":
		reservation.beforePublish = func() { store.connection = false }
	case "response":
		reservation.beforeReply = func() { store.admin = false }
	}
	command := protocol.Command{Operation: protocol.ContextInspect, Project: "project", Body: []byte(`{"gateway_id":"gateway"}`)}
	_, _, err := c.exchange(t.Context(), domain.Destination{Device: "device", Project: "project"}, command, func(context.Context, domain.Transmission) error { return nil }, func(protocol.Reply, domain.Transmission) error { return nil })
	if phase == "success" {
		if err != nil || !reservation.sent {
			t.Fatalf("exchange: %v", err)
		}
	} else {
		var denied *domain.Error
		if !errors.As(err, &denied) || denied.Code != domain.Forbidden {
			t.Fatalf("fence bypass: %v", err)
		}
	}
	if phase == "initial" {
		if link.reserved != 0 {
			t.Fatal("unauthorized reservation")
		}
	} else if !reservation.released {
		t.Fatal("reservation leaked")
	}
	if phase == "queued" && reservation.sent {
		t.Fatal("revoked connection reached wire")
	}
}
