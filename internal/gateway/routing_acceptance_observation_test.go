package gateway

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// The real Registry still owns every mutation. This adapter reports a controlled
// lost acknowledgement only after a real successful commit or credential check.
type acceptanceFaultStore struct {
	DispatchStore
	fault             error
	failResolution    int
	applied           int
	connectionFault   bool
	checkedConnection int
	releaseCount      func() int
	releasesAtApply   []int
	releaseAtCheck    int
}

func (s *acceptanceFaultStore) ApplyResolution(ctx context.Context, resolution domain.ValidatedResolution) (domain.OperationView, error) {
	s.releasesAtApply = append(s.releasesAtApply, s.releaseCount())
	view, err := s.DispatchStore.ApplyResolution(ctx, resolution)
	if err != nil {
		return view, err
	}
	s.applied++
	if s.applied == s.failResolution {
		return view, s.fault
	}
	return view, nil
}

func (s *acceptanceFaultStore) CheckConnection(ctx context.Context, credential domain.CredentialRef, connection domain.ConnectionGeneration, now time.Time) (domain.Credential, error) {
	value, err := s.DispatchStore.CheckConnection(ctx, credential, connection, now)
	if err != nil {
		return value, err
	}
	s.checkedConnection++
	s.releaseAtCheck = s.releaseCount()
	if s.connectionFault {
		return value, s.fault
	}
	return value, nil
}

type acceptanceRecord struct {
	value    RoutingObservation
	releases int
	applied  int
	writes   int
}

func recordAcceptance(f *dispatchFixture, store *acceptanceFaultStore) *[]acceptanceRecord {
	var records []acceptanceRecord
	f.service.observer = RoutingObserverFunc(func(value RoutingObservation) {
		records = append(records, acceptanceRecord{value: value, releases: f.link.releases, applied: store.applied, writes: f.link.writes})
	})
	return &records
}

func acceptanceFault() error {
	return errors.Join(&os.PathError{Op: "sync", Path: "/private-canary/acceptance", Err: os.ErrPermission}, context.DeadlineExceeded)
}

func requireAcceptanceFault(t *testing.T, err error) {
	t.Helper()
	var path *os.PathError
	if !errors.Is(err, os.ErrPermission) || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &path) {
		t.Fatal("late acceptance failure lost the original joined error graph")
	}
}

func requireFailedAcceptance(t *testing.T, records []acceptanceRecord, operation domain.OperationID, class protocol.Operation, releases, applied int) {
	t.Helper()
	var matched []acceptanceRecord
	for _, record := range records {
		if record.value.Operation == operation && record.value.Control.Class == routing.ControlClass(class) {
			matched = append(matched, record)
		}
	}
	if len(matched) != 1 || !matched[0].value.Failed {
		t.Fatalf("late acceptance failure was recorded as successful: class=%s matching=%d", class, len(matched))
	}
	if matched[0].releases != releases || matched[0].applied != applied {
		t.Fatal("final observation preceded original release or caller acceptance")
	}
}

func installAcceptanceFaultStore(f *dispatchFixture) *acceptanceFaultStore {
	store := &acceptanceFaultStore{DispatchStore: f.store, fault: acceptanceFault(), releaseCount: func() int { return f.link.releases }}
	f.service.store = store
	return store
}

func TestStatusRoutingObservationIncludesBindingRejection(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	store := installAcceptanceFaultStore(f)
	records := recordAcceptance(f, store)
	f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
		observation := observationFixture(c)
		observation.Task.TaskID = strings.Repeat("f", 32)
		return encodeReplyFixture(command.Operation, observation)
	}
	_, err := f.service.Status(t.Context(), f.actor, c.Operation)
	dispatchCode(t, err, domain.EvidenceInvalid)
	assertPublishedOperations(t, f.link, protocol.Status)
	requireFailedAcceptance(t, *records, c.Operation, protocol.Status, 1, 0)
	if len(*records) != 1 || !f.view(t, c.Operation).Reserved {
		t.Fatal("binding rejection changed observation count or released uncertain execution")
	}
}

func TestRecoveryRoutingObservationIncludesResolutionFailure(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	f.seedExisting(t, c, false)
	store := installAcceptanceFaultStore(f)
	store.failResolution = 1
	records := recordAcceptance(f, store)
	f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
		return encodeReplyFixture(command.Operation, observationFixture(c))
	}
	_, err := f.service.Recover(t.Context(), f.actor, c.Operation)
	requireAcceptanceFault(t, err)
	assertPublishedOperations(t, f.link, protocol.ResumeExisting)
	requireFailedAcceptance(t, *records, c.Operation, protocol.ResumeExisting, 1, 1)
	if !slices.Equal(store.releasesAtApply, []int{1}) {
		t.Fatal("caller accepted recovery before original control release")
	}
	if len(*records) != 1 || !f.view(t, c.Operation).Reserved {
		t.Fatal("lost resolution acknowledgement changed accounting or duplicated observation")
	}
}

func TestCancellationRoutingObservationIncludesEachAcceptedPhase(t *testing.T) {
	for _, failedPhase := range []protocol.Operation{protocol.FenceAbsent, protocol.Cancel} {
		t.Run(string(failedPhase), func(t *testing.T) {
			f := newDispatchFixture(t)
			c := f.possible(t)
			store := installAcceptanceFaultStore(f)
			if failedPhase == protocol.Cancel {
				store.failResolution = 2
			}
			records := recordAcceptance(f, store)
			f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
				observation := observationFixture(c)
				if failedPhase == protocol.FenceAbsent {
					observation.Task.TaskID = strings.Repeat("f", 32)
				}
				return encodeReplyFixture(command.Operation, observation)
			}
			_, err := f.service.Cancel(t.Context(), f.actor, c.Operation, domain.CancellationID(strings.Repeat("a", 32)))
			if failedPhase == protocol.FenceAbsent {
				dispatchCode(t, err, domain.EvidenceInvalid)
				assertPublishedOperations(t, f.link, protocol.FenceAbsent)
				requireFailedAcceptance(t, *records, c.Operation, protocol.FenceAbsent, 1, 0)
				if len(*records) != 1 {
					t.Fatal("failed fence emitted a second cancellation attempt")
				}
				return
			}
			requireAcceptanceFault(t, err)
			assertPublishedOperations(t, f.link, protocol.FenceAbsent, protocol.Cancel)
			requireFailedAcceptance(t, *records, c.Operation, protocol.Cancel, 2, 2)
			assertAcceptedFenceBeforeCancel(t, *records, store)
		})
	}
}

func assertAcceptedFenceBeforeCancel(t *testing.T, records []acceptanceRecord, store *acceptanceFaultStore) {
	t.Helper()
	if !slices.Equal(store.releasesAtApply, []int{1, 2}) {
		t.Fatal("caller accepted a cancellation phase before its original release")
	}
	if len(records) != 2 || records[0].value.Control.Class != routing.ControlClass(protocol.FenceAbsent) || records[0].value.Failed || records[0].writes != 1 || records[0].releases != 1 || records[0].applied != 1 {
		t.Fatal("successful fence was not finalized before the independent cancel attempt")
	}
}

func TestResultRoutingObservationIncludesLateRangeAndAuthorityFailures(t *testing.T) {
	for _, failure := range []string{"range", "authorization", "connection"} {
		t.Run(failure, func(t *testing.T) {
			f := newDispatchFixture(t)
			c := f.possible(t)
			f.seedExisting(t, c, true)
			store := installAcceptanceFaultStore(f)
			store.connectionFault = failure == "connection"
			records := recordAcceptance(f, store)
			descriptor := protocol.Descriptor{SHA256: fixtureResultSHA256, Length: 3}
			f.link.respond = func(ctx context.Context, command protocol.Command) (protocol.Reply, error) {
				if failure == "authorization" {
					if err := f.store.RevokeGrant(ctx, domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination}); err != nil {
						return protocol.Reply{}, err
					}
				}
				result := protocol.ResultRange{Descriptor: descriptor, DataBase64: "YWJj", NextOffset: 3, EOF: true}
				if failure == "range" {
					result.NextOffset = 2
				}
				return encodeReplyFixture(command.Operation, result)
			}
			result, err := f.service.ReadResult(t.Context(), f.actor, c.Operation, descriptor, 0, 3)
			if result.DataBase64 != "" {
				t.Fatal("late failure released result bytes")
			}
			assertPublishedOperations(t, f.link, protocol.ResultChunk)
			requireFailedAcceptance(t, *records, c.Operation, protocol.ResultChunk, 1, 0)
			assertResultAcceptanceFailure(t, failure, err, *records, store)
		})
	}
}

func assertResultAcceptanceFailure(t *testing.T, failure string, err error, records []acceptanceRecord, store *acceptanceFaultStore) {
	t.Helper()
	switch failure {
	case "range":
		dispatchCode(t, err, domain.EvidenceInvalid)
	case "authorization":
		dispatchCode(t, err, domain.NotFound)
		if len(records) != 2 {
			t.Fatal("late authorization supplement count changed")
		}
		for _, record := range records {
			if !record.value.Failed {
				t.Fatal("late revocation retained a successful control observation")
			}
		}
		return
	case "connection":
		requireAcceptanceFault(t, err)
		if store.checkedConnection != 1 || store.releaseAtCheck != 1 {
			t.Fatal("fixture did not reach the final credential check")
		}
	default:
		t.Fatal("unsupported acceptance fault fixture")
	}
	if len(records) != 1 {
		t.Fatal("late failure duplicated its control observation")
	}
}
