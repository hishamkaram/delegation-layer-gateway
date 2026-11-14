package gateway

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func closureFixture() *protocol.ExecutionClosure {
	return &protocol.ExecutionClosure{Kind: "registered-native", ReferenceSHA256: hexFixture(domain.Hash([]byte("canonical joined owner closure")))}
}

func TestOnlyExactConfirmedCancellationBecomesTypedStopEvidence(t *testing.T) {
	id := domain.CancellationID(strings.Repeat("a", 32))
	for name, change := range map[string]func(*protocol.Reply, *protocol.TaskObservation, *domain.CancellationID){
		"matching": func(*protocol.Reply, *protocol.TaskObservation, *domain.CancellationID) {},
		"other-operation": func(r *protocol.Reply, _ *protocol.TaskObservation, _ *domain.CancellationID) {
			r.Operation = protocol.Status
		},
		"other-cancellation": func(_ *protocol.Reply, o *protocol.TaskObservation, _ *domain.CancellationID) {
			o.Stop.RequestID = strings.Repeat("b", 32)
		},
		"not-requested": func(_ *protocol.Reply, o *protocol.TaskObservation, _ *domain.CancellationID) {
			o.Stop.Requested = false
		},
		"not-terminated": func(_ *protocol.Reply, o *protocol.TaskObservation, _ *domain.CancellationID) {
			o.Stop.Terminated = false
		},
		"invalid-id": func(_ *protocol.Reply, o *protocol.TaskObservation, c *domain.CancellationID) {
			*c = "guessed"
			o.Stop.RequestID = "guessed"
		},
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)
			observation := protocol.TaskObservation{Task: protocol.TaskBinding{SpecSHA256: strings.Repeat("c", 64)}, Resolution: "existing", Stop: &protocol.StopObservation{RequestID: string(id), Requested: true, Terminated: true}}
			reply := protocol.Reply{Operation: protocol.Cancel}
			cancellation := id
			change(&reply, &observation, &cancellation)
			cache, cacheErr := ObservationFromReply(reply, observation, cancellation, now)
			if cacheErr != nil || cache.Validate(now) != nil {
				t.Fatal("cancellation cache produced invalid domain observation")
			}
			if name == "matching" {
				if cache.Kind != domain.Terminal || cache.ConfirmedStop == nil || cache.ConfirmedStop.Cancellation != id {
					t.Fatal("matching cancellation lost explicit stop evidence")
				}
			} else if cache.Kind != domain.Existing || cache.ConfirmedStop != nil {
				t.Fatal("nonmatching cancellation fabricated terminal proof")
			}
		})
	}
}

func TestMismatchedOrUnknownReplyEvidenceCannotUpdateCacheOrReleaseQuota(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*protocol.TaskObservation)
		unknown bool
	}{
		{"task", func(o *protocol.TaskObservation) { o.Task.TaskID = strings.Repeat("f", 32) }, false},
		{"root context", func(o *protocol.TaskObservation) { o.Task.Context.Root = protocol.WireContextGuard("other-root") }, false},
		{"project context", func(o *protocol.TaskObservation) { o.Task.Context.Project = protocol.WireContextGuard("other-project") }, false},
		{"gateway", func(o *protocol.TaskObservation) { o.Task.Origin.GatewayID = "other-gateway" }, false},
		{"principal", func(o *protocol.TaskObservation) { o.Task.Origin.PrincipalRef = "other-principal" }, false},
		{"operation", func(o *protocol.TaskObservation) { o.Task.Origin.OperationID = "other-operation" }, false},
		{"generation", func(o *protocol.TaskObservation) { o.Task.Origin.AdmissionGeneration = "other-generation" }, false},
		{"request digest", func(o *protocol.TaskObservation) { o.Task.Origin.RequestSHA256 = strings.Repeat("f", 64) }, false},
		{"spec digest", func(o *protocol.TaskObservation) { o.Task.SpecSHA256 = strings.Repeat("f", 64) }, false},
		{"brief digest", func(o *protocol.TaskObservation) { o.BriefSHA256 = strings.Repeat("f", 64) }, false},
		{"unknown field", func(*protocol.TaskObservation) {}, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newDispatchFixture(t)
			c := f.possible(t)
			f.seedExisting(t, c, false)
			before := f.view(t, c.Operation)
			f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
				observation := observationFixture(c)
				observation.ExecutionClosure = closureFixture()
				observation.Liveness = "ended"
				test.change(&observation)
				reply, err := encodeReplyFixture(command.Operation, observation)
				if test.unknown {
					reply.Body = append(reply.Body[:len(reply.Body)-1], []byte(`,"native_debug":"must reject"}`)...)
				}
				return reply, err
			}
			if _, err := f.service.Status(t.Context(), f.actor, c.Operation); err == nil {
				t.Fatal("mismatched or unknown evidence accepted")
			}
			if after := f.view(t, c.Operation); !reflect.DeepEqual(before, after) || !after.Reserved {
				t.Fatal("invalid reply updated cache or freed execution quota")
			}
		})
	}
}

func TestAcceptedOutcomeBeforeCanonicalClosureKeepsReservationAndReportsPending(t *testing.T) {
	for _, verdict := range []string{"committed", "rejected"} {
		t.Run(verdict, func(t *testing.T) {
			f := newDispatchFixture(t)
			c := f.possible(t)
			closed := false
			f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
				observation := observationFixture(c)
				observation.Publication = verdict
				observation.Verdict = verdict
				observation.Liveness = "ended"
				observation.ExecutionClosurePending = "owner_busy"
				if verdict == "committed" {
					observation.Result = &protocol.Descriptor{SHA256: fixtureResultSHA256, Length: 3}
				}
				if closed {
					observation.ExecutionClosurePending = ""
					observation.ExecutionClosure = closureFixture()
				}
				return encodeReplyFixture(command.Operation, observation)
			}
			view, err := f.service.Collect(t.Context(), f.actor, c.Operation)
			assertCollectVerdict(t, verdict, err)
			pending := view
			if !pending.Reserved || pending.Delivery != domain.PossibleSend || pending.Observation.Kind != domain.Existing || pending.Observation.ClosurePending != domain.ClosureOwnerBusy {
				t.Fatal("accepted/rejected publication before owner Wait was treated as execution closure")
			}
			closed = true
			view, err = f.service.Status(t.Context(), f.actor, c.Operation)
			terminal := dispatchMust(t, view, err)
			if terminal.Reserved || terminal.Observation.Kind != domain.Terminal || terminal.Observation.Closure == nil || terminal.Observation.ClosurePending != domain.NoClosurePending {
				t.Fatal("canonical closure proof did not settle reservation and preserve proof metadata")
			}
		})
	}
}

func TestStaleGenerationReplyCannotReplaceCurrentObservation(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	f.seedExisting(t, c, false)
	before := f.view(t, c.Operation)
	f.link.respond = func(ctx context.Context, command protocol.Command) (protocol.Reply, error) {
		if _, err := f.store.NextConnectionGeneration(ctx, f.link.snapshot.Credential, "superseding-boot", f.now); err != nil {
			return protocol.Reply{}, err
		}
		observation := observationFixture(c)
		observation.ExecutionClosure = closureFixture()
		return encodeReplyFixture(command.Operation, observation)
	}
	_, err := f.service.Status(t.Context(), f.actor, c.Operation)
	dispatchCode(t, err, domain.Conflict)
	if after := f.view(t, c.Operation); !reflect.DeepEqual(before, after) || !after.Reserved {
		t.Fatal("stale generation changed cached evidence or quota")
	}
}
