package gateway

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func assertResultUnavailable(t *testing.T, err error) {
	t.Helper()
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Failure.Code != "result_unavailable" || remote.Failure.Retryable {
		t.Fatalf("collect error=%v, want nonretryable result_unavailable", err)
	}
}

func assertCollectVerdict(t *testing.T, verdict string, err error) {
	t.Helper()
	if verdict == "rejected" {
		assertResultUnavailable(t, err)
		return
	}
	dispatchOK(t, err)
}

func TestCollectUsesFreshVerdictAfterApplyingClosure(t *testing.T) {
	for _, test := range []struct {
		name, publication, verdict string
	}{
		{"rejected", "rejected", "rejected"},
		{"rejected-without-outcome", "rejected", ""},
		{"pending-after-closure", "pending", ""},
		{"committed", "committed", "committed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newDispatchFixture(t)
			c := f.possible(t)
			f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
				o := observationFixture(c)
				o.Publication, o.Verdict = test.publication, test.verdict
				o.Liveness = "ended"
				o.ExecutionClosure = closureFixture()
				if test.verdict == "committed" {
					o.Result = &protocol.Descriptor{SHA256: fixtureResultSHA256, Length: 3}
				}
				return encodeReplyFixture(command.Operation, o)
			}
			view, err := f.service.Collect(t.Context(), f.actor, c.Operation)
			assertCollectVerdict(t, test.verdict, err)
			stored := f.view(t, c.Operation)
			if !reflect.DeepEqual(view, stored) || stored.Reserved || stored.Delivery != domain.Resolved || stored.Observation.Kind != domain.Terminal || stored.Observation.Closure == nil {
				t.Fatal("collect did not apply canonical closure before returning")
			}
			if (stored.Observation.Result != nil) != (test.verdict == "committed") {
				t.Fatal("collect fabricated or removed an accepted descriptor")
			}
			assertPublishedOperations(t, f.link, protocol.Collect)
		})
	}
}

func TestCollectRejectionCannotReplaceAnAcceptedDescriptor(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	f.seedExisting(t, c, true)
	before := f.view(t, c.Operation)
	f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
		o := observationFixture(c)
		o.Publication, o.Verdict = "rejected", "rejected"
		o.Liveness = "ended"
		o.ExecutionClosure = closureFixture()
		return encodeReplyFixture(command.Operation, o)
	}
	_, err := f.service.Collect(t.Context(), f.actor, c.Operation)
	dispatchCode(t, err, domain.Conflict)
	if after := f.view(t, c.Operation); !reflect.DeepEqual(before, after) {
		t.Fatal("conflicting rejection changed accepted evidence or reservation")
	}
}
