package wirelink_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

type commitGate struct {
	*registry.Store
	committed chan struct{}
	proceed   chan struct{}
}

func (g *commitGate) MarkPossibleSendRouted(ctx context.Context, a domain.Actor, tr domain.Transmission, r routing.Request) (domain.SendDecision, error) {
	decision, err := g.Store.MarkPossibleSendRouted(ctx, a, tr, r)
	if err != nil {
		return decision, err
	}
	close(g.committed)
	select {
	case <-g.proceed:
		return decision, nil
	case <-ctx.Done():
		return decision, ctx.Err()
	}
}

func (f *bridgeFixture) prepare(t *testing.T) domain.Correlation {
	t.Helper()
	prepared, err := f.service.Prepare(t.Context(), f.actor, domain.Destination{Device: "device-one", Project: "project-one"}, domain.FrozenRequest{Provider: "provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: domain.ReadOnly, BudgetSeconds: 60, Brief: "immutable bridge brief"})
	return mustValue(t, prepared, err).Correlation
}

func (f *bridgeFixture) view(t *testing.T, id domain.OperationID) domain.OperationView {
	t.Helper()
	view, err := f.store.GetOperation(t.Context(), f.actor, id)
	return mustValue(t, view, err)
}

func (f *bridgeFixture) outstanding(t *testing.T) int {
	t.Helper()
	status, err := f.store.CheckRoutingReadiness(t.Context(), f.ref, f.client.Generation(), f.now)
	return mustValue(t, status, err).Outstanding
}

func startCall(t *testing.T, ctx context.Context, call func(context.Context) error) <-chan error {
	t.Helper()
	owned, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); done <- call(owned) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-joined:
		case <-time.After(10 * time.Second):
			t.Error("owned bridge call did not join")
		}
	})
	return done
}

func awaitCall(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("bridge call failed to join")
		return context.DeadlineExceeded
	}
}

func (f *bridgeFixture) receive(t *testing.T, operation protocol.Operation) *transport.Received {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	received, err := f.client.Receive(ctx)
	mustOK(t, err)
	frame, err := received.Claim(ctx)
	mustOK(t, err)
	var command protocol.Command
	mustOK(t, protocol.DecodeStrict(frame.Payload, &command, protocol.MaxFrameBytes))
	if command.Operation != operation || frame.Generation.Counter != f.client.Generation().Counter || command.Project != "project-one" {
		t.Fatal("wrong operation, alias or generation crossed bridge")
	}
	hash := domain.Hash(frame.Payload)
	if received.ControlCall().RequestSHA256 != hex.EncodeToString(hash[:]) || received.ControlCall().OperationID != frame.OperationID {
		t.Fatal("control identity does not bind exact immutable command")
	}
	c := f.view(t, domain.OperationID(frame.OperationID)).Correlation
	checkWireBinding(t, command, c)
	return received
}

func checkWireBinding(t *testing.T, command protocol.Command, c domain.Correlation) {
	t.Helper()
	expected := observation(c).Task
	if command.Operation == protocol.Admit {
		var admission protocol.Admission
		mustOK(t, protocol.DecodeStrict(command.Body, &admission, protocol.MaxFrameBytes))
		expected.SpecSHA256 = ""
		if admission.Task != expected || admission.Brief != "immutable bridge brief" {
			t.Fatal("admission does not match frozen request")
		}
		return
	}
	var control protocol.TaskControl
	mustOK(t, protocol.DecodeStrict(command.Body, &control, protocol.MaxFrameBytes))
	if control.Task != expected {
		t.Fatal("task control changed immutable identity or known spec")
	}
}

func observation(c domain.Correlation) protocol.TaskObservation {
	return protocol.TaskObservation{Task: protocol.TaskBinding{TaskID: string(c.Task), Context: protocol.ContextBinding{Root: string(c.Context.Root), Project: string(c.Context.Project)}, Origin: protocol.Origin{GatewayID: string(c.Gateway), AdmissionGeneration: string(c.AdmissionGeneration), OperationID: string(c.Operation), PrincipalRef: string(c.Owner.Principal), RequestSHA256: hex.EncodeToString(c.RequestDigest[:])}, SpecSHA256: strings.Repeat("1", 64)}, BriefSHA256: hex.EncodeToString(c.BriefDigest[:]), Resolution: "existing", Admission: "admitted", Liveness: "ended", Publication: "committed", Verdict: "committed", Result: &protocol.Descriptor{SHA256: strings.Repeat("2", 64), Length: 3}, ExecutionClosurePending: "owner_busy"}
}

func (f *bridgeFixture) reply(t *testing.T, r *transport.Received, o protocol.TaskObservation) {
	t.Helper()
	body, err := protocol.Encode(o, protocol.MaxFrameBytes)
	mustOK(t, err)
	mustOK(t, r.ReplyControl(t.Context(), protocol.Reply{Operation: r.ControlCall().Operation, Body: body}, protocol.ControlCompletion{ProcessBoot: strings.Repeat("a", 32), Call: r.ControlCall(), Disposition: protocol.ControlSettled}))
}

func (f *bridgeFixture) dispatch(t *testing.T, c domain.Correlation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := startCall(t, ctx, func(ctx context.Context) error { _, err := f.service.Dispatch(ctx, f.actor, c.Operation); return err })
	received := f.receive(t, protocol.Admit)
	f.reply(t, received, observation(c))
	mustOK(t, awaitCall(t, done))
}

func (f *bridgeFixture) assertPendingTaskAfterSettledControl(t *testing.T, id domain.OperationID) {
	t.Helper()
	pending := f.view(t, id)
	if !pending.Reserved || pending.Observation == nil || pending.Observation.Result == nil || pending.Observation.ClosurePending != domain.ClosureOwnerBusy || f.outstanding(t) != 0 {
		t.Fatal("control completion conflated with task closure")
	}
}

func TestBridgeCommitBeforePublishAndClosureIsSeparateFromControlCompletion(t *testing.T) {
	f := newBridgeFixture(t)
	c := f.prepare(t)
	gate := &commitGate{Store: f.store, committed: make(chan struct{}), proceed: make(chan struct{})}
	service, err := gateway.New(gate, f.link, f.gateway, rand.Reader, func() time.Time { return f.now }, gateway.RoutingObserverFunc(func(gateway.RoutingObservation) {}))
	mustOK(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := startCall(t, ctx, func(ctx context.Context) error {
		_, dispatchErr := service.Dispatch(ctx, f.actor, c.Operation)
		return dispatchErr
	})
	select {
	case <-gate.committed:
	case <-ctx.Done():
		t.Fatal("durable admission never completed")
	}
	if view := f.view(t, c.Operation); view.Delivery != domain.PossibleSend || !view.Reserved || view.Correlation != c || f.outstanding(t) != 1 {
		t.Fatal("atomic correlation/task reservation/routing permit missing")
	}
	before, cancelReceive := context.WithTimeout(ctx, 30*time.Millisecond)
	_, receiveErr := f.client.Receive(before)
	cancelReceive()
	if !errors.Is(receiveErr, context.DeadlineExceeded) {
		t.Fatal("bytes crossed bridge before committed decision returned")
	}
	close(gate.proceed)
	received := f.receive(t, protocol.Admit)
	f.reply(t, received, observation(c))
	mustOK(t, awaitCall(t, done))
	f.assertPendingTaskAfterSettledControl(t, c.Operation)
	duplicate, err := f.service.Dispatch(ctx, f.actor, c.Operation)
	mustOK(t, err)
	if duplicate.Operation.Correlation != c {
		t.Fatal("duplicate confirmation changed correlation")
	}
	done = startCall(t, ctx, func(ctx context.Context) error {
		_, statusErr := f.service.Status(ctx, f.actor, c.Operation)
		return statusErr
	})
	received = f.receive(t, protocol.Status) // Any replayed Admit fails this assertion.
	closed := observation(c)
	closed.ExecutionClosurePending = ""
	closed.ExecutionClosure = &protocol.ExecutionClosure{Kind: "registered-native", ReferenceSHA256: strings.Repeat("3", 64)}
	f.reply(t, received, closed)
	mustOK(t, awaitCall(t, done))
	final := f.view(t, c.Operation)
	if final.Reserved || final.Delivery != domain.Resolved || final.Observation.Closure == nil || f.outstanding(t) != 0 {
		t.Fatal("canonical closure did not release task quota")
	}
}

func TestBridgeRejectsMismatchedRevokedAndStaleReplyEvidence(t *testing.T) {
	for _, mode := range []string{"wrong-correlation", "revoked-grant", "revoked-device", "stale-generation"} {
		t.Run(mode, func(t *testing.T) {
			f := newBridgeFixture(t)
			c := f.prepare(t)
			f.dispatch(t, c)
			before := f.view(t, c.Operation)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := startCall(t, ctx, func(ctx context.Context) error { _, err := f.service.Status(ctx, f.actor, c.Operation); return err })
			received := f.receive(t, protocol.Status)
			o := observation(c)
			o.ExecutionClosurePending = ""
			o.ExecutionClosure = &protocol.ExecutionClosure{Kind: "registered-native", ReferenceSHA256: strings.Repeat("3", 64)}
			switch mode {
			case "wrong-correlation":
				o.Task.TaskID = strings.Repeat("f", 32)
			case "revoked-grant":
				mustOK(t, f.store.RevokeGrant(ctx, domain.GrantKey{Principal: f.actor.Principal, Destination: c.Destination}))
			case "revoked-device":
				mustOK(t, f.store.SetDeviceRevoked(ctx, f.ref.Device, true))
			case "stale-generation":
				_, err := f.store.NextConnectionGeneration(ctx, f.ref, "superseding-boot", f.now)
				mustOK(t, err)
			}
			f.reply(t, received, o)
			if err := awaitCall(t, done); err == nil {
				t.Fatal("invalid reply accepted by bridge service")
			}
			if mode == "revoked-device" {
				mustOK(t, f.store.SetDeviceRevoked(ctx, f.ref.Device, false))
			}
			if mode == "revoked-grant" {
				mustOK(t, f.store.PutGrant(ctx, domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: c.Destination}, Scopes: f.actor.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 300}}))
			}
			if after := f.view(t, c.Operation); !reflect.DeepEqual(before, after) || !after.Reserved {
				t.Fatal("invalid reply updated observation or released task quota")
			}
		})
	}
}

func TestBridgeUnusedReleaseDoesNotExhaustQueueOrDurablePermits(t *testing.T) {
	f := newBridgeFixture(t)
	body, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(f.gateway)}, protocol.MaxFrameBytes)
	mustOK(t, err)
	for range 40 {
		reserved, reserveErr := f.link.Reserve(t.Context(), "device-one", "metadata-operation", protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: body})
		mustOK(t, reserveErr)
		route, routeErr := reserved.Routing()
		mustOK(t, routeErr)
		route.Now = f.now
		mustOK(t, f.store.AcquireRouting(t.Context(), route))
		mustOK(t, reserved.ArmRouting(route))
		mustOK(t, reserved.Release(t.Context()))
		if f.outstanding(t) != 0 {
			t.Fatal("unused bridge buffer retained durable routing permit")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, receiveErr := f.client.Receive(ctx); !errors.Is(receiveErr, context.DeadlineExceeded) {
		t.Fatal("unused reservation sent bytes")
	}
}
