package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type observedRouting struct {
	RoutingAuthority
	complete func(context.Context, domain.CredentialRef, domain.ConnectionGeneration, protocol.ControlCompletion, time.Time) error
}

func (o observedRouting) CompleteRouting(ctx context.Context, ref domain.CredentialRef, g domain.ConnectionGeneration, c protocol.ControlCompletion, now time.Time) error {
	if o.complete != nil {
		return o.complete(ctx, ref, g, c, now)
	}
	return o.RoutingAuthority.CompleteRouting(ctx, ref, g, c, now)
}

func TestStrictCompletionHookRunsOutsideSessionMutex(t *testing.T) {
	ready := make(chan struct{})
	observed := make(chan bool, 1)
	var f *routedFixture
	f = routedFixtureOptions(t, func(base RoutingAuthority) RoutingAuthority {
		return observedRouting{RoutingAuthority: base, complete: func(ctx context.Context, ref domain.CredentialRef, g domain.ConnectionGeneration, c protocol.ControlCompletion, now time.Time) error {
			<-ready
			f.hub.mu.Lock()
			s := f.hub.sessions["device-one"]
			f.hub.mu.Unlock()
			unlocked := s.mu.TryLock()
			if unlocked {
				s.mu.Unlock()
			}
			observed <- unlocked
			if !unlocked {
				return domain.Reject(domain.Conflict)
			}
			return base.CompleteRouting(ctx, ref, g, c, now)
		}}
	}, false)
	close(ready)
	client := f.dial(t, newCensusPeer())
	r := f.prepare(t, inspect(t))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, receiveErr := client.Receive(t.Context())
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	<-r.job.done
	if _, claimErr := received.Claim(t.Context()); claimErr != nil {
		t.Fatal(claimErr)
	}
	f.reply(t, received, protocol.ControlSettled)
	select {
	case unlocked := <-observed:
		if !unlocked {
			t.Fatal("routing callback held session mutex")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("completion callback missing")
	}
	if _, awaitErr := r.Await(t.Context()); awaitErr != nil {
		t.Fatal(awaitErr)
	}
}

func TestStrictCompletionFailureRetainsPermitAndFencesSession(t *testing.T) {
	f := routedFixtureOptions(t, func(base RoutingAuthority) RoutingAuthority {
		return observedRouting{RoutingAuthority: base, complete: func(context.Context, domain.CredentialRef, domain.ConnectionGeneration, protocol.ControlCompletion, time.Time) error {
			return errors.New("owned callback fault")
		}}
	}, false)
	client := f.dial(t, newCensusPeer())
	r := f.prepare(t, inspect(t))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, receiveErr := client.Receive(t.Context())
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if _, claimErr := received.Claim(t.Context()); claimErr != nil {
		t.Fatal(claimErr)
	}
	f.reply(t, received, protocol.ControlSettled)
	_, awaitErr := r.Await(t.Context())
	if !errors.Is(awaitErr, ErrNotReady) && !errors.Is(awaitErr, ErrOffline) {
		t.Fatal("callback failure delivered successful observation")
	}
	if f.status(t, client.Generation()).Outstanding != 1 {
		t.Fatal("callback fault released durable routing permit")
	}
	if _, reserveErr := f.hub.Reserve(t.Context(), "device-one", inspect(t)); reserveErr == nil {
		t.Fatal("callback fault left routing ready")
	}
}

func TestStrictForgedCompletionCannotReleasePermit(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	r := f.prepare(t, inspect(t))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, receiveErr := client.Receive(t.Context())
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	frame := received.Frame()
	frame.Type = protocol.Response
	call := received.ControlCall()
	call.RequestSHA256 = strings.Repeat("f", 64)
	response := protocol.ControlResponse{Completion: protocol.ControlCompletion{ProcessBoot: strings.Repeat("a", 32), Call: call, Disposition: protocol.ControlSettled}, Reply: protocol.Reply{Operation: protocol.ContextInspect, Error: &protocol.Failure{Code: "pending", Retryable: true}}}
	frame.Payload = payload(t, response)
	writeRaw(t, client.session.conn, frame)
	_, awaitErr := r.Await(t.Context())
	if !errors.Is(awaitErr, ErrProtocol) && !errors.Is(awaitErr, ErrOffline) {
		t.Fatal("forged completion was accepted")
	}
	if f.status(t, client.Generation()).Outstanding != 1 {
		t.Fatal("forged completion released immutable request binding")
	}
}

func TestStrictNotClaimedReceiptReleasesWithoutAcceptingCLI(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	r := f.prepare(t, protectedControl(t, protocol.Status))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, receiveErr := client.Receive(t.Context())
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if rejectErr := received.Reject(t.Context(), protocol.Failure{Code: "resource_limit", Retryable: true}); rejectErr != nil {
		t.Fatal(rejectErr)
	}
	frame, awaitErr := r.Await(t.Context())
	if awaitErr != nil {
		t.Fatal(awaitErr)
	}
	var response protocol.ControlResponse
	if decodeErr := protocol.DecodeStrict(frame.Payload, &response, protocol.MaxFrameBytes); decodeErr != nil || response.Completion.Disposition != protocol.ControlNotClaimed {
		t.Fatal("missing irrevocable not-claimed completion")
	}
	if f.status(t, client.Generation()).Outstanding != 0 {
		t.Fatal("not-claimed receipt retained routing permit")
	}
	_, claimErr := received.Claim(t.Context())
	requireError(t, claimErr, ErrOffline)
}

func TestStrictRecoveryRequiresPriorControlDrainBeforeRecoveryOnlyStatus(t *testing.T) {
	f := routedFixtureOptions(t, nil, true)
	peer := newCensusPeer()
	client := f.dial(t, peer)
	assertRecoveryOnlyExecutionNotReady(t, f, client)
	if state := f.status(t, client.Generation()); state.Ready || state.Reason != routing.ProcessChanged {
		t.Fatal("new recovery process bypassed prior-control reconciliation")
	}
	_, blockedErr := f.hub.Reserve(t.Context(), "device-one", protectedControl(t, protocol.Status))
	requireError(t, blockedErr, ErrNotReady)
	target := attestEmptyRecoveryPriorControls(t, f, client)
	if disconnectErr := f.hub.DisconnectGeneration(t.Context(), target.Credential, target.Generation); disconnectErr != nil {
		t.Fatal(disconnectErr)
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	client = f.dial(t, peer)
	if state := f.status(t, client.Generation()); !state.Ready || client.Generation() == target.Generation {
		t.Fatal("same reconciled process did not become routing-ready after joined reconnect")
	}
	assertRecoveryOnlyExecutionNotReady(t, f, client)
	r := f.prepare(t, protectedControl(t, protocol.Status))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, receiveErr := client.Receive(t.Context())
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if _, claimErr := received.Claim(t.Context()); claimErr != nil {
		t.Fatal(claimErr)
	}
	f.reply(t, received, protocol.ControlSettled)
	if _, awaitErr := r.Await(t.Context()); awaitErr != nil {
		t.Fatal(awaitErr)
	}
	frame := protectedControl(t, protocol.ResumeExisting)
	_, reserveErr := f.hub.Reserve(t.Context(), "device-one", frame)
	requireError(t, reserveErr, ErrForbidden)
}

func assertRecoveryOnlyExecutionNotReady(t *testing.T, f *routedFixture, client *Client) {
	t.Helper()
	snapshot, snapshotErr := f.hub.Snapshot("device-one")
	if snapshotErr != nil || !snapshot.Online || snapshot.RoutingReady || client.RoutingReady() || client.CredentialMode() != domain.RecoveryOnly {
		t.Fatal("recovery ACK pretended regular execution readiness or lost authoritative mode")
	}
}

func attestEmptyRecoveryPriorControls(t *testing.T, f *routedFixture, client *Client) routing.DrainTarget {
	t.Helper()
	if rosterErr := f.store.RegisterRoutingRecoveryRoster(t.Context(), "recovery-one", []domain.DeviceID{"device-one"}); rosterErr != nil {
		t.Fatal(rosterErr)
	}
	target, targetErr := f.store.ReadRoutingDrainTarget(t.Context(), "device-one", f.clock.now())
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	if target.Credential != f.credential || target.Generation != client.Generation() {
		t.Fatal("drain target did not freeze the authenticated connection")
	}
	result, drainErr := f.store.AttestRoutingDrained(t.Context(), routing.Drain{Device: target.Device, Credential: target.Credential, Recovery: target.Recovery, Scope: routing.AllPriorControls, CurrentBoot: target.ProcessBoot, Generation: target.Generation, Now: f.clock.now()})
	if drainErr != nil || result.Disposition != routing.Drained || result.Target.Blocked || !result.Target.Covered {
		t.Fatal("explicit all-prior drain did not cover the frozen recovery target")
	}
	return target
}

func TestStrictUnknownPermitSurvivesSQLiteReopen(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	r := f.prepare(t, inspect(t))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	if _, receiveErr := client.Receive(t.Context()); receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if closeErr := f.hub.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	f.server.Close()
	if closeErr := f.store.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	reopened, openErr := registry.Open(t.Context(), f.path, registry.Options{Gateway: f.gateway, Admin: routingAdmin{}})
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	state, stateErr := reopened.CheckRoutingReadiness(t.Context(), f.credential, client.Generation(), f.clock.now())
	if stateErr != nil || state.Outstanding != 1 {
		t.Fatal("uncertain permit was lost across real SQLite reopen")
	}
}

func TestStrictOversizedProtectedReceiptCannotReleasePermit(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	r := f.prepare(t, protectedControl(t, protocol.Cancel))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, receiveErr := client.Receive(t.Context())
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	frame := received.Frame()
	frame.Type = protocol.Response
	response := protocol.ControlResponse{Completion: protocol.ControlCompletion{ProcessBoot: strings.Repeat("a", 32), Call: received.ControlCall(), Disposition: protocol.ControlSettled}, Reply: protocol.Reply{Operation: protocol.Cancel, Body: payload(t, struct {
		Padding string `json:"padding"`
	}{strings.Repeat("x", MaxProtectedFrameBytes)})}}
	frame.Payload = payload(t, response)
	writeRaw(t, client.session.conn, frame)
	_, awaitErr := r.Await(t.Context())
	if !errors.Is(awaitErr, ErrProtocol) && !errors.Is(awaitErr, ErrOffline) {
		t.Fatal("oversized protected response was accepted")
	}
	if f.status(t, client.Generation()).Outstanding != 1 {
		t.Fatal("unvalidated oversized receipt reached durable completion hook")
	}
}

type failedUnpublished struct{ RoutingAuthority }

func (failedUnpublished) ReleaseUnpublishedRouting(context.Context, routing.Request) error {
	return errors.New("owned unpublished callback fault")
}

func TestStrictUnusedCleanupFailureSurfacesAndRetainsPermit(t *testing.T) {
	f := routedFixtureOptions(t, func(base RoutingAuthority) RoutingAuthority { return failedUnpublished{RoutingAuthority: base} }, false)
	client := f.dial(t, newCensusPeer())
	r, reserveErr := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if reserveErr != nil {
		t.Fatal(reserveErr)
	}
	route, routeErr := r.Routing()
	if routeErr != nil {
		t.Fatal(routeErr)
	}
	if acquireErr := f.store.AcquireRouting(t.Context(), route); acquireErr != nil {
		t.Fatal(acquireErr)
	}
	if armErr := r.ArmRouting(route); armErr != nil {
		t.Fatal(armErr)
	}
	requireError(t, r.ReleaseUnused(t.Context()), ErrNotReady)
	requireError(t, r.ReleaseUnused(t.Context()), ErrNotReady)
	if f.status(t, client.Generation()).Outstanding != 1 {
		t.Fatal("failed explicit cleanup pretended durable release")
	}
	if _, nextErr := f.hub.Reserve(t.Context(), "device-one", inspect(t)); nextErr == nil {
		t.Fatal("cleanup failure left session routing ready")
	}
}
