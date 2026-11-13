package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestStrictRoutingHandshakeAndLateAbandonedCompletion(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	snapshot, snapshotErr := f.hub.Snapshot("device-one")
	if snapshotErr != nil || !snapshot.RoutingReady || snapshot.ProcessBoot != client.ProcessBoot() {
		t.Fatal("routing ACK did not gate current session")
	}
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
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, awaitErr := r.Await(ctx)
	requireError(t, awaitErr, ErrExpired)
	if f.status(t, client.Generation()).Outstanding != 1 {
		t.Fatal("observation cancellation released durable routing permit")
	}
	f.reply(t, received, protocol.ControlSettled)
	waitRoutingCount(t, f, client.Generation(), 0)
	if _, snapshotErr := f.hub.Snapshot("device-one"); snapshotErr != nil {
		t.Fatal("late completion canceled reader")
	}
}

func TestStrictPrewriteDenialReleasesOnlyRoutingPermit(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	for range 4 {
		r := f.prepare(t, protectedControl(t, protocol.Status))
		if publishErr := r.Publish(t.Context(), func(context.Context, Metadata) error { return domain.Reject(domain.Forbidden) }); publishErr != nil {
			t.Fatal(publishErr)
		}
		_, awaitErr := r.Await(t.Context())
		requireError(t, awaitErr, ErrForbidden)
		if f.status(t, client.Generation()).Outstanding != 0 {
			t.Fatal("definitely unwritten control retained scan permit")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, receiveErr := client.Receive(ctx); receiveErr == nil {
		t.Fatal("denied prewrite reached connector")
	}
	if !client.RoutingReady() {
		t.Fatal("prewrite denial poisoned healthy session")
	}
}

func TestStrictCanceledPublicationAndExplicitUnusedRelease(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	canceled := f.prepare(t, protectedControl(t, protocol.Status))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	requireError(t, canceled.Publish(ctx, allowed), ErrExpired)
	if f.status(t, client.Generation()).Outstanding != 0 {
		t.Fatal("canceled pre-publication retained routing scan")
	}
	unused := f.prepare(t, protectedControl(t, protocol.Status))
	if releaseErr := unused.ReleaseUnused(t.Context()); releaseErr != nil {
		t.Fatal(releaseErr)
	}
	if releaseErr := unused.ReleaseUnused(t.Context()); releaseErr != nil {
		t.Fatal("explicit unused release not idempotent")
	}
	if f.status(t, client.Generation()).Outstanding != 0 {
		t.Fatal("unused buffer release did not free routing scan")
	}
}

func TestStrictWriteThenSocketLossRetainsDurablePermit(t *testing.T) {
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
	if _, claimErr := received.Claim(t.Context()); claimErr != nil {
		t.Fatal(claimErr)
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	_, awaitErr := r.Await(t.Context())
	if !errors.Is(awaitErr, ErrOffline) {
		t.Fatal("socket loss did not leave observation unknown")
	}
	if f.status(t, client.Generation()).Outstanding != 1 {
		t.Fatal("generic socket cleanup released possibly written routing permit")
	}
	if releaseErr := r.ReleaseUnused(t.Context()); releaseErr != nil {
		t.Fatal(releaseErr)
	}
	if f.status(t, client.Generation()).Outstanding != 1 {
		t.Fatal("used pending request was discarded by cleanup")
	}
}

func waitRoutingCount(t *testing.T, f *routedFixture, g domain.ConnectionGeneration, count int) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if f.status(t, g).Outstanding == count {
			return
		}
		select {
		case <-timer.C:
			t.Fatal("routing receipt did not reach durable owner")
		case <-ticker.C:
		}
	}
}

func TestStrictRoutingHashesActualEncodedCommandBytes(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	frame := inspect(t)
	var pretty bytes.Buffer
	if indentErr := json.Indent(&pretty, frame.Payload, "", "  "); indentErr != nil {
		t.Fatal(indentErr)
	}
	frame.Payload = pretty.Bytes()
	r := f.prepare(t, frame)
	route, routeErr := r.Routing()
	if routeErr != nil {
		t.Fatal(routeErr)
	}
	hash := domain.Hash(route.Payload)
	if route.Call.RequestSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("routing digest did not bind actual encoded Command bytes")
	}
	if releaseErr := r.ReleaseUnused(t.Context()); releaseErr != nil {
		t.Fatal(releaseErr)
	}
	if f.status(t, client.Generation()).Outstanding != 0 {
		t.Fatal("exact encoded unused proof did not release")
	}
}

func TestStrictQueueExpiryReleasesBeforeWriteInvocation(t *testing.T) {
	f := newRoutedFixture(t)
	client := f.dial(t, newCensusPeer())
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	first := f.prepare(t, inspect(t))
	guard := func(ctx context.Context, _ Metadata) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if publishErr := first.Publish(t.Context(), guard); publishErr != nil {
		t.Fatal(publishErr)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("writer guard did not start")
	}
	queued := f.prepare(t, protectedControl(t, protocol.Status))
	if publishErr := queued.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	f.clock.advance(31 * time.Second)
	unblock()
	_, firstErr := first.Await(t.Context())
	requireError(t, firstErr, ErrExpired)
	_, queuedErr := queued.Await(t.Context())
	requireError(t, queuedErr, ErrExpired)
	if f.status(t, client.Generation()).Outstanding != 0 {
		t.Fatal("queue expiration exhausted durable scan permit")
	}
}

func TestStrictSameBootCensusRetainsActiveThenReleasesJoinedAbsent(t *testing.T) {
	f := newRoutedFixture(t)
	first := f.dial(t, newCensusPeer())
	r := f.prepare(t, inspect(t))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	if _, receiveErr := first.Receive(t.Context()); receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if closeErr := first.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	active := newCensusPeer()
	active.active = []protocol.ControlCall{r.Frame().Call}
	second := f.dial(t, active)
	if f.status(t, second.Generation()).Outstanding != 1 {
		t.Fatal("same-boot active census released retained key")
	}
	if closeErr := second.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	third := f.dial(t, newCensusPeer())
	if f.status(t, third.Generation()).Outstanding != 0 {
		t.Fatal("complete fenced same-boot absence did not reconcile old permit")
	}
}

func TestStrictChangedProcessStaysOnlineButCannotRoute(t *testing.T) {
	f := newRoutedFixture(t)
	first := f.dial(t, newCensusPeer())
	r := f.prepare(t, inspect(t))
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	if _, receiveErr := first.Receive(t.Context()); receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if closeErr := first.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	changed := newCensusPeer()
	changed.boot = strings.Repeat("c", 32)
	second := f.dial(t, changed)
	snapshot, snapshotErr := f.hub.Snapshot("device-one")
	if snapshotErr != nil || !snapshot.Online || snapshot.RoutingReady || second.RoutingReady() {
		t.Fatal("changed process became execution-ready or lost admin connection")
	}
	if f.status(t, second.Generation()).Outstanding != 1 {
		t.Fatal("changed process erased old routing owner")
	}
	_, reserveErr := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	requireError(t, reserveErr, ErrNotReady)
	if reportErr := second.ReportCapabilities(t.Context(), protocol.CapabilityReport{ObservedAt: f.clock.now()}); reportErr != nil {
		t.Fatal("blocked online session cannot carry metadata/admin recovery")
	}
}
