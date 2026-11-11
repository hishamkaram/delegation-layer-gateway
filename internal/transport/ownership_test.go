package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDisconnectContextRetainsClosingSessionUntilActualJoin(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	r, reserveErr := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if reserveErr != nil {
		t.Fatal(reserveErr)
	}
	// Owned fault gate deliberately ignores cancellation; the test creator releases
	// and joins it. A caller deadline must never manufacture a completed join.
	guard := func(context.Context, Metadata) error { close(entered); <-release; return nil }
	if publishErr := r.Publish(t.Context(), guard); publishErr != nil {
		t.Fatal(publishErr)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("writer did not enter owned gate")
	}
	f.hub.mu.Lock()
	original := f.hub.sessions["device-one"]
	f.hub.mu.Unlock()
	for range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		disconnectErr := f.hub.DisconnectContext(ctx, "device-one")
		cancel()
		requireError(t, disconnectErr, ErrExpired)
	}
	select {
	case <-original.done:
		t.Fatal("deadline discarded unsettled worker")
	default:
	}
	unblock()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	disconnectErr := f.hub.DisconnectContext(ctx, "device-one")
	if disconnectErr != nil && !errors.Is(disconnectErr, ErrNoSession) {
		t.Fatal(disconnectErr)
	}
	select {
	case <-original.done:
	default:
		t.Fatal("disconnect acknowledged before actual worker join")
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestReceivedMetadataKeepsOriginalAuthenticatedBindingAfterClaim(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	reservation := publishRenewal(t, client, renewalFrame(t))
	received, frame := claimRenewal(t, f.hub)
	metadata := received.Metadata()
	if metadata.Credential != f.store.value.Ref || metadata.Connection != client.Generation() || metadata.RequestID != frame.RequestID || metadata.EncodedFrameBytes <= 0 {
		t.Fatal("received metadata lost original authenticated binding")
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	newer := f.dial(t)
	if newer.Generation() == metadata.Connection {
		t.Fatal("fixture did not supersede socket generation")
	}
	retained := received.Metadata()
	if retained != metadata {
		t.Fatal("received binding followed a newer session or cleared after Claim")
	}
	_, awaitErr := reservation.Await(t.Context())
	requireError(t, awaitErr, ErrOffline)
}

func waitRetired(t *testing.T, hub *Hub) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		hub.mu.Lock()
		remaining := hub.sessions["device-one"] != nil
		hub.mu.Unlock()
		if !remaining {
			return
		}
		select {
		case <-timer.C:
			t.Fatal("old socket owner did not retire")
		case <-ticker.C:
		}
	}
}
