package transport

import (
	"context"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestDisconnectGenerationPreservesReplacementAfterDrainCommit(t *testing.T) {
	f := newFixture(t, Settings{})
	first := f.dial(t)
	capturedCredential, capturedGeneration := f.store.value.Ref, first.Generation()
	if closeErr := first.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	waitRetired(t, f.hub)
	replacement := f.dial(t)
	if replacement.Generation() == capturedGeneration {
		t.Fatal("fixture did not reconnect after the captured drain")
	}
	disconnectErr := f.hub.DisconnectGeneration(t.Context(), capturedCredential, capturedGeneration)
	requireError(t, disconnectErr, ErrNoSession)
	protectedOperationRoundTrip(t, f, replacement, protocol.Status)
	wrongCredential := capturedCredential
	wrongCredential.Epoch = "another-credential-epoch"
	disconnectErr = f.hub.DisconnectGeneration(t.Context(), wrongCredential, replacement.Generation())
	requireError(t, disconnectErr, ErrNoSession)
	protectedOperationRoundTrip(t, f, replacement, protocol.Status)
	if disconnectErr = f.hub.DisconnectGeneration(t.Context(), capturedCredential, replacement.Generation()); disconnectErr != nil {
		t.Fatal(disconnectErr)
	}
	waitSessionJoined(t, replacement.session)
}

func TestDisconnectGenerationRetainsOwnershipUntilJoined(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release) })
	reservation, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if publishErr := reservation.Publish(t.Context(), func(context.Context, Metadata) error { close(entered); <-release; return nil }); publishErr != nil {
		t.Fatal(publishErr)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("writer did not enter owned gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	err = f.hub.DisconnectGeneration(ctx, f.store.value.Ref, client.Generation())
	requireError(t, err, ErrExpired)
	original := gatewaySession(t, f)
	select {
	case <-original.done:
		t.Fatal("deadline reported join while writer still owned work")
	default:
	}
}
