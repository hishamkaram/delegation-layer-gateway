package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestUnstartedInboundSessionRemainsOwnedUntilClose(t *testing.T) {
	f := newFixture(t, Settings{})
	peer, err := f.hub.RegisterPeer(f.certificate, f.store.value.Ref, f.store.value)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := peer.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err = f.hub.DisconnectContext(ctx, "device-one"); !errors.Is(err, ErrExpired) {
		t.Fatal("unstarted socket resource escaped its caller's close/join")
	}
	if _, err = f.hub.RegisterPeer(f.certificate, f.store.value.Ref, f.store.value); !errors.Is(err, ErrConflict) {
		t.Fatal("closing unjoined resource allowed replacement")
	}
	if err = peer.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := f.hub.RegisterPeer(f.certificate, f.store.value.Ref, f.store.value)
	if err != nil {
		t.Fatal(err)
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInboundGenerationNeverRebinds(t *testing.T) {
	f := newFixture(t, Settings{})
	peer, err := f.hub.RegisterPeer(f.certificate, f.store.value.Ref, f.store.value)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := peer.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	first := domain.ConnectionGeneration{BootEpoch: "boot-one", Counter: 1}
	if err = peer.SetGeneration(first); err != nil {
		t.Fatal(err)
	}
	if err = peer.SetGeneration(first); err != nil {
		t.Fatal(err)
	}
	if err = peer.SetGeneration(domain.ConnectionGeneration{BootEpoch: "boot-one", Counter: 2}); !errors.Is(err, ErrConflict) {
		t.Fatal("connection generation rebound")
	}
	snapshot, err := peer.Snapshot()
	if err != nil || snapshot.Generation != first {
		t.Fatal("rejected generation changed captured identity")
	}
}

func TestTransportErrorAdapterPreservesCauseWithoutFormattingUnknownClass(t *testing.T) {
	cause := errors.New("private cause")
	err := NewError(errors.New("private unknown class"), cause)
	if err.Error() != "protocol_error" || strings.Contains(err.Error(), "private") {
		t.Fatal("adapter exposed a non-classification error")
	}
	if !errors.Is(err, cause) {
		t.Fatal("adapter lost original cause")
	}
}
