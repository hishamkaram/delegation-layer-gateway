package transport

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestNegotiatedWireVersionIsUsedForHandshakeAndReplies(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			f, client := negotiatedVersionClient(t, version)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := f.hub.WaitReady(ctx, "device-one"); err != nil {
				t.Fatal(err)
			}
			snapshot, err := f.hub.Snapshot("device-one")
			if err != nil || snapshot.WireVersion != version || client.WireVersion() != version {
				t.Fatal("negotiated protocol was not bound to both peers")
			}
			assertNegotiatedExchange(t, ctx, f, client, version)
		})
	}
}

func negotiatedVersionClient(t *testing.T, version int) (*fixture, *Client) {
	t.Helper()
	f := newVersionFixture(t, Settings{}, true)
	cfg := f.config()
	cfg.WireVersion = version
	if version == 2 {
		cfg.Capabilities = protocol.CapabilityReport{}
		cfg.CapabilitiesV2 = &protocol.CapabilityReportV2{ObservedAt: f.clock.now()}
	}
	client, err := Dial(t.Context(), cfg, f.http, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return f, client
}

func assertNegotiatedExchange(t *testing.T, ctx context.Context, f *fixture, client *Client, version int) {
	t.Helper()
	request := inspect(t)
	request.Version = version
	r, err := f.hub.Reserve(ctx, "device-one", request)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Publish(ctx, allowed); err != nil {
		t.Fatal(err)
	}
	received, err := client.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := received.Claim(ctx)
	if err != nil || frame.Version != version {
		t.Fatal("request changed negotiated wire version")
	}
	if err = received.Reply(ctx, protocol.Reply{Operation: protocol.ContextInspect, Body: payload(t, struct {
		OK bool `json:"ok"`
	}{true})}); err != nil {
		t.Fatal(err)
	}
	reply, err := r.Await(ctx)
	if err != nil || reply.Version != version || reply.RequestID != frame.RequestID {
		t.Fatal("reply changed negotiated identity")
	}
	request.Version = 3 - version
	if _, err = f.hub.Reserve(ctx, "device-one", request); err == nil {
		t.Fatal("outgoing frame with wrong version accepted")
	}
}

func TestV2ClientNeverSilentlyFallsBackToV1(t *testing.T) {
	f := newFixture(t, Settings{})
	cfg := f.config()
	cfg.WireVersion = 2
	cfg.Capabilities = protocol.CapabilityReport{}
	cfg.CapabilitiesV2 = &protocol.CapabilityReportV2{ObservedAt: f.clock.now()}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, cfg, f.http, f.clock.now)
	if err == nil {
		if closeErr := client.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("v2 client silently used a legacy session")
	}
}
