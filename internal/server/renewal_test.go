package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

type testClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *testClock) now() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *testClock) set(now time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.value = now }
func TestRuntimeRenewalReceiverUsesStableSemanticID(t *testing.T) {
	f := configFixture(t)
	clock := &testClock{value: time.Now().UTC().Truncate(time.Second).Add(-21 * 24 * time.Hour)}
	f.now = clock.now
	f.start(t)
	store, certificate := f.enrollDevice(t)
	clock.set(time.Now().UTC().Truncate(time.Second))
	roots := x509.NewCertPool()
	roots.AddCert(f.deviceCA.certificate)
	_, ref, err := store.Certificate(roots, time.Now())
	require(t, err)
	intent, err := store.BeginRenewal(ref, rand.Reader)
	require(t, err)
	endpoint := strings.Replace(f.deviceURL(t), "https://", "wss://", 1)
	client, err := transport.Dial(t.Context(), transport.ClientConfig{URL: endpoint, GatewayID: f.runtime.gatewayID, Certificate: certificate.Leaf, Capabilities: protocol.CapabilityReport{ObservedAt: clock.now()}, Routing: &emptyCensus{boot: strings.Repeat("a", 32)}}, f.deviceHTTP(t, &certificate), clock.now)
	peer := checked(t, client, err)
	t.Cleanup(func() { require(t, peer.Close()) })
	request := protocol.Renewal{DeviceID: "device", RenewalID: intent.ID, CredentialGeneration: ref.Generation, CSRDERBase64: base64.StdEncoding.EncodeToString(intent.CSRDER)}
	first := renewThroughClient(t, peer, request)
	second := renewThroughClient(t, peer, request)
	if first.RenewalID != intent.ID || second.CertificateDERBase64 != first.CertificateDERBase64 || first.Epoch != string(ref.Epoch) || first.Generation != ref.Generation {
		t.Fatal("wire retry ID replaced durable renewal identity/certificate")
	}
	der, err := base64.StdEncoding.DecodeString(first.CertificateDERBase64)
	require(t, err)
	require(t, store.CompleteRenewal(intent.ID, der, roots, time.Now()))
	if _, err = store.PendingRenewal(); !errors.Is(err, deviceidentity.ErrAbsent) {
		t.Fatal("renewal completion not persisted")
	}
	leaf, _, err := store.Certificate(roots, time.Now())
	require(t, err)
	if leaf.Leaf.NotBefore.Before(clock.now().Add(-time.Minute)) {
		t.Fatal("renewal receiver returned old certificate")
	}
}

func renewThroughClient(t *testing.T, client *transport.Client, request protocol.Renewal) protocol.RenewalResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	payload, err := protocol.Encode(request, 32<<10)
	require(t, err)
	reservation, err := client.Reserve(ctx, protocol.Frame{Version: 1, Type: protocol.RenewCertificate, TTLMillis: 30000, Payload: payload})
	buffer := checked(t, reservation, err)
	require(t, buffer.Publish(ctx, nil))
	frame, err := buffer.Await(ctx)
	response := checked(t, frame, err)
	var result protocol.RenewalResult
	require(t, protocol.DecodeStrict(response.Payload, &result, 32<<10))
	require(t, result.Validate())
	if result.Error != nil {
		t.Fatalf("renewal denied: %s", result.Error.Code)
	}
	return result
}
