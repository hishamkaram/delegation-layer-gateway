package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/tlsconfig"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

type gatedSigner struct {
	next    enrollment.Signer
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *gatedSigner) Sign(ctx context.Context, intent domain.IssuanceIntent, csr []byte, serial *big.Int, random io.Reader) ([]byte, error) {
	s.once.Do(func() { close(s.started) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.release:
		return s.next.Sign(ctx, intent, csr, serial, random)
	}
}

func TestRenewalSupersessionDuringSigningNeverRepliesOnOldGeneration(t *testing.T) {
	f := configFixture(t)
	clock := &testClock{value: time.Now().UTC().Truncate(time.Second).Add(-21 * 24 * time.Hour)}
	f.now = clock.now
	f.construct(t)
	bundle, err := tlsconfig.Load(f.cfg.TLS, f.cfg.DeviceCA, "localhost", clock.now())
	require(t, err)
	gate := &gatedSigner{next: bundle.Authority, started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	t.Cleanup(release)
	replacement, err := enrollment.New(f.runtime.store, gate, rand.Reader, clock.now)
	f.runtime.enrollment = checked(t, replacement, err)
	f.serve(t)
	store, certificate := f.enrollDevice(t)
	clock.set(time.Now().UTC().Truncate(time.Second))
	roots := x509.NewCertPool()
	roots.AddCert(f.deviceCA.certificate)
	_, ref, err := store.Certificate(roots, time.Now())
	require(t, err)
	intent, err := store.BeginRenewal(ref, rand.Reader)
	require(t, err)
	endpoint := strings.Replace(f.deviceURL(t), "https://", "wss://", 1)
	dialed, err := transport.Dial(t.Context(), transport.ClientConfig{URL: endpoint, GatewayID: f.runtime.gatewayID, Certificate: certificate.Leaf, Capabilities: protocol.CapabilityReport{ObservedAt: clock.now()}, Routing: &emptyCensus{boot: strings.Repeat("a", 32)}}, f.deviceHTTP(t, &certificate), clock.now)
	peer := checked(t, dialed, err)
	t.Cleanup(func() { require(t, peer.Close()) })
	payload, err := protocol.Encode(protocol.Renewal{DeviceID: "device", RenewalID: intent.ID, CredentialGeneration: ref.Generation, CSRDERBase64: base64.StdEncoding.EncodeToString(intent.CSRDER)}, 32<<10)
	require(t, err)
	reserved, err := peer.Reserve(t.Context(), protocol.Frame{Version: 1, Type: protocol.RenewCertificate, TTLMillis: 30000, Payload: payload})
	buffer := checked(t, reserved, err)
	require(t, buffer.Publish(t.Context(), nil))
	select {
	case <-gate.started:
	case <-time.After(5 * time.Second):
		t.Fatal("actual issuance did not reach signing gate")
	}
	_, err = f.runtime.store.NextConnectionGeneration(t.Context(), ref, "superseding-gateway", clock.now())
	require(t, err)
	release()
	waitRenewedCredential(t, f, ref, clock.now()) // The durable receipt remains committed.
	observation, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if _, err = buffer.Await(observation); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("old-generation renewal reply escaped: %v", err)
	}
	pending, err := store.PendingRenewal()
	require(t, err)
	if pending.ID != intent.ID {
		t.Fatal("response uncertainty erased connector renewal intent")
	}
}

func waitRenewedCredential(t *testing.T, f *fixture, ref domain.CredentialRef, minimum time.Time) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		credential, err := f.runtime.store.CheckCredential(t.Context(), ref, f.now())
		if err == nil && !credential.NotBefore.Before(minimum) {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("durable renewed certificate not activated")
		}
	}
}
