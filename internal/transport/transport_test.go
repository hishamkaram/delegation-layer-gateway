package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type clock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.value = c.value.Add(d) }

type credentialStore struct {
	mu      sync.Mutex
	value   domain.Credential
	revoked bool
	counter uint64
}

func (s *credentialStore) CheckCredential(ctx context.Context, ref domain.CredentialRef, now time.Time) (domain.Credential, error) {
	if checkErr := ctx.Err(); checkErr != nil {
		return domain.Credential{}, checkErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || ref != s.value.Ref || now.Before(s.value.NotBefore) || !now.Before(s.value.NotAfter) {
		return domain.Credential{}, domain.Reject(domain.Forbidden)
	}
	return s.value, nil
}

func (s *credentialStore) NextConnectionGeneration(ctx context.Context, ref domain.CredentialRef, boot domain.BootEpoch, now time.Time) (domain.ConnectionGeneration, error) {
	if _, checkErr := s.CheckCredential(ctx, ref, now); checkErr != nil {
		return domain.ConnectionGeneration{}, checkErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	return domain.ConnectionGeneration{BootEpoch: boot, Counter: s.counter}, nil
}
func (s *credentialStore) revoke() { s.mu.Lock(); defer s.mu.Unlock(); s.revoked = true }

type fixture struct {
	hub         *Hub
	server      *httptest.Server
	http        *http.Client
	certificate *x509.Certificate
	clock       *clock
	store       *credentialStore
	settings    Settings
}

func privateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func parseCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func newFixture(t *testing.T, settings Settings) *fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	caKey := privateKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate := parseCertificate(t, caDER)
	ca, err := identity.NewCertificateAuthority(caCertificate, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key := privateKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := identity.ParseCSR(csr)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.CredentialRef{Device: "device-one", Epoch: "epoch-one", Generation: 1}
	intent := domain.IssuanceIntent{ID: "issuance-one", Credential: ref, Mode: domain.Regular, Serial: []byte{1, 2, 3}, CSRHash: info.CSRHash, PublicKeyHash: info.PublicKeyHash, NotBefore: now, NotAfter: now.Add(domain.CertificateLifetime)}
	leafDER, err := ca.Sign(t.Context(), intent, csr, new(big.Int).SetBytes(intent.Serial), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseCertificate(t, leafDER)
	clock := &clock{value: time.Now()}
	store := &credentialStore{value: domain.Credential{Ref: ref, Mode: domain.Regular, PublicKeyHash: info.PublicKeyHash, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}}
	hub, err := NewHub(t.Context(), Config{GatewayID: "gateway-one", BootEpoch: "boot-one", Settings: settings}, store, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := hub.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	server := httptest.NewUnstartedServer(hub)
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	httpClient := *server.Client()
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected test transport")
	}
	owned := transport.Clone()
	owned.TLSClientConfig = transport.TLSClientConfig.Clone()
	owned.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key, Leaf: leaf}}
	httpClient.Transport = owned
	t.Cleanup(owned.CloseIdleConnections)
	return &fixture{hub: hub, server: server, http: &httpClient, certificate: leaf, clock: clock, store: store, settings: settings}
}

func (f *fixture) config() ClientConfig {
	return ClientConfig{URL: "wss" + strings.TrimPrefix(f.server.URL, "https"), GatewayID: "gateway-one", Certificate: f.certificate, Capabilities: protocol.CapabilityReport{ObservedAt: f.clock.now()}, Settings: f.settings}
}

func (f *fixture) dial(t *testing.T) *Client {
	t.Helper()
	client, err := Dial(t.Context(), f.config(), f.http, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if checkErr := f.hub.WaitReady(ctx, "device-one"); checkErr != nil {
		t.Fatal(checkErr)
	}
	return client
}

func payload(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := protocol.Encode(value, protocol.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func inspect(t *testing.T) protocol.Frame {
	t.Helper()
	return protocol.Frame{Version: protocol.Version, Type: protocol.Request, OperationID: "operation-one", TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload(t, protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: payload(t, protocol.InspectRequest{GatewayID: "gateway-one"})})}
}
func allowed(context.Context, Metadata) error { return nil }
func requireError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error=%v, want %v", err, want)
	}
}

func TestReservedFrameWaitsForPublishAndCorrelatesReply(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	r, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	metadata := r.Frame()
	assertMetadata(t, metadata, client.Generation())
	before, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = client.Receive(before)
	requireError(t, err, context.DeadlineExceeded)
	var committed atomic.Bool
	guard := func(context.Context, Metadata) error {
		if !committed.Load() {
			return ErrForbidden
		}
		return nil
	}
	committed.Store(true)
	if checkErr := r.Publish(t.Context(), guard); checkErr != nil {
		t.Fatal(checkErr)
	}
	requireError(t, r.Publish(t.Context(), guard), ErrConflict)
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	frame, err := received.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if frame.RequestID != metadata.RequestID || frame.Generation != wireGeneration(metadata.Connection) || frame.OperationID != metadata.OperationID {
		t.Fatal("wire identity changed after possible-send commit")
	}
	if checkErr := received.Reply(t.Context(), protocol.Reply{Operation: protocol.ContextInspect, Body: payload(t, struct {
		OK bool `json:"ok"`
	}{true})}); checkErr != nil {
		t.Fatal(err)
	}
	response, err := r.Await(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestID != metadata.RequestID || response.Type != protocol.Response {
		t.Fatal("uncorrelated response")
	}
}

func assertMetadata(t *testing.T, metadata Metadata, generation domain.ConnectionGeneration) {
	t.Helper()
	if metadata.Connection != generation || metadata.Credential.Device != "device-one" || metadata.EncodedFrameBytes <= 0 {
		t.Fatal("wrong accounting metadata")
	}
}

func TestQueueReservationsBoundBeforeAnyPublish(t *testing.T) {
	f := newFixture(t, Settings{})
	f.dial(t)
	var reservations []*Reservation
	for range QueueFrames - ProtectedFrames {
		r, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, r)
	}
	_, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	requireError(t, err, ErrCapacity)
	for range ProtectedFrames {
		r, reserveErr := f.hub.Reserve(t.Context(), "device-one", protectedControl(t, protocol.FenceAbsent))
		if reserveErr != nil {
			t.Fatal(reserveErr)
		}
		reservations = append(reservations, r)
	}
	_, err = f.hub.Reserve(t.Context(), "device-one", protectedControl(t, protocol.Cancel))
	requireError(t, err, ErrCapacity)
	for _, r := range reservations {
		if checkErr := r.Release(); checkErr != nil {
			t.Fatal(checkErr)
		}
	}
	large := inspect(t)
	large.Payload = payload(t, protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: payload(t, struct {
		Padding string `json:"padding"`
	}{strings.Repeat("x", 600<<10)})})
	r, err := f.hub.Reserve(t.Context(), "device-one", large)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.hub.Reserve(t.Context(), "device-one", large)
	requireError(t, err, ErrCapacity)
	if checkErr := r.Release(); checkErr != nil {
		t.Fatal(checkErr)
	}
}

func TestAwaitCancellationAndPrewriteDenialKeepSession(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	r, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if checkErr := r.Publish(t.Context(), func(context.Context, Metadata) error { return ErrForbidden }); checkErr != nil {
		t.Fatal(checkErr)
	}
	_, err = r.Await(t.Context())
	requireError(t, err, ErrForbidden)
	r, err = f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if checkErr := r.Publish(t.Context(), allowed); checkErr != nil {
		t.Fatal(checkErr)
	}
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, checkErr := received.Claim(t.Context()); checkErr != nil {
		t.Fatal(checkErr)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = r.Await(ctx)
	requireError(t, err, context.Canceled)
	if checkErr := received.Reply(t.Context(), protocol.Reply{Operation: protocol.ContextInspect, Body: payload(t, struct {
		OK bool `json:"ok"`
	}{true})}); checkErr != nil {
		t.Fatal(err)
	}
	if checkErr := client.ReportCapabilities(t.Context(), protocol.CapabilityReport{ObservedAt: f.clock.now()}); checkErr != nil {
		t.Fatal("Await cancelled the reader:", checkErr)
	}
}

func TestClaimExpiresLocallyAndDuplicateIdentityRejected(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	_, err := Dial(t.Context(), f.config(), f.http, f.clock.now)
	requireError(t, err, ErrOffline)
	frame := inspect(t)
	frame.TTLMillis = 1
	r, err := f.hub.Reserve(t.Context(), "device-one", frame)
	if err != nil {
		t.Fatal(err)
	}
	if checkErr := r.Publish(t.Context(), allowed); checkErr != nil {
		t.Fatal(checkErr)
	}
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Second)
	_, err = received.Claim(t.Context())
	requireError(t, err, ErrExpired)
	if checkErr := f.hub.Disconnect("device-one"); checkErr != nil {
		t.Fatal(checkErr)
	}
}

func TestRevocationBetweenGuardAndWriteClosesWithoutExecution(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	r, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if checkErr := r.Publish(t.Context(), func(context.Context, Metadata) error { f.store.revoke(); return nil }); checkErr != nil {
		t.Fatal(checkErr)
	}
	_, err = r.Await(t.Context())
	if !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrOffline) {
		t.Fatalf("revocation was ignored: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = client.Receive(ctx)
	requireError(t, err, ErrOffline)
}

func TestGlobalBudgetHasOneAccountingOwner(t *testing.T) {
	var shared budget
	sessions := make([]*session, 8)
	for i := range sessions {
		sessions[i] = &session{}
		for range DeviceQueueBytes / MaxProtectedFrameBytes {
			if !shared.acquire(sessions[i], MaxProtectedFrameBytes, protectedTraffic) {
				t.Fatal("expected configured total capacity")
			}
		}
	}
	if shared.acquire(&session{}, 1, protectedTraffic) {
		t.Fatal("aggregate 8MiB bound exceeded")
	}
	if shared.acquire(sessions[0], 1, protectedTraffic) {
		t.Fatal("device 1MiB bound exceeded")
	}
	for _, s := range sessions {
		shared.release(s, 1<<20)
		if s.bytes != 0 {
			t.Fatal("device reservation leaked")
		}
	}
	if shared.used != 0 {
		t.Fatal("aggregate reservation leaked")
	}
}

func (f *fixture) raw(t *testing.T) (*websocket.Conn, *session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx, f.config().URL, &websocket.DialOptions{HTTPClient: f.http, Subprotocols: []string{protocol.Subprotocol}, CompressionMode: websocket.CompressionContextTakeover})
	if response != nil && response.Body != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := conn.CloseNow(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Error(closeErr)
		}
	})
	if response.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatal("compression was enabled")
	}
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := protocol.DecodeFrame(data)
	if err != nil {
		t.Fatal(err)
	}
	if checkErr := conn.Write(ctx, websocket.MessageText, data); checkErr != nil {
		t.Fatal(checkErr)
	}
	capabilities := protocol.Frame{Version: protocol.Version, Type: protocol.Capabilities, RequestID: "d:1", Generation: hello.Generation, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload(t, protocol.CapabilityReport{ObservedAt: f.clock.now()})}
	writeRaw(t, conn, capabilities)
	if checkErr := f.hub.WaitReady(ctx, "device-one"); checkErr != nil {
		t.Fatal(checkErr)
	}
	s, err := f.hub.current("device-one")
	if err != nil {
		t.Fatal(err)
	}
	return conn, s
}

func writeRaw(t *testing.T, conn *websocket.Conn, frame protocol.Frame) {
	t.Helper()
	data, err := protocol.EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if checkErr := conn.Write(t.Context(), websocket.MessageText, data); checkErr != nil {
		t.Fatal(checkErr)
	}
}

func waitClosed(t *testing.T, s *session) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("session children did not join")
	}
}

func TestWrongGenerationAndDuplicateResponseFailClosed(t *testing.T) {
	for _, test := range []string{"wrong generation", "duplicate reply"} {
		t.Run(test, func(t *testing.T) {
			f := newFixture(t, Settings{})
			conn, s := f.raw(t)
			r, reply := rawInspectionReply(t, f, conn)
			if test == "wrong generation" {
				reply.Generation.Counter++
			}
			writeRaw(t, conn, reply)
			if test == "duplicate reply" {
				if _, checkErr := r.Await(t.Context()); checkErr != nil {
					t.Fatal(checkErr)
				}
				writeRaw(t, conn, reply)
			}
			waitClosed(t, s)
			s.mu.Lock()
			protocolErr := s.err
			s.mu.Unlock()
			requireError(t, protocolErr, ErrProtocol)
		})
	}
}

func rawInspectionReply(t *testing.T, f *fixture, conn *websocket.Conn) (*Reservation, protocol.Frame) {
	t.Helper()
	r, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if checkErr := r.Publish(t.Context(), allowed); checkErr != nil {
		t.Fatal(checkErr)
	}
	_, data, err := conn.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.DecodeFrame(data)
	if err != nil {
		t.Fatal(err)
	}
	reply := request
	reply.Type = protocol.Response
	reply.Payload = payload(t, protocol.Reply{Operation: protocol.ContextInspect, Body: payload(t, struct {
		OK bool `json:"ok"`
	}{true})})
	return r, reply
}

func TestHeartbeatOwnsOfflineClosureAndCleanup(t *testing.T) {
	f := newFixture(t, Settings{HeartbeatInterval: 15 * time.Millisecond, OfflineTimeout: 60 * time.Millisecond})
	_, s := f.raw(t)
	// This peer deliberately stops reading, so websocket ping cannot get a pong.
	waitClosed(t, s)
	s.mu.Lock()
	remaining := s.bytes
	s.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("closed session retained %d reserved bytes", remaining)
	}
}

func TestMissingMTLSCertificateCannotCreateSession(t *testing.T) {
	f := newFixture(t, Settings{})
	_, err := Dial(t.Context(), f.config(), f.server.Client(), f.clock.now)
	requireError(t, err, ErrOffline)
	f.hub.mu.Lock()
	count := len(f.hub.sessions)
	f.hub.mu.Unlock()
	if count != 0 {
		t.Fatal("unverified peer registered a session")
	}
}

func renewalFrame(t *testing.T) protocol.Frame {
	t.Helper()
	key := privateKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Frame{Version: protocol.Version, Type: protocol.RenewCertificate, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload(t, protocol.Renewal{DeviceID: "device-one", RenewalID: strings.Repeat("a", 32), CredentialGeneration: 1, CSRDERBase64: base64.StdEncoding.EncodeToString(csr)})}
}

func publishRenewal(t *testing.T, client *Client, frame protocol.Frame) *Reservation {
	t.Helper()
	reservation, err := client.Reserve(t.Context(), frame)
	if err != nil {
		t.Fatal(err)
	}
	if publishErr := reservation.Publish(t.Context(), nil); publishErr != nil {
		t.Fatal(publishErr)
	}
	return reservation
}

func claimRenewal(t *testing.T, hub *Hub) (*Received, protocol.Frame) {
	t.Helper()
	received, err := hub.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	frame, err := received.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return received, frame
}

func TestRenewalKeepsPayloadIdentityAcrossLostReplyAndReconnect(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	if reportErr := client.ReportCapabilities(t.Context(), protocol.CapabilityReport{ObservedAt: f.clock.now()}); reportErr != nil {
		t.Fatal(reportErr)
	}
	frame := renewalFrame(t)
	first := publishRenewal(t, client, frame)
	lost, firstWire := claimRenewal(t, f.hub)
	if closeErr := f.hub.Disconnect("device-one"); closeErr != nil {
		t.Fatal(closeErr)
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	_, err := first.Await(t.Context())
	requireError(t, err, ErrOffline)
	result := protocol.RenewalResult{DeviceID: "device-one", RenewalID: strings.Repeat("a", 32), Epoch: "epoch-one", Generation: 1, CertificateDERBase64: base64.StdEncoding.EncodeToString(f.certificate.Raw)}
	requireError(t, lost.ReplyRenewal(t.Context(), result), ErrOffline)
	secondClient := f.dial(t)
	second := publishRenewal(t, secondClient, frame)
	received, secondWire := claimRenewal(t, f.hub)
	assertRenewalReplay(t, firstWire, secondWire)
	invalid := result
	invalid.Error = &protocol.Failure{Code: "pending", Retryable: true}
	requireError(t, received.ReplyRenewal(t.Context(), invalid), ErrProtocol)
	failure := protocol.RenewalResult{DeviceID: result.DeviceID, RenewalID: result.RenewalID, Error: &protocol.Failure{Code: "pending", Retryable: true}}
	if replyErr := received.ReplyRenewal(t.Context(), failure); replyErr != nil {
		t.Fatal(replyErr)
	}
	response, err := second.Await(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var decoded protocol.RenewalResult
	if decodeErr := protocol.DecodeStrict(response.Payload, &decoded, protocol.MaxFrameBytes); decodeErr != nil || decoded.Error == nil {
		t.Fatal("typed renewal failure was lost")
	}
	third := publishRenewal(t, secondClient, frame)
	completed, _ := claimRenewal(t, f.hub)
	if replyErr := completed.ReplyRenewal(t.Context(), result); replyErr != nil {
		t.Fatal(replyErr)
	}
	if _, replyErr := third.Await(t.Context()); replyErr != nil {
		t.Fatal(replyErr)
	}
}

func assertRenewalReplay(t *testing.T, first, second protocol.Frame) {
	t.Helper()
	if first.Generation == second.Generation || first.RequestID == second.RequestID || string(first.Payload) != string(second.Payload) {
		t.Fatal("reconnect did not preserve renewal payload with fresh transport identity")
	}
}

func TestDisconnectDropsUnclaimedFrameAndOldReservation(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	r, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	old, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if publishErr := r.Publish(t.Context(), allowed); publishErr != nil {
		t.Fatal(publishErr)
	}
	received, err := client.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := f.hub.Disconnect("device-one"); closeErr != nil {
		t.Fatal(closeErr)
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	_, err = received.Claim(t.Context())
	requireError(t, err, ErrOffline)
	requireError(t, old.Publish(t.Context(), allowed), ErrOffline)
	newClient := f.dial(t)
	if newClient.Generation().Counter <= client.Generation().Counter {
		t.Fatal("connection generation was reused")
	}
}

func TestRecoveryCredentialCannotCarryAdmission(t *testing.T) {
	f := newFixture(t, Settings{})
	f.store.mu.Lock()
	f.store.value.Mode = domain.RecoveryOnly
	f.store.mu.Unlock()
	f.dial(t)
	frame := inspect(t)
	frame.Payload = payload(t, protocol.Command{Operation: protocol.Admit, Project: "project-one", Body: json.RawMessage(`{}`)})
	_, err := f.hub.Reserve(t.Context(), "device-one", frame)
	requireError(t, err, ErrForbidden)
	read, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	if err != nil {
		t.Fatal(err)
	}
	if releaseErr := read.Release(); releaseErr != nil {
		t.Fatal(releaseErr)
	}
}

func TestCredentialExpiryIsCheckedAfterHandshake(t *testing.T) {
	f := newFixture(t, Settings{})
	client := f.dial(t)
	f.clock.advance(domain.CertificateLifetime + time.Minute)
	_, err := f.hub.Reserve(t.Context(), "device-one", inspect(t))
	requireError(t, err, ErrForbidden)
	err = client.ReportCapabilities(t.Context(), protocol.CapabilityReport{ObservedAt: f.clock.now()})
	requireError(t, err, ErrForbidden)
}

func TestMalformedRenewalReplyCannotResolvePendingCall(t *testing.T) {
	for _, name := range []string{"wrong stable identity", "mixed failure and success"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Settings{})
			client := f.dial(t)
			reservation := publishRenewal(t, client, renewalFrame(t))
			received, _ := claimRenewal(t, f.hub)
			result := protocol.RenewalResult{DeviceID: "device-one", RenewalID: strings.Repeat("a", 32), Error: &protocol.Failure{Code: "pending", Retryable: true}}
			if name == "wrong stable identity" {
				result.RenewalID = strings.Repeat("b", 32)
			} else {
				result.Epoch = "epoch-one"
			}
			// Fault injection bypasses only the sender's validator, exercising the
			// production receiver over real WSS with invalid peer-controlled bytes.
			sendErr := received.reply(t.Context(), protocol.RenewCertificateResult, payload(t, result))
			if sendErr != nil && !errors.Is(sendErr, ErrOffline) {
				t.Fatal(sendErr)
			}
			_, err := reservation.Await(t.Context())
			requireError(t, err, ErrProtocol)
		})
	}
}
