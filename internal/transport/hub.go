package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Hub owns current sessions. Registry owns credential validity and durable
// connection counters; snapshots below are only dated transport observations.
type Hub struct {
	ctx      context.Context
	cancel   context.CancelFunc
	config   Config
	store    CredentialStore
	now      func() time.Time
	budget   budget
	incoming chan *Received
	mu       sync.Mutex
	closed   bool
	sessions map[domain.DeviceID]*session
	workers  sync.WaitGroup
}

type Snapshot struct {
	CredentialMode         domain.CredentialMode
	ProcessBoot            string
	RoutingReady           bool
	Credential             domain.CredentialRef
	Generation             domain.ConnectionGeneration
	LastSeen               time.Time
	Online                 bool
	Capabilities           protocol.CapabilityReport
	CapabilitiesObservedAt time.Time
}

func NewHub(ctx context.Context, config Config, store CredentialStore, now func() time.Time) (*Hub, error) {
	if ctx == nil || store == nil || now == nil || (protocol.HelloBody{GatewayID: string(config.GatewayID), DeviceID: "check"}).Validate() != nil || wireGeneration(domain.ConnectionGeneration{BootEpoch: config.BootEpoch, Counter: 1}).Validate() != nil {
		return nil, fail(ErrProtocol, nil)
	}
	checked, err := settings(config.Settings)
	if err != nil {
		return nil, err
	}
	config.Settings = checked
	owned, cancel := context.WithCancel(ctx)
	return &Hub{ctx: owned, cancel: cancel, config: config, store: store, now: now, incoming: make(chan *Received, QueueFrames), sessions: make(map[domain.DeviceID]*session)}, nil
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	preflight, cancel := context.WithTimeout(r.Context(), h.config.Settings.HandshakeTimeout)
	defer cancel()
	request := r.WithContext(preflight)
	s, err := h.register(preflight, request)
	if err != nil {
		http.Error(w, "device connection rejected", http.StatusForbidden)
		return
	}
	ran := false
	defer func() {
		s.stop(fail(ErrOffline, nil))
		if !ran {
			s.finish()
		}
		h.retire(s)
	}()
	generation, err := h.store.NextConnectionGeneration(preflight, s.ref, h.config.BootEpoch, h.now())
	if err != nil {
		http.Error(w, "device connection rejected", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	s.generation = generation
	s.mu.Unlock()
	conn, err := websocket.Accept(w, request, &websocket.AcceptOptions{Subprotocols: []string{protocol.Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	s.mu.Lock()
	s.conn = conn
	closing := s.closing
	s.mu.Unlock()
	if closing {
		if closeErr := conn.CloseNow(); closeErr != nil {
			s.recordCloseError(closeErr)
		}
		return
	}
	conn.SetReadLimit(protocol.MaxFrameBytes)
	if conn.Subprotocol() != protocol.Subprotocol {
		return
	}
	if checkErr := h.handshake(preflight, s); checkErr != nil {
		s.stop(checkErr)
		return
	}
	close(s.ready)
	ran = true
	s.run(r.Context())
}

func (h *Hub) register(ctx context.Context, r *http.Request) (*session, error) {
	certificate, ref, err := verifiedPeer(r)
	if err != nil {
		return nil, err
	}
	if (protocol.HelloBody{GatewayID: string(h.config.GatewayID), DeviceID: string(ref.Device)}).Validate() != nil {
		return nil, fail(ErrProtocol, nil)
	}
	credential, err := h.store.CheckCredential(ctx, ref, h.now())
	if err != nil {
		return nil, fail(ErrForbidden, err)
	}
	return h.add(certificate, ref, credential)
}

func verifiedPeer(r *http.Request) (*x509.Certificate, domain.CredentialRef, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, domain.CredentialRef{}, fail(ErrForbidden, nil)
	}
	certificate, err := x509.ParseCertificate(bytes.Clone(r.TLS.PeerCertificates[0].Raw))
	if err != nil {
		return nil, domain.CredentialRef{}, fail(ErrForbidden, err)
	}
	ref, err := identity.CredentialFromCertificate(certificate)
	if err != nil {
		return nil, domain.CredentialRef{}, fail(ErrForbidden, err)
	}
	return certificate, ref, nil
}

func (h *Hub) add(certificate *x509.Certificate, ref domain.CredentialRef, credential domain.Credential) (*session, error) {
	if credential.Ref != ref || credential.PublicKeyHash != domain.Hash(certificate.RawSubjectPublicKeyInfo) || credential.Mode.Validate() != nil {
		return nil, fail(ErrForbidden, nil)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil {
		return nil, fail(ErrOffline, nil)
	}
	if _, exists := h.sessions[ref.Device]; exists {
		return nil, fail(ErrConflict, nil)
	}
	if len(h.sessions) >= MaxDevices {
		return nil, fail(ErrCapacity, nil)
	}
	s := newSession(h.ctx, h.config.Settings, h.now, &h.budget, h.incoming)
	s.routing = h.config.Routing
	s.strictRouting = h.config.Routing != nil
	s.ref = ref
	s.certificate = certificate
	s.mode = credential.Mode
	s.store = h.store
	s.gateway = true
	h.sessions[ref.Device] = s
	h.workers.Add(1)
	return s, nil
}

func (h *Hub) handshake(ctx context.Context, s *session) error {
	body := protocol.HelloBody{GatewayID: string(h.config.GatewayID), DeviceID: string(s.ref.Device)}
	payload, err := protocol.Encode(body, protocol.MaxFrameBytes)
	if err != nil {
		return fail(ErrProtocol, err)
	}
	hello := protocol.Frame{Version: protocol.Version, Type: protocol.Hello, RequestID: "hello", Generation: wireGeneration(s.generation), TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload}
	if checkErr := s.writeHandshake(ctx, hello); checkErr != nil {
		return checkErr
	}
	echo, err := s.readHandshake(ctx)
	if err != nil {
		return err
	}
	var echoed protocol.HelloBody
	if echo.Type != protocol.Hello || echo.RequestID != hello.RequestID || echo.OperationID != "" || protocol.DecodeStrict(echo.Payload, &echoed, protocol.MaxFrameBytes) != nil || echoed != body {
		return fail(ErrProtocol, nil)
	}
	if s.strictRouting {
		if routingErr := h.routingHandshake(ctx, s); routingErr != nil {
			return routingErr
		}
	}
	capabilities, err := s.readHandshake(ctx)
	if err != nil {
		return err
	}
	if capabilities.Type != protocol.Capabilities || capabilities.OperationID != "" {
		return fail(ErrProtocol, nil)
	}
	return s.route(ctx, capabilities, nil, h.now())
}

func (s *session) readHandshake(ctx context.Context) (protocol.Frame, error) {
	kind, data, err := s.conn.Read(ctx)
	if err != nil {
		return protocol.Frame{}, fail(ErrOffline, err)
	}
	if kind != websocket.MessageText {
		return protocol.Frame{}, fail(ErrProtocol, nil)
	}
	if checkErr := s.check(ctx); checkErr != nil {
		return protocol.Frame{}, checkErr
	}
	frame, err := protocol.DecodeFrame(data)
	if err != nil || frame.Generation != wireGeneration(s.generation) {
		return protocol.Frame{}, fail(ErrProtocol, err)
	}
	return frame, nil
}

func (s *session) writeHandshake(ctx context.Context, frame protocol.Frame) error {
	if checkErr := s.check(ctx); checkErr != nil {
		return checkErr
	}
	encoded, err := protocol.EncodeFrame(frame)
	if err != nil {
		return fail(ErrProtocol, err)
	}
	if checkErr := s.conn.Write(ctx, websocket.MessageText, encoded); checkErr != nil {
		return fail(ErrOffline, checkErr)
	}
	return nil
}

func (h *Hub) retire(s *session) {
	h.mu.Lock()
	if h.sessions[s.ref.Device] == s {
		delete(h.sessions, s.ref.Device)
	}
	h.mu.Unlock()
	h.workers.Done()
}

func (h *Hub) current(device domain.DeviceID) (*session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[device]
	if h.closed || s == nil {
		return nil, fail(ErrOffline, nil)
	}
	return s, nil
}

// WaitReady waits for wire hello/capabilities, not provider/execution readiness.
func (h *Hub) WaitReady(ctx context.Context, device domain.DeviceID) error {
	s, err := h.current(device)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return fail(ErrOffline, ctx.Err())
	case <-s.done:
		return fail(ErrOffline, nil)
	case <-s.ready:
		return s.check(ctx)
	}
}

func (h *Hub) Snapshot(device domain.DeviceID) (Snapshot, error) {
	s, err := h.current(device)
	if err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	result := Snapshot{CredentialMode: s.mode, ProcessBoot: s.processBoot, RoutingReady: s.routingReady && s.mode == domain.Regular && !s.closing, Credential: s.ref, Generation: s.generation, LastSeen: s.lastSeen, Online: !s.closing, CapabilitiesObservedAt: s.capabilitiesObservedAt}
	data := bytes.Clone(s.capabilities)
	s.mu.Unlock()
	if len(data) != 0 {
		if checkErr := protocol.DecodeStrict(data, &result.Capabilities, protocol.MaxFrameBytes); checkErr != nil {
			return Snapshot{}, fail(ErrProtocol, checkErr)
		}
	}
	return result, nil
}

func (h *Hub) Reserve(ctx context.Context, device domain.DeviceID, frame protocol.Frame) (*Reservation, error) {
	s, err := h.current(device)
	if err != nil {
		return nil, err
	}
	return s.reserve(ctx, frame)
}

func (h *Hub) Receive(ctx context.Context) (*Received, error) {
	select {
	case <-ctx.Done():
		return nil, fail(ErrOffline, ctx.Err())
	case <-h.ctx.Done():
		return nil, fail(ErrOffline, h.ctx.Err())
	case received := <-h.incoming:
		return received, nil
	}
}

func (h *Hub) Disconnect(device domain.DeviceID) error {
	s, err := h.current(device)
	if err != nil {
		return err
	}
	s.stop(fail(ErrOffline, nil))
	<-s.done
	h.mu.Lock()
	if h.sessions[device] == s {
		delete(h.sessions, device)
	}
	h.mu.Unlock()
	return s.closeFailure()
}

func (h *Hub) Close() error {
	h.mu.Lock()
	h.closed = true
	sessions := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	h.cancel()
	for _, s := range sessions {
		s.stop(fail(ErrOffline, nil))
	}
	h.workers.Wait()
	var failures []error
	for _, s := range sessions {
		failures = append(failures, s.closeFailure())
	}
	return errors.Join(failures...)
}

// DisconnectContext cancels this socket and waits only for its owned workers.
// Expiry reports an unconfirmed join while Hub keeps ownership. ErrNoSession
// means the session was already retired, never that Delegate execution stopped.
func (h *Hub) DisconnectContext(ctx context.Context, device domain.DeviceID) error {
	if ctx.Err() != nil {
		return fail(ErrExpired, ctx.Err())
	}
	h.mu.Lock()
	s := h.sessions[device]
	h.mu.Unlock()
	if s == nil {
		return fail(ErrNoSession, nil)
	}
	return disconnectSession(ctx, s)
}

// DisconnectGeneration joins only the captured authenticated connection. A
// replacement connection stays owned by Hub and is never selected by this call.
// ErrNoSession means the captured connection has already been superseded.
func (h *Hub) DisconnectGeneration(ctx context.Context, ref domain.CredentialRef, generation domain.ConnectionGeneration) error {
	if ref.Validate() != nil || generation.Validate() != nil {
		return fail(ErrProtocol, nil)
	}
	if ctx.Err() != nil {
		return fail(ErrExpired, ctx.Err())
	}
	h.mu.Lock()
	s := h.sessions[ref.Device]
	h.mu.Unlock()
	if s == nil {
		return fail(ErrNoSession, nil)
	}
	s.mu.Lock()
	matches := s.ref == ref && s.generation == generation
	s.mu.Unlock()
	if !matches {
		return fail(ErrNoSession, nil)
	}
	return disconnectSession(ctx, s)
}

func disconnectSession(ctx context.Context, s *session) error {
	s.stop(fail(ErrOffline, nil))
	select {
	case <-ctx.Done():
		return fail(ErrExpired, ctx.Err())
	case <-s.done:
		return s.closeFailure()
	}
}
