package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Server owns bounded socket sessions. Registry owns credential validity and durable
// connection counters; snapshots below are only dated transport observations.
type Server struct {
	ctx      context.Context
	cancel   context.CancelFunc
	config   Config
	store    CredentialChecker
	now      func() time.Time
	budget   budget
	incoming chan *Received
	mu       sync.Mutex
	closed   bool
	sessions map[domain.DeviceID]*session
	workers  sync.WaitGroup
}

type Snapshot struct {
	WireVersion    int
	CredentialMode domain.CredentialMode
	ProcessBoot    string
	RoutingReady   bool
	Credential     domain.CredentialRef
	Generation     domain.ConnectionGeneration
	LastSeen       time.Time
	Online         bool
	// Joined means all socket workers joined, never Native task closure.
	Joined                 bool
	Capabilities           protocol.CapabilityReport
	CapabilitiesV2         *protocol.CapabilityReportV2
	CapabilitiesObservedAt time.Time
}

// Subprotocols returns the immutable server policy as a caller-owned slice.
func (h *Server) Subprotocols() []string {
	if h.config.EnableWireV2 {
		return []string{protocol.SubprotocolV2, protocol.Subprotocol}
	}
	return []string{protocol.Subprotocol}
}

func NewServer(ctx context.Context, config Config, store CredentialChecker, now func() time.Time) (*Server, error) {
	if ctx == nil || store == nil || now == nil || (protocol.HelloBody{GatewayID: string(config.GatewayID), DeviceID: "check"}).Validate() != nil || wireGeneration(domain.ConnectionGeneration{BootEpoch: config.BootEpoch, Counter: 1}).Validate() != nil {
		return nil, fail(ErrProtocol, nil)
	}
	checked, err := settings(config.Settings)
	if err != nil {
		return nil, err
	}
	config.Settings = checked
	owned, cancel := context.WithCancel(ctx)
	return &Server{ctx: owned, cancel: cancel, config: config, store: store, now: now, incoming: make(chan *Received, QueueFrames), sessions: make(map[domain.DeviceID]*session)}, nil
}

func (h *Server) add(certificate *x509.Certificate, ref domain.CredentialRef, credential domain.Credential) (*session, error) {
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

func (h *Server) handshake(ctx context.Context, s *session) error {
	body := protocol.HelloBody{GatewayID: string(h.config.GatewayID), DeviceID: string(s.ref.Device)}
	payload, err := protocol.Encode(body, protocol.MaxFrameBytes)
	if err != nil {
		return fail(ErrProtocol, err)
	}
	hello := protocol.Frame{Version: s.wireVersion, Type: protocol.Hello, RequestID: "hello", Generation: wireGeneration(s.generation), TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload}
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

func (h *Server) retire(s *session) {
	h.mu.Lock()
	if h.sessions[s.ref.Device] == s {
		delete(h.sessions, s.ref.Device)
	}
	h.mu.Unlock()
	h.workers.Done()
}

func (h *Server) current(device domain.DeviceID) (*session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[device]
	if h.closed || s == nil {
		return nil, fail(ErrOffline, nil)
	}
	return s, nil
}

func (h *Server) WaitReady(ctx context.Context, device domain.DeviceID) error {
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

func (h *Server) Snapshot(device domain.DeviceID) (Snapshot, error) {
	s, err := h.current(device)
	if err != nil {
		return Snapshot{}, err
	}
	return s.snapshot()
}

func (s *session) snapshot() (Snapshot, error) {
	s.mu.Lock()
	// Registration precedes the handshake; ready is the handshake owner's
	// authority for whether this session can accept wire reservations.
	online := false
	select {
	case <-s.ready:
		online = !s.closing
	default:
	}
	joined := false
	select {
	case <-s.done:
		joined = true
	default:
	}
	result := Snapshot{WireVersion: s.wireVersion, CredentialMode: s.mode, ProcessBoot: s.processBoot, RoutingReady: s.routingReady && s.mode == domain.Regular && online, Credential: s.ref, Generation: s.generation, LastSeen: s.lastSeen, Online: online, Joined: joined, CapabilitiesObservedAt: s.capabilitiesObservedAt}
	data := bytes.Clone(s.capabilities)
	s.mu.Unlock()
	if len(data) != 0 {
		if result.WireVersion == protocol.WireVersion2 {
			result.CapabilitiesV2 = new(protocol.CapabilityReportV2)
			if checkErr := protocol.DecodeStrict(data, result.CapabilitiesV2, protocol.MaxFrameBytes); checkErr != nil {
				return Snapshot{}, fail(ErrProtocol, checkErr)
			}
		} else if checkErr := protocol.DecodeStrict(data, &result.Capabilities, protocol.MaxFrameBytes); checkErr != nil {
			return Snapshot{}, fail(ErrProtocol, checkErr)
		}
	}
	return result, nil
}

func (h *Server) Reserve(ctx context.Context, device domain.DeviceID, frame protocol.Frame) (*Reservation, error) {
	s, err := h.current(device)
	if err != nil {
		return nil, err
	}
	return s.reserve(ctx, frame)
}

func (h *Server) Receive(ctx context.Context) (*Received, error) {
	select {
	case <-ctx.Done():
		return nil, fail(ErrOffline, ctx.Err())
	case <-h.ctx.Done():
		return nil, fail(ErrOffline, h.ctx.Err())
	case received := <-h.incoming:
		return received, nil
	}
}

func (h *Server) Disconnect(device domain.DeviceID) error {
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

func (h *Server) Close() error {
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

func (h *Server) DisconnectContext(ctx context.Context, device domain.DeviceID) error {
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

func (h *Server) DisconnectGeneration(ctx context.Context, ref domain.CredentialRef, generation domain.ConnectionGeneration) error {
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

// Settings returns the validated immutable wire limits used by the server.
func (h *Server) Settings() Settings { return h.config.Settings }
