package transport

import (
	"context"
	"crypto/x509"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// InboundSession owns one registered socket resource. The HTTP adapter must call
// Close after RegisterPeer succeeds, even if protocol upgrade or allocation fails.
// Run and Close belong to that single caller; Server.Close may concurrently stop
// the underlying session and joins it through this ownership.
type InboundSession struct {
	server  *Server
	session *session
	ran     bool
	closed  bool
}

// RegisterPeer reserves bounded socket resources after the caller authenticates
// its peer and checks current authority. It never allocates a credential or task.
func (h *Server) RegisterPeer(certificate *x509.Certificate, ref domain.CredentialRef, credential domain.Credential) (*InboundSession, error) {
	if certificate == nil {
		return nil, fail(ErrForbidden, nil)
	}
	s, err := h.add(certificate, ref, credential)
	if err != nil {
		return nil, err
	}
	return &InboundSession{server: h, session: s}, nil
}

// Run owns handshake and established socket workers. A handshake deadline does
// not become the established session lifetime. Close remains required on return.
func (p *InboundSession) Run(handshake, lifetime context.Context, conn *websocket.Conn, onReady func()) (bool, error) {
	if p.closed || p.ran || conn == nil {
		return false, fail(ErrProtocol, nil)
	}
	s := p.session
	version, versionErr := protocol.SubprotocolVersion(conn.Subprotocol())
	s.mu.Lock()
	s.conn = conn
	if versionErr == nil {
		s.wireVersion = version
	}
	closing := s.closing
	s.mu.Unlock()
	if closing {
		if err := conn.CloseNow(); err != nil {
			s.recordCloseError(err)
		}
		return false, fail(ErrOffline, nil)
	}
	conn.SetReadLimit(protocol.MaxFrameBytes)
	if versionErr != nil || (version == protocol.WireVersion2 && !p.server.config.EnableWireV2) {
		return false, fail(ErrProtocol, versionErr)
	}
	if err := p.server.handshake(handshake, s); err != nil {
		s.stop(err)
		return false, err
	}
	close(s.ready)
	p.ran = true
	if onReady != nil {
		onReady()
	}
	s.run(lifetime)
	return true, s.closeFailure()
}

// Snapshot is a dated observation of this captured connection, never a lookup
// that could silently switch to a replacement generation.
func (p *InboundSession) Snapshot() (Snapshot, error) { return p.session.snapshot() }

func (p *InboundSession) Close() error {
	if p.closed {
		return p.session.closeFailure()
	}
	p.closed = true
	s := p.session
	s.stop(fail(ErrOffline, nil))
	if !p.ran {
		s.finish()
	}
	p.server.retire(s)
	return s.closeFailure()
}

// SetGeneration binds the registry-allocated connection before HTTP upgrade.
// Repeating the same binding is safe; a different generation never rebinds it.
func (p *InboundSession) SetGeneration(generation domain.ConnectionGeneration) error {
	if generation.Validate() != nil || p.closed || p.ran {
		return fail(ErrProtocol, nil)
	}
	s := p.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation.Validate() == nil && s.generation != generation {
		return fail(ErrConflict, nil)
	}
	s.generation = generation
	return nil
}
