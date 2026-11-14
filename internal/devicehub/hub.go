// Package devicehub authenticates inbound HTTP device connections and composes
// their registry authority with bounded transport-owned socket resources.
package devicehub

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

type Config = transport.Config

type ownedCredentialChecker interface {
	CheckOwnedCredential(context.Context, domain.CredentialRef, time.Time) (domain.Credential, error)
}

// Hub owns inbound HTTP handlers and their authority/observation callbacks.
// Server alone owns bounded wire sessions. Neither owner manages Native tasks.
type Hub struct {
	*transport.Server
	ctx     context.Context
	cancel  context.CancelFunc
	config  Config
	store   transport.CredentialStore
	owned   ownedCredentialChecker
	now     func() time.Time
	mu      sync.Mutex
	closed  bool
	workers sync.WaitGroup
}

func NewHub(ctx context.Context, config Config, store transport.CredentialStore, now func() time.Time) (*Hub, error) {
	var gate ownedCredentialChecker
	if config.EnableWireV2 {
		var ok bool
		gate, ok = store.(ownedCredentialChecker)
		if !ok {
			return nil, domain.ErrInvalid
		}
	}
	server, err := transport.NewServer(ctx, config, store, now)
	if err != nil {
		return nil, err
	}
	config.Settings = server.Settings()
	owned, cancel := context.WithCancel(ctx)
	return &Hub{Server: server, ctx: owned, cancel: cancel, config: config, store: store, owned: gate, now: now}, nil
}

func (h *Hub) begin() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil {
		return false
	}
	h.workers.Add(1)
	return true
}

func (h *Hub) Close() error {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.cancel()
	err := h.Server.Close()
	h.workers.Wait()
	return err
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if !h.begin() {
		http.Error(w, "device connection rejected", http.StatusForbidden)
		return
	}
	defer h.workers.Done()
	preflight, cancel := context.WithTimeout(r.Context(), h.config.Settings.HandshakeTimeout)
	defer cancel()
	certificate, ref, err := verifiedPeer(r)
	if err != nil {
		h.observeConnection(started, transport.ConnectionFailed, nil)
		http.Error(w, "device connection rejected", http.StatusForbidden)
		return
	}
	peer, err := h.register(preflight, certificate, ref)
	if err != nil {
		h.observeConnection(started, transport.ConnectionFailed, nil)
		http.Error(w, "device connection rejected", http.StatusForbidden)
		return
	}
	defer func() {
		if closeErr := peer.Close(); closeErr != nil {
			h.observeConnection(started, transport.ConnectionFailed, peer)
		}
	}()
	generation, err := h.store.NextConnectionGeneration(preflight, ref, h.config.BootEpoch, h.now())
	if err != nil {
		h.observeConnection(started, transport.ConnectionFailed, peer)
		http.Error(w, "device connection rejected", http.StatusForbidden)
		return
	}
	if err = peer.SetGeneration(generation); err != nil {
		h.observeConnection(started, transport.ConnectionFailed, peer)
		http.Error(w, "device connection rejected", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r.WithContext(preflight), &websocket.AcceptOptions{Subprotocols: h.Subprotocols(), CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		h.observeConnection(started, transport.ConnectionFailed, peer)
		return
	}
	if err = h.authorizeAccepted(preflight, conn, ref); err != nil {
		h.observeConnection(started, transport.ConnectionFailed, peer)
		return
	}
	// The adapter observes establishment only after the transport handshake owns it.
	established, runErr := peer.Run(preflight, r.Context(), conn, func() { h.observeConnection(started, transport.ConnectionEstablished, peer) })
	snapshot, snapshotErr := peer.Snapshot()
	if runErr != nil || !established || snapshotErr != nil || !snapshot.Joined {
		h.observeConnection(started, transport.ConnectionFailed, peer)
	} else {
		h.observeConnection(started, transport.ConnectionClosed, peer)
	}
}

// The pinned WebSocket library selects the actual protocol. Keep an accepted
// socket under HTTP ownership until v2 ownership is verified, before Run can
// consume HELLO or publish capabilities. A failed gate closes before peer cleanup.
func (h *Hub) authorizeAccepted(ctx context.Context, conn *websocket.Conn, ref domain.CredentialRef) (err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, conn.Close(websocket.StatusPolicyViolation, "device connection rejected"))
		}
	}()
	version, err := protocol.SubprotocolVersion(conn.Subprotocol())
	if err != nil {
		return err
	}
	if version == protocol.WireVersion2 {
		if h.owned == nil {
			return domain.Reject(domain.Forbidden)
		}
		_, err = h.owned.CheckOwnedCredential(ctx, ref, h.now())
	}
	return err
}

func (h *Hub) register(ctx context.Context, certificate *x509.Certificate, ref domain.CredentialRef) (*transport.InboundSession, error) {
	if (protocol.HelloBody{GatewayID: string(h.config.GatewayID), DeviceID: string(ref.Device)}).Validate() != nil {
		return nil, transport.NewError(transport.ErrProtocol, nil)
	}
	credential, err := h.store.CheckCredential(ctx, ref, h.now())
	if err != nil {
		switch denied := err.(type) { //nolint:errorlint // Only sole policy errors identify a registry policy denial.
		case *domain.Error:
			if denied != nil && denied.Code == domain.Forbidden && h.config.CredentialDenied != nil {
				h.config.CredentialDenied(ref)
			}
		}
		return nil, transport.NewError(transport.ErrForbidden, err)
	}
	return h.RegisterPeer(certificate, ref, credential)
}

func verifiedPeer(r *http.Request) (*x509.Certificate, domain.CredentialRef, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, domain.CredentialRef{}, transport.NewError(transport.ErrForbidden, nil)
	}
	certificate, err := x509.ParseCertificate(bytes.Clone(r.TLS.PeerCertificates[0].Raw))
	if err != nil {
		return nil, domain.CredentialRef{}, transport.NewError(transport.ErrForbidden, err)
	}
	ref, err := devicecert.CredentialFromCertificate(certificate)
	if err != nil {
		return nil, domain.CredentialRef{}, transport.NewError(transport.ErrForbidden, err)
	}
	return certificate, ref, nil
}
