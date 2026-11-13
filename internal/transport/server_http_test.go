package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// Hub is the HTTP fixture for white-box transport tests. Production HTTP policy
// lives in devicehub; this fixture connects its tests to the real Server engine.
type Hub struct {
	*Server
	test  *testing.T
	store CredentialStore
}

func newTestHub(t *testing.T, ctx context.Context, cfg Config, store CredentialStore, now func() time.Time) (*Hub, error) {
	server, err := NewServer(ctx, cfg, store, now)
	if err != nil {
		return nil, err
	}
	return &Hub{Server: server, test: t, store: store}, nil
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	preflight, cancel := context.WithTimeout(r.Context(), h.config.Settings.HandshakeTimeout)
	defer cancel()
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	certificate, err := x509.ParseCertificate(bytes.Clone(r.TLS.PeerCertificates[0].Raw))
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ref, err := devicecert.CredentialFromCertificate(certificate)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	credential, err := h.store.CheckCredential(preflight, ref, h.now())
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	peer, err := h.RegisterPeer(certificate, ref, credential)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer func() {
		if closeErr := peer.Close(); closeErr != nil {
			h.test.Error(closeErr)
		}
	}()
	generation, err := h.store.NextConnectionGeneration(preflight, ref, h.config.BootEpoch, h.now())
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err = peer.SetGeneration(generation); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r.WithContext(preflight), &websocket.AcceptOptions{Subprotocols: h.Subprotocols(), CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	if _, err = peer.Run(preflight, r.Context(), conn, nil); err != nil {
		return
	}
}

var _ interface {
	DisconnectGeneration(context.Context, domain.CredentialRef, domain.ConnectionGeneration) error
} = (*Hub)(nil)
