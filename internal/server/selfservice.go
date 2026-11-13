package server

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
	"github.com/hishamkaram/delegation-layer-gateway/internal/tlsconfig"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func (r *Runtime) selfServiceHandler(cfg config.Gateway, bundle tlsconfig.Bundle, auth auditedAuthenticator) (http.Handler, error) {
	if cfg.DeviceLogin == nil {
		return nil, nil
	}
	issuer, err := enrollment.NewSelf(r.store, bundle.Authority, rand.Reader, r.now)
	if err != nil {
		return nil, err
	}
	descriptor := contract.Descriptor{
		SchemaVersion: 1, GatewayID: string(r.gatewayID), PublicURL: cfg.PublicURL,
		Issuer: cfg.Identity.Issuer, NativeClientID: cfg.DeviceLogin.NativeClientID,
		Audience: cfg.Identity.Audience, EnrollmentURL: cfg.PublicURL + "/v1/enroll",
		SelfEnrollmentURL: cfg.PublicURL + contract.EnrollmentPath,
		RevokeURL:         cfg.PublicURL + contract.RevocationPath,
		DeviceWSSURL:      cfg.DeviceLogin.DeviceWSSURL, DeviceCAPEM: bundle.DeviceCAPEM,
		SupportedWireVersions: []int{1, 2}, Capabilities: []string{"self-enrollment", "owner-revocation", "workspace-projects"},
	}
	revoker := ownerRevoker{store: r.store, sessions: r.hub, timeout: min(r.controlTimeout, 5*time.Second), recorder: r.recorder}
	return selfservice.New(selfservice.Options{Descriptor: descriptor, Authenticator: auth, Enroller: auditedSelfEnrollment{issuer, r.recorder}, Revoker: revoker, Now: r.now})
}

type auditedSelfEnrollment struct {
	next     *enrollment.SelfService
	recorder *observability.Recorder
}

func (a auditedSelfEnrollment) SelfEnroll(ctx context.Context, actor domain.Actor, request domain.RequestID, name string, csr []byte, replace domain.DeviceID, generation uint64) (domain.CertificateReceipt, error) {
	receipt, err := a.next.SelfEnroll(ctx, actor, request, name, csr, replace, generation)
	if err == nil {
		a.recorder.Record(observability.Event{Code: observability.EnrollmentIssued, Principal: actor.Principal, Device: receipt.Intent.Credential.Device})
	}
	return receipt, err
}

// Registry owns revocation. Socket cleanup follows its commit and has a
// separate finite lifetime; a failed join cannot restore authorization or turn
// the committed revocation into an uncommitted response.
type ownerRevoker struct {
	store interface {
		RevokeOwnedDevice(context.Context, domain.Actor, domain.DeviceID) error
	}
	sessions interface {
		DisconnectContext(context.Context, domain.DeviceID) error
	}
	timeout  time.Duration
	recorder *observability.Recorder
}

func (r ownerRevoker) RevokeOwned(ctx context.Context, actor domain.Actor, device domain.DeviceID) error {
	if err := r.store.RevokeOwnedDevice(ctx, actor, device); err != nil {
		return err
	}
	r.recorder.Record(observability.Event{Code: observability.CredentialRevoked, Principal: actor.Principal, Device: device})
	// This request retains ownership and joins the bounded cleanup even if its
	// caller disappears after commit. Runtime also owns and closes the Hub.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
	defer cancel()
	if err := r.sessions.DisconnectContext(cleanup, device); err != nil && !errors.Is(err, transport.ErrNoSession) {
		r.recorder.Record(observability.Event{Code: observability.RevocationCleanupUnavailable, Principal: actor.Principal, Device: device})
	}
	return nil
}
