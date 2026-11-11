package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpsserver"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
	"github.com/hishamkaram/delegation-layer-gateway/internal/mcpadapter"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/tlsconfig"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
	"github.com/hishamkaram/delegation-layer-gateway/internal/wirelink"
)

// New owns resources only after their constructors succeed. No listener serves
// and no provider work runs until Serve; a failure joins reverse cleanup.
func New(ctx context.Context, cfg config.Gateway, options Options) (runtime *Runtime, result error) {
	options, bundle, err := checkedConfiguration(ctx, cfg, options)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	r := &Runtime{now: options.Now, lifetime: lifetime, cancel: cancel, serveErrors: make(chan error, 7), controlTimeout: time.Duration(cfg.ControlTimeoutSeconds) * time.Second}
	defer func() {
		if result != nil {
			result = failed(errors.Join(result, r.Close()))
		}
	}()
	if err = r.openStorage(cfg); err != nil {
		return nil, err
	}
	authority := adminapi.NewAuthorizer()
	if err = r.openBackend(cfg, bundle, authority); err != nil {
		return nil, err
	}
	public, err := r.publicHandler(cfg, options.JWKSClient)
	if err != nil {
		return nil, err
	}
	if err = r.bindTLS(cfg, bundle, public); err != nil {
		return nil, err
	}
	if err = r.bindAdmin(cfg, authority); err != nil {
		return nil, err
	}
	return r, nil
}

func randomID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func (r *Runtime) openStorage(cfg config.Gateway) error {
	lease, err := instance.Acquire(filepath.Join(filepath.Dir(cfg.Database), "gateway.lock"))
	if err != nil {
		return failed(err)
	}
	r.lease = lease
	audit, err := observability.Open(cfg.AuditDirectory, r.now)
	if err != nil {
		return failed(err)
	}
	r.audit = audit
	recorder, err := observability.NewRecorder(audit, &r.metrics)
	if err != nil {
		return failed(err)
	}
	r.recorder = recorder
	return nil
}

func (r *Runtime) publicHandler(cfg config.Gateway, jwksClient *http.Client) (http.Handler, error) {
	if jwksClient == nil {
		jwksClient, r.ownJWKS = defaultJWKSClient()
	}
	authenticator, err := identity.NewAuthenticator(identity.Config{Issuer: cfg.Identity.Issuer, Audience: cfg.Identity.Audience, JWKSURL: cfg.Identity.JWKSURL}, jwksClient, r.now, r.store)
	if err != nil {
		return nil, failed(err)
	}
	link, err := wirelink.New(r.hub)
	if err != nil {
		return nil, failed(err)
	}
	service, err := gateway.New(r.store, link, r.gatewayID, rand.Reader, r.now)
	if err != nil {
		return nil, failed(err)
	}
	adapter, err := mcpadapter.New(mcpadapter.Options{Registry: r.store, Operations: service, Presence: link, Authenticator: auditedAuthenticator{authenticator, r.recorder}, Recorder: r.recorder, ResourceURL: cfg.PublicURL + "/mcp", Issuer: cfg.Identity.Issuer, Timeout: time.Duration(cfg.ControlTimeoutSeconds) * time.Second, Now: r.now})
	if err != nil {
		return nil, failed(err)
	}
	handler, err := enrollment.HTTPHandler(auditedEnrollment{r.enrollment, r.recorder}, r.now)
	if err != nil {
		return nil, failed(err)
	}
	guard, err := httpguard.New(httpguard.Options{PublicOrigin: cfg.PublicURL, ConcurrentRequests: 128, Timeout: time.Duration(cfg.HTTPTimeoutSeconds) * time.Second, MaxBodyBytes: 1 << 20})
	if err != nil {
		return nil, failed(err)
	}
	return guard.Wrap(r.publicRoutes(adapter, handler)), nil
}

func (r *Runtime) bindTLS(cfg config.Gateway, bundle tlsconfig.Bundle, public http.Handler) error {
	listener, err := net.Listen("tcp", cfg.PublicAddress)
	if err != nil {
		return failed(err)
	}
	server, err := httpsserver.New(listener, bundle.Public, public, 128, time.Duration(cfg.HTTPTimeoutSeconds)*time.Second)
	if err != nil {
		return failed(errors.Join(err, listener.Close()))
	}
	r.public = server
	r.addresses.Public = listener.Addr().String()
	devices, err := net.Listen("tcp", cfg.DeviceAddress)
	if err != nil {
		return failed(err)
	}
	_, port, err := net.SplitHostPort(devices.Addr().String())
	if err != nil {
		return failed(errors.Join(err, devices.Close()))
	}
	origin, err := config.HTTPSURL(cfg.PublicURL)
	if err != nil {
		return failed(errors.Join(err, devices.Close()))
	}
	device, err := httpsserver.New(devices, bundle.Devices, r.deviceHandler(net.JoinHostPort(origin.Hostname(), port)), 256, time.Duration(cfg.HTTPTimeoutSeconds)*time.Second)
	if err != nil {
		return failed(errors.Join(err, devices.Close()))
	}
	r.device = device
	r.addresses.Device = devices.Addr().String()
	return nil
}

func defaultJWKSClient() (*http.Client, *http.Transport) {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	owned := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: owned, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, owned
}

type deviceDisconnector struct{ hub *transport.Hub }

func (d deviceDisconnector) Disconnect(ctx context.Context, device domain.DeviceID) error {
	err := d.hub.DisconnectContext(ctx, device)
	if errors.Is(err, transport.ErrNoSession) {
		return nil
	}
	return err
}

func (d deviceDisconnector) DisconnectGeneration(ctx context.Context, ref domain.CredentialRef, generation domain.ConnectionGeneration) (adminapi.ConnectionStatus, error) {
	err := d.hub.DisconnectGeneration(ctx, ref, generation)
	if errors.Is(err, transport.ErrNoSession) {
		return adminapi.ConnectionRetired, nil
	}
	if err != nil {
		return "", err
	}
	return adminapi.ConnectionJoined, nil
}

func checkedConfiguration(ctx context.Context, cfg config.Gateway, options Options) (Options, tlsconfig.Bundle, error) {
	if ctx == nil || cfg.Validate() != nil || validateStorage(cfg) != nil {
		return Options{}, tlsconfig.Bundle{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Options{}, tlsconfig.Bundle{}, failed(err)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Now().IsZero() {
		return Options{}, tlsconfig.Bundle{}, ErrUnavailable
	}
	origin, err := config.HTTPSURL(cfg.PublicURL)
	if err != nil || origin.ForceQuery {
		return Options{}, tlsconfig.Bundle{}, ErrUnavailable
	}
	bundle, err := tlsconfig.Load(cfg.TLS, cfg.DeviceCA, origin.Hostname(), options.Now())
	if err != nil {
		return Options{}, tlsconfig.Bundle{}, failed(err)
	}
	return options, bundle, nil
}

func (r *Runtime) openBackend(cfg config.Gateway, bundle tlsconfig.Bundle, authority *adminapi.Authorizer) error {
	store, err := registry.Open(r.lifetime, cfg.Database, registry.Options{Gateway: domain.GatewayID(cfg.GatewayID), Admin: authority})
	if err != nil {
		return failed(err)
	}
	r.store = store
	r.gatewayID, err = store.Identity(r.lifetime)
	if err != nil {
		return failed(err)
	}
	issuer, err := enrollment.New(store, bundle.Authority, rand.Reader, r.now)
	if err != nil {
		return failed(err)
	}
	r.enrollment = issuer
	boot, err := randomID()
	if err != nil {
		return failed(err)
	}
	hub, err := transport.NewHub(r.lifetime, transport.Config{Routing: store, GatewayID: r.gatewayID, BootEpoch: domain.BootEpoch(boot)}, store, r.now)
	if err != nil {
		return failed(err)
	}
	r.hub = hub
	return nil
}

func (r *Runtime) bindAdmin(cfg config.Gateway, authority *adminapi.Authorizer) error {
	link, err := wirelink.New(r.hub)
	if err != nil {
		return failed(err)
	}
	namespace, err := recovery.New(r.store, link, r.gatewayID, r.now)
	if err != nil {
		return failed(err)
	}
	initializer, err := recovery.NewInitializer(r.store, namespace, r.now)
	if err != nil {
		return failed(err)
	}
	restorer, err := recovery.NewRestorer(r.store, namespace, r.now)
	if err != nil {
		return failed(err)
	}
	drainer, err := recovery.NewDrainer(r.store, namespace, r.now)
	if err != nil {
		return failed(err)
	}
	handler, err := adminapi.NewHandler(adminapi.Options{Roots: initializer, Recoveries: restorer, Tasks: drainer, Projects: namespace, Permits: r.store, RoutingDrains: r.store, GenerationDisconnector: deviceDisconnector{r.hub}, Store: r.store, Authority: authority, Disconnector: deviceDisconnector{r.hub}, Random: rand.Reader, Now: r.now, MetadataMetrics: r.MetadataMetrics(), MetadataHealth: r.Health})
	if err != nil {
		return failed(err)
	}
	admin, err := adminapi.Listen(cfg.AdminSocket, handler)
	if err != nil {
		return failed(err)
	}
	r.admin = admin
	parent, err := filepath.EvalSymlinks(filepath.Dir(cfg.AdminSocket))
	if err != nil {
		return failed(err)
	}
	r.addresses.Admin = filepath.Join(parent, filepath.Base(cfg.AdminSocket))
	return nil
}
