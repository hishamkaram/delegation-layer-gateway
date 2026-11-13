package deviceruntime

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"net/url"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
	"github.com/hishamkaram/delegation-layer-gateway/internal/connectorconfig"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

// Configuration is the runtime consumer's immutable connection/local-boundary
// snapshot. Legacy file configuration and Native's durable profile implement
// the same contract; neither owns a second execution or reconnect loop.
type Configuration interface {
	Adapter() connector.Config
	DeviceID() domain.DeviceID
	WSSURL() *url.URL
	Roots() (*x509.CertPool, error)
	DeviceRoots() (*x509.CertPool, error)
	NetworkTimeout() time.Duration
}

// Run preserves the legacy static-configuration entry point and nil rejection.
func Run(ctx context.Context, cfg *connectorconfig.Config, store *deviceidentity.Store) error {
	if cfg == nil {
		return ErrConfiguration
	}
	return RunConfigured(ctx, cfg, store)
}

// RunConfigured retains its Adapter/Service ownership across socket generations. Caller
// owns the identity lease and must retain it until Run has joined all CLI owners.
// Context cancellation stops network observation; accepted CLI ownership drains.
func RunConfigured(ctx context.Context, cfg Configuration, store *deviceidentity.Store) (result error) {
	if ctx == nil || cfg == nil || store == nil {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deviceRoots, err := cfg.DeviceRoots()
	if err != nil {
		return failed(ErrConfiguration, err)
	}
	if _, ref, certErr := store.Certificate(deviceRoots, time.Now()); certErr != nil || ref.Device != cfg.DeviceID() {
		return failed(ErrConfiguration, certErr)
	}
	adapter, err := connector.NewAdapter(cfg.Adapter(), time.Now)
	if err != nil {
		return failed(ErrConfiguration, err)
	}
	owner, cancelOwner := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelOwner()
	// Startup inspection is one local finite CLI owner, outside Gateway-routed
	// fleet permits. No native Probe runs on a heartbeat or reconnect timer.
	probe, cancelProbe := context.WithTimeout(owner, cfg.Adapter().ControlTimeout)
	probeErr := probeAdapter(probe, adapter)
	cancelProbe()
	if probeErr != nil {
		return errors.Join(failed(ErrConfiguration, probeErr), drainAdapter(adapter))
	}
	boot := make([]byte, 16)
	if _, err = rand.Read(boot); err != nil {
		return errors.Join(failed(ErrConfiguration, err), drainAdapter(adapter))
	}
	service, err := connector.NewService(owner, adapter, connector.ServiceConfig{ProcessBoot: hex.EncodeToString(boot), Random: rand.Reader})
	if err != nil {
		return errors.Join(failed(ErrConfiguration, err), drainAdapter(adapter))
	}
	defer func() { cancelOwner(); result = errors.Join(result, drainService(owner, service, adapter)) }()
	return runConnections(ctx, cfg, store, deviceRoots, adapter, service)
}

func runConnections(ctx context.Context, cfg Configuration, store *deviceidentity.Store, deviceRoots *x509.CertPool, adapter *connector.Adapter, service *connector.Service) error {
	transportRoots, err := cfg.Roots()
	if err != nil {
		return failed(ErrConfiguration, err)
	}
	delay := time.Second
	var lastFailure error
	for ctx.Err() == nil {
		lastFailure = runConnection(ctx, cfg, store, deviceRoots, transportRoots, adapter, service)
		if errors.Is(lastFailure, ErrConfiguration) {
			return lastFailure
		}

		if ctx.Err() != nil {
			break
		}
		if err := waitReconnect(ctx, delay); err != nil {
			return errors.Join(lastFailure, failed(ErrConnection, err))
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
	return errors.Join(ctx.Err(), lastFailure)
}

func waitReconnect(ctx context.Context, maximum time.Duration) error {
	span := maximum - time.Second
	if span < 0 || maximum > 30*time.Second {
		return ErrConfiguration
	}
	jitter, err := rand.Int(rand.Reader, big.NewInt(int64(span)+1))
	if err != nil {
		return err
	}
	timer := time.NewTimer(time.Second + time.Duration(jitter.Int64()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func drainAdapter(adapter *connector.Adapter) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var failureSeen bool
	for adapter.Status().Active != 0 {
		if err := adapter.RetryCleanup(); err != nil {
			failureSeen = true
		}
		if adapter.Status().Active != 0 {
			<-ticker.C
		}
	}
	if failureSeen {
		return ErrCleanup
	}
	return nil
}

func drainService(owner context.Context, service *connector.Service, adapter *connector.Adapter) error {
	// Service.Close stops intake and joins workers. If cleanup remains, this owner
	// keeps the identity lease alive and retries known files; no process searches.
	var failureSeen bool
	for {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(owner), time.Second)
		err := service.Close(cleanup)
		cancel()
		if err == nil {
			if failureSeen {
				return ErrCleanup
			}
			return nil
		}
		if !onlyPending(err) {
			failureSeen = true // An unexpected error still provides no worker-join proof.
		}
		if retryErr := adapter.RetryCleanup(); retryErr != nil {
			failureSeen = true
		}
		timer := time.NewTimer(100 * time.Millisecond)
		<-timer.C
	}
}

func connectionLifetime(ctx context.Context, cfg Configuration, store *deviceidentity.Store, service *connector.Service, client *transport.Client, roots *x509.CertPool) error {
	observation, cancel := context.WithCancel(ctx)
	defer cancel()
	attached := make(chan error, 1)
	renewed := make(chan error, 1)
	go func() { attached <- service.Attach(observation, client) }()
	go func() { renewed <- scheduledRenewal(observation, cfg, store, client, roots) }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	pending := false
	attachJoined, renewJoined := false, false
	var result error
	waiting := true
	for waiting {
		select {
		case <-ctx.Done():
			result = ctx.Err()
			waiting = false
		case result = <-attached:
			attachJoined = true
			waiting = false
		case result = <-renewed:
			renewJoined = true
			waiting = false
		case <-service.NeedsReconcile():
			pending = true
		case <-ticker.C:
			if pending && service.Status().Adapter.Active == 0 {
				waiting = false
			}
		}
	}
	cancel()
	closeErr := client.Close()
	if ctx.Err() != nil && onlyPending(result) {
		result = ctx.Err()
	}
	return errors.Join(result, closeErr, joinConnectionWorkers(attached, renewed, attachJoined, renewJoined))
}

func joinConnectionWorkers(attached, renewed <-chan error, attachJoined, renewJoined bool) (result error) {
	if !attachJoined {
		joinErr := <-attached
		if joinErr != nil && !onlyPending(joinErr) && !IsExpectedCancellation(joinErr) {
			result = errors.Join(result, joinErr)
		}
	}
	if !renewJoined {
		joinErr := <-renewed
		if joinErr != nil && !IsExpectedCancellation(joinErr) {
			result = errors.Join(result, joinErr)
		}
	}
	return result
}

func scheduledRenewal(ctx context.Context, cfg Configuration, store *deviceidentity.Store, client *transport.Client, roots *x509.CertPool) error {
	certificate, _, err := store.Certificate(roots, time.Now())
	if err != nil {
		return failed(ErrRenewal, err)
	}
	delay, err := nextRenewal(store, certificate.Leaf, time.Now())
	if err != nil {
		return err
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return renew(ctx, cfg, store, client, roots, time.Now)
	}
}

func probeAdapter(ctx context.Context, adapter *connector.Adapter) error {
	if adapter.WorkspaceMode() {
		return adapter.ProbeWorkspaces(ctx)
	}
	if adapter.Probe(ctx).Validate() != nil {
		return ErrConfiguration
	}
	return nil
}

func connectionConfig(ctx context.Context, cfg Configuration, certificate *x509.Certificate, adapter *connector.Adapter, service *connector.Service) (transport.ClientConfig, error) {
	result := transport.ClientConfig{URL: cfg.WSSURL().String(), GatewayID: cfg.Adapter().GatewayID, Certificate: certificate, Routing: service}
	if adapter.WorkspaceMode() {
		report, err := adapter.CapabilitiesV2(ctx)
		if err != nil {
			return transport.ClientConfig{}, err
		}
		result.WireVersion = protocol.WireVersion2
		result.CapabilitiesV2 = &report
	} else {
		result.Capabilities = adapter.Capabilities()
	}
	return result, nil
}

func runConnection(ctx context.Context, cfg Configuration, store *deviceidentity.Store, deviceRoots, transportRoots *x509.CertPool, adapter *connector.Adapter, service *connector.Service) error {
	certificate, ref, err := store.Certificate(deviceRoots, time.Now())
	if err != nil || ref.Device != cfg.DeviceID() {
		return failed(ErrConfiguration, err)
	}
	clientHTTP, owned := directClient(transportRoots, &certificate, cfg.NetworkTimeout())
	defer owned.CloseIdleConnections()
	config, err := connectionConfig(ctx, cfg, certificate.Leaf, adapter, service)
	if err != nil {
		return failed(ErrConfiguration, err)
	}
	client, err := transport.Dial(ctx, config, clientHTTP, time.Now)
	if err != nil {
		return failed(ErrConnection, err)
	}
	err = connectionLifetime(ctx, cfg, store, service, client, deviceRoots)
	return connectionFailure(err, ctx.Err() != nil)
}
