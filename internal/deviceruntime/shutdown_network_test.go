package deviceruntime

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func TestCancelledConnectionRetainsActualJoinedSocketDiagnostic(t *testing.T) {
	owner, cancelOwner := context.WithCancel(context.WithoutCancel(t.Context()))
	t.Cleanup(cancelOwner)
	f := newNetworkFixture(t, domain.RecoveryOnly, 0)
	adapter, err := connector.NewAdapter(f.cfg.Adapter(), time.Now)
	require(t, err)
	probe, cancelProbe := context.WithTimeout(t.Context(), f.cfg.Adapter().ControlTimeout)
	report := adapter.Probe(probe)
	cancelProbe()
	require(t, report.Validate())
	service, err := connector.NewService(owner, adapter, connector.ServiceConfig{ProcessBoot: strings.Repeat("a", 32), Random: rand.Reader})
	require(t, err)
	t.Cleanup(func() { cancelOwner(); require(t, drainService(owner, service, adapter)) })
	roots, err := f.cfg.Roots()
	require(t, err)
	deviceRoots, err := f.cfg.DeviceRoots()
	require(t, err)
	certificate, _, err := f.identity.Certificate(deviceRoots, time.Now())
	require(t, err)
	clientHTTP, owned := directClient(roots, &certificate, f.cfg.NetworkTimeout())
	t.Cleanup(owned.CloseIdleConnections)
	injected := errors.New("independent TCP close diagnostic during cancellation")
	var socket atomic.Pointer[closedTCPDiagnostic]
	dial := owned.DialContext
	owned.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, dialErr := dial(ctx, network, address)
		if dialErr != nil {
			return nil, dialErr
		}
		closed := &closedTCPDiagnostic{Conn: connection, failure: injected}
		socket.Store(closed)
		return closed, nil
	}
	client, err := transport.Dial(t.Context(), transport.ClientConfig{URL: f.cfg.WSSURL().String(), GatewayID: f.cfg.Adapter().GatewayID, Certificate: certificate.Leaf, Capabilities: adapter.Capabilities(), Routing: service}, clientHTTP, time.Now)
	require(t, err)
	t.Cleanup(func() {
		if closeErr := client.Close(); !errors.Is(closeErr, injected) {
			t.Error("socket did not retain its actual diagnostic", closeErr)
		}
	})
	ready, cancelReady := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelReady()
	require(t, f.hub.WaitReady(ready, f.cfg.DeviceID()))
	stopped, cancel := context.WithCancel(t.Context())
	cancel()
	result := connectionLifetime(stopped, f.cfg, f.identity, service, client, deviceRoots)
	forwarded := connectionFailure(result, true)
	if !errors.Is(forwarded, injected) || !errors.Is(forwarded, context.Canceled) || IsExpectedCancellation(forwarded) {
		t.Fatal("expected cancellation concealed its independent joined socket diagnostic")
	}
	if closed := socket.Load(); closed == nil || !closed.closed.Load() {
		t.Fatal("fault fixture did not close the actual TCP socket")
	}
}
