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
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

// This fault closes the actual TCP connection before returning a diagnostic.
// It models a terminal TLS close error without pretending that Close succeeded.
type closedTCPDiagnostic struct {
	net.Conn
	failure error
	closed  atomic.Bool
}

func (c *closedTCPDiagnostic) Close() error {
	err := c.Conn.Close()
	if err == nil || errors.Is(err, net.ErrClosed) {
		c.closed.Store(true)
	}
	return errors.Join(err, c.failure)
}

func TestFreshInventoryAfterJoinedPriorSocketCloseDiagnostic(t *testing.T) {
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
	t.Cleanup(func() {
		cancelOwner()
		require(t, drainService(owner, service, adapter))
	})
	roots, err := f.cfg.Roots()
	require(t, err)
	deviceRoots, err := f.cfg.DeviceRoots()
	require(t, err)
	certificate, _, err := f.identity.Certificate(deviceRoots, time.Now())
	require(t, err)
	clientHTTP, owned := directClient(roots, &certificate, f.cfg.NetworkTimeout())
	t.Cleanup(owned.CloseIdleConnections)
	injected := errors.New("injected diagnostic after actual TCP close")
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
		if closeErr := client.Close(); closeErr != nil && !errors.Is(closeErr, injected) {
			t.Error(closeErr)
		}
	})
	watchdog, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require(t, f.hub.WaitReady(watchdog, f.cfg.DeviceID()))
	intake, stopIntake := context.WithCancel(t.Context())
	stopIntake()
	// Attach registers its socket before its cancelled report and joins intake
	// on return. No CLI control is accepted or provider execution requested.
	if err = service.Attach(intake, client); !errors.Is(err, connector.ErrPending) {
		t.Fatalf("cancelled intake did not settle: %v", err)
	}
	if closeErr := client.Close(); !errors.Is(closeErr, injected) {
		t.Fatalf("actual transport close lost the injected diagnostic: %v", closeErr)
	}
	closed := socket.Load()
	if closed == nil || !closed.closed.Load() {
		t.Fatal("fault did not close its actual TCP connection")
	}
	generation := client.Generation()
	generation.Counter++
	if _, err = service.Inventory(watchdog, generation); !errors.Is(err, connector.ErrPending) {
		t.Fatalf("initial prior-socket diagnostic was hidden: %v", err)
	}
	if service.Status().LastError != "prior_socket_cleanup" {
		t.Fatal("terminal close diagnostic was not retained")
	}
	generation.Counter++
	inventory, err := service.Inventory(watchdog, generation)
	if err != nil {
		t.Fatalf("joined prior socket permanently blocked fresh census: %v", err)
	}
	if !inventory.Complete || inventory.Generation != (protocol.Generation{BootEpoch: string(generation.BootEpoch), Counter: generation.Counter}) {
		t.Fatal("fresh census did not preserve its authenticated generation")
	}
	if closeErr := client.Close(); !errors.Is(closeErr, injected) {
		t.Fatal("retiring the service slot erased the transport close diagnostic")
	}
}
