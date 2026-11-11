package deviceruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connectorconfig"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

type fixtureAdmin struct{}

func (fixtureAdmin) AuthorizeAdmin(context.Context) error { return nil }

type networkFixture struct {
	cfg      *connectorconfig.Config
	identity *deviceidentity.Store
	registry *registry.Store
	hub      *transport.Hub
	ca       testCA
	renewal  *enrollment.Service
}

func newNetworkFixture(t *testing.T, mode domain.CredentialMode, age time.Duration) *networkFixture {
	t.Helper()
	t.Setenv("GATEWAY_RUNTIME_CLI_FIXTURE", "1")
	f := &networkFixture{ca: newCA(t)}
	store, err := registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.sqlite"), registry.CreateOptions{Admin: fixtureAdmin{}})
	f.registry = checked(t, store, err)
	t.Cleanup(func() { require(t, f.registry.Close()) })
	generatedID, identityErr := store.Identity(t.Context())
	require(t, identityErr)
	device, err := store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "device", Name: "Fixture"})
	_ = checked(t, device, err)
	raw := bytes.Repeat([]byte{1}, 32)
	issuedAt := f.ca.now.Add(-age)
	require(t, store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: domain.Hash(raw), Device: "device", Mode: mode, Generation: 1, CreatedAt: issuedAt, ExpiresAt: issuedAt.Add(domain.EnrollmentTTL)}))
	service, err := enrollment.New(store, f.ca.signer, rand.Reader, func() time.Time { return issuedAt })
	issuer := checked(t, service, err)
	handler, err := enrollment.HTTPHandler(issuer, time.Now)
	enroller := checked(t, handler, err)
	renewal, err := enrollment.New(store, f.ca.signer, rand.Reader, time.Now)
	f.renewal = checked(t, renewal, err)
	hub, err := transport.NewHub(t.Context(), transport.Config{Routing: store, GatewayID: generatedID, BootEpoch: "gateway-boot"}, store, time.Now)
	f.hub = checked(t, hub, err)
	t.Cleanup(func() { require(t, f.hub.Close()) })
	mux := http.NewServeMux()
	mux.Handle("/enroll", enroller)
	mux.Handle("/connect", f.hub)
	transportCA := newCA(t)
	server := newMutualTLSServer(t, transportCA, f.ca, mux)
	f.cfg = fixtureConfigWithDeviceCA(t, transportCA, &f.ca, server.URL, "", string(generatedID))
	f.identity = openStore(t, f.cfg)
	require(t, Enroll(t.Context(), f.cfg, f.identity, base64.RawURLEncoding.EncodeToString(raw)))
	return f
}

func startRun(t *testing.T, f *networkFixture) (context.CancelFunc, <-chan struct{}, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var final error
	go func() { final = Run(ctx, f.cfg, f.identity); close(done) }()
	var once sync.Once
	join := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("runtime failed to join owned work")
			}
		})
		if final != nil && !errors.Is(final, context.Canceled) {
			t.Errorf("runtime shutdown: %v", final)
		}
	}
	t.Cleanup(join)
	return cancel, done, join
}

func waitSnapshot(t *testing.T, f *networkFixture, minimum uint64) transport.Snapshot {
	t.Helper()
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot, err := f.hub.Snapshot("device")
		if err == nil && snapshot.Online && snapshot.Generation.Counter >= minimum && len(snapshot.Capabilities.Projects) == 1 {
			return snapshot
		}
		select {
		case <-deadline.C:
			t.Fatalf("runtime did not establish generation%d: %v", minimum, err)
		case <-ticker.C:
		}
	}
}

func TestRunUsesAuthoritativeACKModeAndReusesOneStartupProbe(t *testing.T) {
	for _, mode := range []domain.CredentialMode{domain.Regular, domain.RecoveryOnly} {
		t.Run(string(mode), func(t *testing.T) {
			f := newNetworkFixture(t, mode, 0)
			_, _, join := startRun(t, f)
			snapshot := waitSnapshot(t, f, 1)
			if snapshot.CredentialMode != mode || snapshot.RoutingReady != (mode == domain.Regular) || snapshot.Capabilities.Projects[0].Ready != (mode == domain.Regular) {
				t.Fatalf("runtime guessed mode or ignored ACK: mode=%s routing=%v capability=%+v", snapshot.CredentialMode, snapshot.RoutingReady, snapshot.Capabilities.Projects[0])
			}
			require(t, f.hub.Disconnect("device"))
			next := waitSnapshot(t, f, 2)
			if next.ProcessBoot != snapshot.ProcessBoot {
				t.Fatal("reconnect replaced service/process routing owner")
			}
			join()
			data, err := os.ReadFile(filepath.Join(f.cfg.Adapter().Projects[0].Root, "native-calls"))
			require(t, err)
			if string(data) != "context\n" {
				t.Fatal("reconnect invoked periodic native probe or another command")
			}
		})
	}
}

func TestRunShutdownWaitsForAcceptedNativeCLI(t *testing.T) {
	f := newNetworkFixture(t, domain.Regular, 0)
	cancel, done, join := startRun(t, f)
	waitSnapshot(t, f, 1)
	root := f.cfg.Adapter().Projects[0].Root
	require(t, os.WriteFile(filepath.Join(root, "block-native"), []byte("block"), 0o600))
	t.Cleanup(func() { require(t, os.WriteFile(filepath.Join(root, "release-native"), []byte("release"), 0o600)) })
	body, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(f.cfg.Adapter().GatewayID)}, protocol.MaxFrameBytes)
	require(t, err)
	payload, err := protocol.Encode(protocol.Command{Operation: protocol.ContextInspect, Project: "project", Body: body}, protocol.MaxFrameBytes)
	require(t, err)
	reserved, err := f.hub.Reserve(t.Context(), "device", protocol.Frame{Version: 1, Type: protocol.Request, TTLMillis: 30000, Payload: payload})
	buffer := checked(t, reserved, err)
	route, err := buffer.Routing()
	request := checked(t, route, err)
	require(t, f.registry.AcquireRouting(t.Context(), request))
	require(t, buffer.ArmRouting(request))
	require(t, buffer.Publish(t.Context(), func(context.Context, transport.Metadata) error { return nil }))
	waitFile(t, filepath.Join(root, "native-started"))
	cancel()
	select {
	case <-done:
		t.Fatal("runtime returned before accepted CLI joined")
	case <-time.After(150 * time.Millisecond):
	}
	// Caller retains its identity lease while runtime drains the accepted native
	// owner. Opening another store must still fail during that interval.
	if other, err := deviceidentity.Open(f.cfg.IdentityDirectory()); !errors.Is(err, deviceidentity.ErrBusy) {
		if err == nil {
			require(t, other.Close())
		}
		t.Fatal("identity lease escaped while CLI owned work")
	}
	require(t, os.WriteFile(filepath.Join(root, "release-native"), []byte("release"), 0o600))
	join()
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("native owner did not reach gate")
		case <-ticker.C:
		}
	}
}

func newMutualTLSServer(t *testing.T, a, deviceCA testCA, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{a.serverCertificate(t)}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: fixtureRoots(deviceCA)}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestAlreadyCancelledRunStartsNoNativeOwner(t *testing.T) {
	f := newNetworkFixture(t, domain.Regular, 0)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Run(ctx, f.cfg, f.identity); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled runtime started")
	}
	if _, err := os.Stat(filepath.Join(f.cfg.Adapter().Projects[0].Root, "native-calls")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled runtime invoked native CLI")
	}
}
