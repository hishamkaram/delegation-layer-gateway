package registry

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestRoutingCrashRetainsUnacknowledgedPermit(t *testing.T) {
	if path := os.Getenv("GATEWAY_ROUTING_CRASH_DB"); path != "" {
		store, err := Open(t.Context(), path, options(readFixtureIdentity(t, path)))
		current := must(t, store, err)
		f := &fixture{store: current, credential: domain.CredentialRef{Device: "device", Epoch: fixtureEpoch(t, current), Generation: 1}, connection: domain.ConnectionGeneration{BootEpoch: "boot1", Counter: 1}, now: time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)}
		requireOK(t, current.AcquireRouting(t.Context(), routingRequest(t, f, protocol.Status, 999)))
		os.Exit(93) // Abrupt owner death deliberately skips SQLite and connection Close.
	}
	f := newFixture(t)
	requireOK(t, f.store.Close())
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRoutingCrashRetainsUnacknowledgedPermit$")
	child.Env = append(os.Environ(), "GATEWAY_ROUTING_CRASH_DB="+f.path)
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 93 {
		t.Fatalf("crash fixture did not commit then exit93: %v %s", err, output)
	}
	store, err := Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, store, err)
	if routingOutstanding(t, f) != 1 {
		t.Fatal("WAL recovery freed unacknowledged routing permit")
	}
	requireCode(t, f.store.AcquireRouting(t.Context(), routingRequest(t, f, protocol.Resolve, 1000)), domain.ResourceLimit)
}
