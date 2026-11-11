package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestOnlyCanonicalExecutionClosureIsForwarded(t *testing.T) {
	f := newFixture(t)
	f.state.Closure = true
	f.writeState()
	result := observation(t, f.adapter.Execute(t.Context(), f.command(protocol.Resolve)))
	if result.ExecutionClosure == nil || result.ExecutionClosure.Kind != "registered-native" || result.ExecutionClosure.ReferenceSHA256 != strings.Repeat("d", 64) || result.ExecutionClosurePending != "" {
		t.Fatal("canonical closure was lost or replaced")
	}
}

func TestOriginControlsValidateAndProjectPublicProofs(t *testing.T) {
	f := newFixture(t)
	root := f.task().Context.Root
	barrier := protocol.OriginBarrierRequest{GatewayID: "gateway-one", RecoveryID: "recovery-new", Generation: "generation-new", ExpectedRoot: root}
	cases := []struct {
		op   protocol.Operation
		body any
	}{
		{protocol.OriginBarrier, barrier},
		{protocol.OriginInventory, protocol.OriginInventoryRequest{GatewayID: "gateway-one", Generation: "generation-new", Limit: 100, ExpectedRoot: root}},
		{protocol.OriginReopen, protocol.OriginReopenRequest{GatewayID: "gateway-one", RecoveryID: "recovery-new", Generation: "generation-new", CompletenessReceipt: strings.Repeat("f", 64), ExpectedRoot: root}},
	}
	for _, c := range cases {
		reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: c.op, Project: "project-one", Body: encoded(t, c.body)})
		if reply.Error != nil || strings.Contains(string(reply.Body), "PRIVATE-CANARY") || strings.Contains(string(reply.Body), f.config.Projects[0].Root) {
			t.Fatalf("origin control %s did not project safe public proof", c.op)
		}
	}
	barrier.RecoveryID = "/private/path"
	before := len(f.calls())
	assertCode(t, f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.OriginBarrier, Project: "project-one", Body: encoded(t, barrier)}), "context_mismatch")
	if len(f.calls()) != before {
		t.Fatal("invalid recovery identity reached CLI")
	}
}

func TestReloadOwnsImmutableConfiguration(t *testing.T) {
	f := newFixture(t)
	if err := f.adapter.Reload(t.Context(), f.config); err != nil {
		t.Fatal(err)
	}
	f.config.Projects[0].Providers[0].Models[0] = "changed"
	snapshot := f.adapter.snapshot()
	if snapshot.Projects[0].Providers[0].Models[0] != "model-safe" {
		t.Fatal("caller mutated installed configuration")
	}
}

func TestCleanupFaultRetainsOwnerUntilExplicitRetry(t *testing.T) {
	f := newFixture(t)
	f.state.Block = "status"
	f.writeState()
	result := make(chan protocol.Reply, 1)
	done := make(chan struct{})
	go func() { defer close(done); result <- f.adapter.Execute(t.Context(), f.command(protocol.Status)) }()
	var foreign string
	ownCleanupFault(t, f, done, &foreign)
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+f.task().TaskID))
	dirs, readErr := os.ReadDir(f.config.TemporaryDirectory)
	if readErr != nil || len(dirs) != 1 {
		t.Fatal("missing owned control directory")
	}
	foreign = filepath.Join(f.config.TemporaryDirectory, dirs[0].Name(), "test-owned-foreign")
	if err := os.WriteFile(foreign, []byte("must not delete strangers"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.release()
	assertCode(t, <-result, "pending")
	status := f.adapter.Status()
	if status.Active != 1 || status.CleanupPending != 1 || status.Ready {
		t.Fatal("cleanup failure released retained ownership")
	}
	if err := f.adapter.RetryCleanup(); !errors.Is(err, ErrPending) {
		t.Fatal("retry removed unknown file or claimed cleanup complete")
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	foreign = ""
	if err := f.adapter.RetryCleanup(); err != nil {
		t.Fatal(err)
	}
	if f.adapter.Status().Active != 0 {
		t.Fatal("successful retry retained settled owner")
	}
}

func ownCleanupFault(t *testing.T, f *fixture, done <-chan struct{}, foreign *string) {
	t.Helper()
	t.Cleanup(func() {
		f.release()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("cleanup-fault process did not join")
		}
		if *foreign != "" {
			if err := os.Remove(*foreign); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := f.adapter.RetryCleanup(); err != nil {
			t.Error(err)
		}
	})
}

func TestRoutedInspectionRefreshesOnlyCurrentConfigurationCache(t *testing.T) {
	f := newFixture(t)
	command := protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: encoded(t, protocol.InspectRequest{GatewayID: "gateway-one"})}
	first := f.adapter.Capabilities().ObservedAt
	f.clock.advance(time.Second)
	reply := f.adapter.Execute(t.Context(), command)
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	report := f.adapter.Capabilities()
	if !report.ObservedAt.After(first) || len(report.Projects) != 1 || !report.Projects[0].Ready || !f.adapter.Status().Ready {
		t.Fatal("routed native observation did not refresh dated cache")
	}
	old := f.adapter.Generation()
	if reloadErr := f.adapter.Reload(t.Context(), f.config); reloadErr != nil {
		t.Fatal(reloadErr)
	}
	f.adapter.observeProject(old, report.Projects[0])
	if f.adapter.Status().Ready {
		t.Fatal("old configuration observation repopulated current cache")
	}
}
