package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type testClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = c.value.Add(d)
}

type fixture struct {
	adapter *Adapter
	config  Config
	state   helperState
	clock   *testClock
	t       *testing.T
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t.Setenv("GATEWAY_CONNECTOR_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	project := Project{Alias: "project-one", Root: t.TempDir(), Directory: t.TempDir(), RootToken: strings.Repeat("a", 64), ProjectToken: "local-project-token-PRIVATE-CANARY", Providers: []ProviderPolicy{{Provider: "fixture", Models: []string{"model-safe"}, Permissions: []domain.Permission{domain.ReadOnly, domain.WorkspaceWrite}, MaxBudgetSeconds: 120, NativeModel: true, NativeEffort: true}}}
	config := Config{Executable: executable, TemporaryDirectory: t.TempDir(), GatewayID: "gateway-one", Projects: []Project{project}, ControlTimeout: time.Second}
	clock := &testClock{value: time.Now()}
	adapter, err := NewAdapter(config, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{adapter: adapter, config: config, clock: clock, t: t, state: helperState{Provider: "fixture", Permission: "read-only", Budget: int64(120 * time.Second), NativeModel: true, Brief: "a private brief PRIVATE-CANARY"}}
	f.writeState()
	t.Cleanup(func() {
		f.release()
		if cleanupErr := adapter.RetryCleanup(); cleanupErr != nil {
			t.Error(cleanupErr)
		}
	})
	return f
}

func (f *fixture) writeState() {
	f.t.Helper()
	data, err := json.Marshal(f.state)
	if err != nil {
		f.t.Fatal(err)
	}
	if writeErr := os.WriteFile(filepath.Join(f.config.Projects[0].Root, "helper-state.json"), data, 0o600); writeErr != nil {
		f.t.Fatal(writeErr)
	}
}

func (f *fixture) release() {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.config.Projects[0].Root, "release"), nil, 0o600); err != nil {
		f.t.Error(err)
	}
}

func (f *fixture) calls() []helperCall {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.config.Projects[0].Root, "calls.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	var calls []helperCall
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var call helperCall
		if decodeErr := json.Unmarshal([]byte(line), &call); decodeErr != nil {
			f.t.Fatal(decodeErr)
		}
		calls = append(calls, call)
	}
	return calls
}

func encoded(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := protocol.Encode(value, protocol.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *fixture) task() protocol.TaskBinding {
	return protocol.TaskBinding{TaskID: strings.Repeat("1", 32), Context: f.config.Projects[0].wireContext(), Origin: protocol.Origin{GatewayID: "gateway-one", AdmissionGeneration: "origin-one", OperationID: "operation-one", PrincipalRef: "principal-one", RequestSHA256: strings.Repeat("b", 64)}, SpecSHA256: strings.Repeat("c", 64)}
}

func (f *fixture) command(op protocol.Operation) protocol.Command {
	return protocol.Command{Operation: op, Project: "project-one", Body: encoded(f.t, protocol.TaskControl{Task: f.task()})}
}

func assertCode(t *testing.T, reply protocol.Reply, code string) {
	t.Helper()
	if reply.Error == nil || reply.Error.Code != code {
		t.Fatalf("reply error=%+v, want %s", reply.Error, code)
	}
}

func observation(t *testing.T, reply protocol.Reply) protocol.TaskObservation {
	t.Helper()
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var result protocol.TaskObservation
	if err := protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes); err != nil || result.Validate() != nil {
		t.Fatal("invalid observation")
	}
	return result
}

func TestCLIObservationsAreHashedAndEndedIsNotClosure(t *testing.T) {
	f := newFixture(t)
	result := observation(t, f.adapter.Execute(t.Context(), f.command(protocol.Status)))
	if result.ExecutionClosure != nil || result.ExecutionClosurePending != "closure_unproven" || result.Liveness != "ended" {
		t.Fatal("liveness fabricated closure")
	}
	if result.Task.Context != f.task().Context || strings.Contains(string(encoded(t, result)), "PRIVATE-CANARY") {
		t.Fatal("local context leaked instead of hashed binding")
	}
	for _, call := range f.calls() {
		if filepath.Dir(call.Directory) != f.config.TemporaryDirectory || call.Directory == f.config.Projects[0].Root {
			t.Fatal("CLI cwd is not its connector-owned control directory")
		}
		if call.Command == "status" && slicesContains(call.Args, "--cwd") {
			t.Fatal("unsupported status --cwd")
		}
	}
	if f.adapter.Status().Active != 0 {
		t.Fatal("joined CLI retained a permit")
	}
}

func TestAdmissionUsesOwnedFilesAndPassiveVerification(t *testing.T) {
	f := newFixture(t)
	task := f.task()
	task.SpecSHA256 = ""
	admission := protocol.Admission{Task: task, Provider: "fixture", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}, Permission: "read-only", BudgetSeconds: 120, Brief: f.state.Brief}
	command := protocol.Command{Operation: protocol.Admit, Project: "project-one", Body: encoded(t, admission)}
	result := observation(t, f.adapter.Execute(t.Context(), command))
	if result.Task.TaskID != task.TaskID {
		t.Fatal("task ID changed")
	}
	var dispatch, resolve bool
	for _, call := range f.calls() {
		switch call.Command {
		case "dispatch":
			dispatch = true
			if call.BriefMode != 0o600 || call.OriginMode != 0o600 {
				t.Fatal("sensitive files not0600")
			}
			if strings.Contains(strings.Join(call.Args, " "), f.state.Brief) {
				t.Fatal("brief leaked in argv")
			}
		case "resolve":
			resolve = true
		}
	}
	if !dispatch || !resolve {
		t.Fatal("missing dispatch/canonical passive verification")
	}
	entries, err := os.ReadDir(f.config.TemporaryDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatal("owned temporary files leaked")
	}
}

func TestCurrentCeilingBlocksResumeAndReloadRejectsOldGeneration(t *testing.T) {
	f := newFixture(t)
	f.state.Budget = int64(121 * time.Second)
	f.writeState()
	assertCode(t, f.adapter.Execute(t.Context(), f.command(protocol.ResumeExisting)), "forbidden")
	for _, call := range f.calls() {
		if slicesContains(call.Args, "--resume-admission") {
			t.Fatal("resume started outside local ceiling")
		}
	}
	generation := f.adapter.Generation()
	if err := f.adapter.Reload(t.Context(), f.config); err != nil {
		t.Fatal(err)
	}
	assertCode(t, f.adapter.execute(t.Context(), f.command(protocol.Status), acceptance{generation: generation}), "context_mismatch")
}

func TestCapabilityProbeRefusesClosedOrIncompatibleOrigin(t *testing.T) {
	for _, name := range []string{"closed", "missing feature"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.state.Closed = name == "closed"
			f.state.Disabled = name == "missing feature"
			f.writeState()
			report := f.adapter.Probe(t.Context())
			if len(report.Projects) != 1 || report.Projects[0].Ready || f.adapter.Status().Ready {
				t.Fatal("unready origin advertised ready")
			}
			if report.Validate() != nil {
				t.Fatal("invalid capability report")
			}
		})
	}
}

func TestCLIOutputIsBoundedAndUnknownSchemaFailsClosed(t *testing.T) {
	for _, mode := range []string{"stdout", "stderr", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.state.Mode = mode
			f.writeState()
			reply := f.adapter.Execute(t.Context(), f.command(protocol.Status))
			if reply.Error == nil || strings.Contains(string(encoded(t, reply)), "PRIVATE-CANARY") {
				t.Fatal("untrusted output escaped")
			}
			if f.adapter.Status().Active != 0 {
				t.Fatal("output owner not joined")
			}
		})
	}
}

func TestRangeProjectionNormalizesDescriptorAndChecksCursor(t *testing.T) {
	f := newFixture(t)
	rangeRequest := protocol.RangeRequest{Task: f.task(), Descriptor: protocol.Descriptor{SHA256: helperHash("accepted result"), Length: int64(len("accepted result"))}, Limit: 65536}
	command := protocol.Command{Operation: protocol.ResultChunk, Project: "project-one", Body: encoded(t, rangeRequest)}
	reply := f.adapter.Execute(t.Context(), command)
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var result protocol.ResultRange
	if err := protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes); err != nil || result.ValidateFor(rangeRequest) != nil {
		t.Fatal("range did not satisfy wire contract")
	}
	f.state.Mode = "range"
	f.writeState()
	assertCode(t, f.adapter.Execute(t.Context(), command), "evidence_invalid")
}

func waitPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal("owner gate cancelled")
		case <-deadline.C:
			t.Fatal("helper did not reach owner gate")
		case <-tick.C:
		}
	}
}

func TestTransportObservationCancellationDoesNotReleaseCLIOwner(t *testing.T) {
	f := newFixture(t)
	f.state.Block = "status"
	f.writeState()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan protocol.Reply, 1)
	done := make(chan struct{})
	go func() { defer close(done); result <- f.adapter.Execute(ctx, f.command(protocol.Status)) }()
	t.Cleanup(func() {
		f.release()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("owned CLI did not join")
		}
	})
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+f.task().TaskID))
	cancel()
	f.clock.advance(2 * time.Second)
	if status := f.adapter.Status(); status.Active != 1 || status.CleanupPending != 1 || status.Ready {
		t.Fatal("observation expiry released an unsettled CLI owner")
	}
	select {
	case <-result:
		t.Fatal("control returned before Wait joined")
	default:
	}
	f.release()
	reply := <-result
	assertCode(t, reply, "pending")
	if f.adapter.Status().Active != 0 {
		t.Fatal("settled owner did not release")
	}
}

func TestResumeReloadBetweenPassiveReceiptAndStartRefusesMutation(t *testing.T) {
	f := newFixture(t)
	f.state.Block = "resolve"
	f.writeState()
	result := make(chan protocol.Reply, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- f.adapter.Execute(t.Context(), f.command(protocol.ResumeExisting))
	}()
	t.Cleanup(func() {
		f.release()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("resume owner did not join")
		}
	})
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+f.task().TaskID))
	config := f.config
	config.Projects = append([]Project(nil), config.Projects...)
	config.Projects[0].Providers = clonePolicies(config.Projects[0].Providers)
	config.Projects[0].Providers[0].MaxBudgetSeconds = 1
	if err := f.adapter.Reload(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	f.release()
	reply := <-result
	assertCode(t, reply, "context_mismatch")
	for _, call := range f.calls() {
		if slicesContains(call.Args, "--resume-admission") {
			t.Fatal("stale ceiling generation reached resume Start")
		}
	}
}

func TestContextAndGatewaySubstitutionNeverReachTaskCLI(t *testing.T) {
	f := newFixture(t)
	task := f.task()
	task.Context.Root = protocol.WireContextGuard("other local root")
	command := protocol.Command{Operation: protocol.Status, Project: "project-one", Body: encoded(t, protocol.TaskControl{Task: task})}
	assertCode(t, f.adapter.Execute(t.Context(), command), "context_mismatch")
	if _, err := os.Stat(filepath.Join(f.config.Projects[0].Root, "calls.jsonl")); !os.IsNotExist(err) {
		t.Fatal("substituted context reached CLI")
	}
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
