package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Real profile persistence is tested by the SDK. This controlled port supplies
// policy transitions while the adapter launches and joins actual CLI processes.
type workspaceTestStore struct {
	mu         sync.Mutex
	state      WorkspaceSnapshot
	pins       map[string]ProjectPin
	beforeLock func(*WorkspaceSnapshot)
	closeError bool
}

func (s *workspaceTestStore) Snapshot(ctx context.Context) (WorkspaceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return WorkspaceSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return copiedWorkspaceState(s.state), nil
}

func copiedWorkspaceState(state WorkspaceSnapshot) WorkspaceSnapshot {
	state.Workspaces = append([]WorkspacePolicy(nil), state.Workspaces...)
	for i := range state.Workspaces {
		state.Workspaces[i].Providers = clonePolicies(state.Workspaces[i].Providers)
	}
	return state
}

func (s *workspaceTestStore) LookupPin(ctx context.Context, id string) (ProjectPin, error) {
	if err := ctx.Err(); err != nil {
		return ProjectPin{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pin, ok := s.pins[id]
	if !ok {
		return ProjectPin{}, ErrConflict
	}
	return pin, nil
}

func (s *workspaceTestStore) LookupResolution(ctx context.Context, request protocol.ResolveProjectRequest) (ProjectPin, bool, error) {
	if err := ctx.Err(); err != nil {
		return ProjectPin{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pin, ok := s.pins[request.RequestID]
	if ok && pin.Request != request {
		return ProjectPin{}, false, ErrConflict
	}
	return pin, ok, nil
}

func (s *workspaceTestStore) Lock(ctx context.Context) (WorkspaceLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.beforeLock != nil {
		s.beforeLock(&s.state)
		s.beforeLock = nil
	}
	return &workspaceTestLease{s: s}, nil
}

type workspaceTestLease struct{ s *workspaceTestStore }

func (l *workspaceTestLease) Snapshot() WorkspaceSnapshot { return copiedWorkspaceState(l.s.state) }
func (l *workspaceTestLease) CurrentWorkspace(id string) (WorkspacePolicy, error) {
	for _, w := range l.s.state.Workspaces {
		if w.ID == id && w.Enabled {
			return w, nil
		}
	}
	return WorkspacePolicy{}, ErrConflict
}

func (l *workspaceTestLease) CommitResolution(pin ProjectPin) (ProjectPin, error) {
	if prior, ok := l.s.pins[pin.Request.RequestID]; ok {
		if prior.Request != pin.Request {
			return ProjectPin{}, ErrConflict
		}
		return prior, nil
	}
	w, err := l.CurrentWorkspace(pin.Request.WorkspaceID)
	if err != nil || w.NativeContext != pin.WorkspaceContext {
		return ProjectPin{}, ErrConflict
	}
	if pin.Validate() != nil {
		return ProjectPin{}, ErrEvidence
	}
	l.s.pins[pin.Request.RequestID] = pin
	return pin, nil
}

func (l *workspaceTestLease) Close() error {
	fail := l.s.closeError
	l.s.mu.Unlock()
	if fail {
		return ErrEvidence
	}
	return nil
}

func newWorkspaceFixture(t *testing.T) (*fixture, *workspaceTestStore, protocol.ResolveProjectRequest) {
	t.Helper()
	f := newFixture(t)
	f.state.Features = []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease, protocol.WorkspaceFeature}
	f.writeState()
	p := f.config.Projects[0]
	s := &workspaceTestStore{state: WorkspaceSnapshot{RootDirectory: p.Root, RootContext: p.RootToken, Workspaces: []WorkspacePolicy{{ID: "workspace-one", Alias: "work", Directory: p.Directory, NativeContext: "opaque-workspace-token", Enabled: true, Revision: 1, Providers: p.Providers}}, ProjectBudget: protocol.ProjectBudget{Limit: protocol.MaxProjectPins, ByteLimit: protocol.MaxProjectPinBytes, BytesUsed: 2}}, pins: make(map[string]ProjectPin)}
	cfg := f.config
	cfg.Projects = nil
	cfg.ProjectStore = s
	adapter, err := NewAdapter(cfg, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	f.adapter = adapter
	return f, s, protocol.ResolveProjectRequest{RequestID: strings.Repeat("1", 32), WorkspaceID: "workspace-one", RelativePath: "."}
}

func resolveWorkspace(t *testing.T, f *fixture, request protocol.ResolveProjectRequest) protocol.ResolveProjectReply {
	t.Helper()
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.ResolveProject, Root: protocol.WireContextGuard(f.config.Projects[0].RootToken), Body: encoded(t, request)})
	if reply.Error != nil {
		t.Fatal("resolution failed", reply.Error.Code)
	}
	var result protocol.ResolveProjectReply
	if protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes) != nil || result.ValidateFor(request) != nil {
		t.Fatal("invalid resolution")
	}
	return result
}

func TestWorkspaceResolutionReplayDoesNotRediscoverOrRequireLiveApproval(t *testing.T) {
	f, s, request := newWorkspaceFixture(t)
	first := resolveWorkspace(t, f, request)
	before := len(f.calls())
	s.mu.Lock()
	s.state.Workspaces[0].Enabled = false
	s.mu.Unlock()
	if err := os.Remove(f.config.Projects[0].Directory); err != nil {
		t.Fatal(err)
	}
	if second := resolveWorkspace(t, f, request); !reflect.DeepEqual(first, second) {
		t.Fatal("replay changed identity")
	}
	if len(f.calls()) != before {
		t.Fatal("replay launched Native again")
	}
	changed := request
	changed.RelativePath = "other"
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.ResolveProject, Root: first.Project.Context.Root, Body: encoded(t, changed)})
	if reply.Error == nil || len(f.calls()) != before {
		t.Fatal("changed request reused identity or launched Native")
	}
}

func TestWorkspaceReportsAreMetadataOnlyAndExcludeRemovedApprovals(t *testing.T) {
	f, s, _ := newWorkspaceFixture(t)
	if err := f.adapter.ProbeWorkspaces(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls())
	report, err := f.adapter.CapabilitiesV2(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if report.Validate() != nil || len(report.Workspaces) != 1 {
		t.Fatal("missing approved workspace")
	}
	s.mu.Lock()
	s.state.Workspaces[0].Enabled = false
	s.mu.Unlock()
	report, err = f.adapter.CapabilitiesV2(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Workspaces) != 0 || len(f.calls()) != before {
		t.Fatal("metadata refresh retained removed workspace or launched CLI")
	}
}

func workspaceAdmission(t *testing.T, f *fixture, handle string) protocol.Command {
	t.Helper()
	task := f.task()
	task.SpecSHA256 = ""
	return protocol.Command{Operation: protocol.Admit, Project: handle, Body: encoded(t, protocol.Admission{Task: task, Provider: "fixture", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}, Permission: "read-only", BudgetSeconds: 120, Brief: f.state.Brief})}
}

func TestWorkspaceCurrentCeilingIsCheckedAtStartWithoutStrandingReads(t *testing.T) {
	f, s, request := newWorkspaceFixture(t)
	resolveWorkspace(t, f, request)
	s.mu.Lock()
	s.beforeLock = func(state *WorkspaceSnapshot) { state.Workspaces[0].Providers[0].MaxBudgetSeconds = 60 }
	s.mu.Unlock()
	reply := f.adapter.Execute(t.Context(), workspaceAdmission(t, f, request.RequestID))
	if reply.Error == nil {
		t.Fatal("late local ceiling narrowing allowed Start")
	}
	assertNoNewExecution(t, f.calls())
	s.mu.Lock()
	s.state.Workspaces[0].Enabled = false
	s.mu.Unlock()
	command := f.command(protocol.Status)
	command.Project = request.RequestID
	if reply = f.adapter.Execute(t.Context(), command); reply.Error != nil {
		t.Fatal("policy removal stranded saved read", reply.Error.Code)
	}
}

func TestWorkspacePolicyLeaseEndsAtStartAndRetainsWaitOwnership(t *testing.T) {
	f, s, request := newWorkspaceFixture(t)
	resolveWorkspace(t, f, request)
	f.state.Block = "dispatch"
	f.writeState()
	done := make(chan protocol.Reply, 1)
	command := workspaceAdmission(t, f, request.RequestID)
	go func() { done <- f.adapter.Execute(t.Context(), command) }()
	t.Cleanup(func() {
		f.release()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("CLI owner did not join")
		}
	})
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+f.task().TaskID))
	changed := make(chan error, 1)
	go func() {
		lease, err := s.Lock(t.Context())
		if err == nil {
			s.state.Workspaces[0].Enabled = false
			err = lease.Close()
		}
		changed <- err
	}()
	select {
	case err := <-changed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("policy lock spanned CLI Wait")
	}
	select {
	case <-done:
		t.Fatal("accepted CLI Wait ownership released early")
	default:
	}
	f.release()
	select {
	case reply := <-done:
		if reply.Error != nil {
			t.Fatal(reply.Error.Code)
		}
		done <- reply
	case <-time.After(2 * time.Second):
		t.Fatal("CLI did not finish")
	}
	if f.adapter.Status().Active != 0 {
		t.Fatal("accepted CLI owner leaked")
	}
}

func TestWorkspaceUnknownHandleNeverResolvesImplicitly(t *testing.T) {
	f, _, _ := newWorkspaceFixture(t)
	command := f.command(protocol.Resolve)
	command.Project = strings.Repeat("9", 32)
	if reply := f.adapter.Execute(t.Context(), command); reply.Error == nil || len(f.calls()) != 0 {
		t.Fatal("unknown handle triggered discovery")
	}
	if !errors.Is(f.adapter.Reload(t.Context(), Config{}), ErrConfiguration) {
		t.Fatal("invalid reload accepted")
	}
}

func TestWorkspaceUnlockFailureAfterStartStillJoinsExactlyOneCLI(t *testing.T) {
	f, s, request := newWorkspaceFixture(t)
	resolveWorkspace(t, f, request)
	f.state.Block = "dispatch"
	f.writeState()
	s.mu.Lock()
	s.closeError = true
	s.mu.Unlock()
	command := workspaceAdmission(t, f, request.RequestID)
	done := make(chan protocol.Reply, 1)
	go func() { done <- f.adapter.Execute(t.Context(), command) }()
	t.Cleanup(func() {
		f.release()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("failed unlock lost CLI Wait ownership")
		}
	})
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+f.task().TaskID))
	select {
	case <-done:
		t.Fatal("unlock failure returned before accepted CLI joined")
	default:
	}
	lease, err := s.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.closeError = false
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	f.release()
	select {
	case reply := <-done:
		if reply.Error == nil {
			t.Fatal("unlock uncertainty was hidden")
		}
		done <- reply
	case <-time.After(2 * time.Second):
		t.Fatal("accepted CLI did not join")
	}
	dispatches := 0
	for _, call := range f.calls() {
		if call.Command == "dispatch" {
			dispatches++
		}
	}
	if dispatches != 1 || f.adapter.Status().Active != 0 {
		t.Fatal("uncertain unlock repeated Start or leaked ownership")
	}
}

func TestWorkspaceLargeOpaqueTokenIsBoundedLocallyAndNormalizedOnWire(t *testing.T) {
	f, store, request := newWorkspaceFixture(t)
	f.state.ProjectToken = strings.Repeat("p", 512<<10)
	f.writeState()
	result := resolveWorkspace(t, f, request)
	store.mu.Lock()
	pin := store.pins[request.RequestID]
	store.mu.Unlock()
	if len(pin.Project.ProjectToken) != 512<<10 || result.Project.Context.Project != protocol.WireContextGuard(f.state.ProjectToken) {
		t.Fatal("opaque local context was truncated or leaked instead of normalized")
	}
	encoded := encoded(t, result)
	if len(encoded) > 2048 || strings.Contains(string(encoded), strings.Repeat("p", 100)) {
		t.Fatal("local context enlarged the public wire reply")
	}
}

func TestWorkspaceInventoryBoundsRawLocalPageWithoutChangingWireRequest(t *testing.T) {
	f, _, _ := newWorkspaceFixture(t)
	request := protocol.OriginInventoryRequest{GatewayID: "gateway-one", Generation: "origin-one", ExpectedRoot: protocol.WireContextGuard(f.config.Projects[0].RootToken), Limit: 100}
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.OriginInventory, Root: request.ExpectedRoot, Body: encoded(t, request)})
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var report protocol.OriginInventoryReport
	if protocol.DecodeStrict(reply.Body, &report, protocol.MaxFrameBytes) != nil || report.ValidateFor(request) != nil {
		t.Fatal("bounded page broke public inventory contract")
	}
	for _, call := range f.calls() {
		if call.Command == "origin" {
			flags, _, _, _ := helperArguments(call.Args)
			if flags["limit"] != "1" || flags["include-workspace-constraint"] != "true" {
				t.Fatal("local page retained unbounded count of raw workspace tokens")
			}
			return
		}
	}
	t.Fatal("no Native inventory call was made")
}
