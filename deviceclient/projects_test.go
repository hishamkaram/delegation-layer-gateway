package deviceclient

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func projectFixture(t *testing.T) (*gatewayFixture, *profileProjects, connector.ProjectPin) {
	t.Helper()
	f := newGatewayFixture(t)
	store, err := openProfile(f.options.ProfileDirectory, true, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pinnedProfile(f.options, f.descriptor, issuerEndpoints{}, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.save(p); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	request := protocol.ResolveProjectRequest{RequestID: fmt.Sprintf("%032x", 1), WorkspaceID: p.Workspaces[0].ID, RelativePath: "project"}
	pin := connector.ProjectPin{Request: request, WorkspaceContext: p.Workspaces[0].NativeContext, Project: connector.Project{Alias: request.RequestID, Root: p.DelegateRoot, Directory: filepath.Join(p.Workspaces[0].Directory, "project"), RootToken: p.DelegateRootContext, ProjectToken: "opaque-project-context"}}
	return f, newProfileProjects(f.options.ProfileDirectory), pin
}

func commitProject(t *testing.T, store connector.ProjectStore, pin connector.ProjectPin) connector.ProjectPin {
	t.Helper()
	lease, err := store.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result, commitErr := lease.CommitResolution(pin)
	closeErr := lease.Close()
	if err = errors.Join(commitErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestProjectPinReplayIsImmutableBeforePolicyAndLiveness(t *testing.T) {
	f, store, pin := projectFixture(t)
	first := commitProject(t, store, pin)
	local, err := ListWorkspaces(t.Context(), f.options.ProfileDirectory)
	if err != nil {
		t.Fatal(err)
	}
	current, err := UpdateWorkspace(t.Context(), f.options.ProfileDirectory, local[0].ID, local[0].Revision, WorkspaceUpdate{Providers: []ProviderPolicy{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RemoveWorkspace(t.Context(), f.options.ProfileDirectory, current.ID, current.Revision); err != nil {
		t.Fatal(err)
	}
	// The directory need not exist anymore. Passive history never scans it.
	pin.Project.ProjectToken = "new inspection of a different object"
	replay := commitProject(t, store, pin)
	if !reflect.DeepEqual(first, replay) || len(replay.Project.Providers) != 0 {
		t.Fatal("retry rebound immutable identity or captured policy")
	}
	found, ok, err := store.LookupResolution(t.Context(), pin.Request)
	if err != nil || !ok || !reflect.DeepEqual(found, first) {
		t.Fatal("resolution replay lost historical identity", err)
	}
	changed := pin.Request
	changed.RelativePath = "other"
	if _, _, err = store.LookupResolution(t.Context(), changed); !errors.Is(err, connector.ErrConflict) {
		t.Fatal("request ID accepted another selector", err)
	}
	snapshot, err := store.Snapshot(t.Context())
	if err != nil || snapshot.ProjectBudget.Used != 1 || snapshot.ProjectBudget.Validate() != nil {
		t.Fatal("pin budget observation invalid", err)
	}
}

func TestProjectPinGuardsRejectSourceRetargetAndDoNotStorePolicy(t *testing.T) {
	f, store, pin := projectFixture(t)
	lease, err := store.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	wrong := pin
	wrong.WorkspaceContext = "different workspace"
	if _, err = lease.CommitResolution(wrong); !errors.Is(err, connector.ErrEvidence) {
		t.Fatal("workspace source rebound", err)
	}
	wrong = pin
	wrong.Project.Providers = []connector.ProviderPolicy{{Provider: "claude"}}
	if _, err = lease.CommitResolution(wrong); !errors.Is(err, connector.ErrEvidence) {
		t.Fatal("immutable pin captured mutable policy", err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	commitProject(t, store, pin)
	p, err := openProfile(f.options.ProfileDirectory, false, false)
	if err != nil {
		t.Fatal(err)
	}
	tampered := *p.value
	tampered.Workspaces[0].NativeContext = "tampered workspace context"
	data, err := protocol.Encode(tampered, maxProfileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(f.options.ProfileDirectory, profileName), data)
	if _, err = store.LookupPin(t.Context(), pin.Request.RequestID); !errors.Is(err, connector.ErrEvidence) {
		t.Fatal("tampered guard join silently rebound pin", err)
	}
}

func TestUnconfirmedRenameReplaysFromFreshProcess(t *testing.T) {
	f, store, pin := projectFixture(t)
	lease, err := store.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	owned, ok := lease.(*profileWorkspaceLease)
	if !ok {
		t.Fatal("unexpected owner")
	}
	// Real filesystem fault: file data sync/rename can succeed, but the retained
	// directory fd cannot sync. No production fault hook or fake store is used.
	if err = owned.store.directory.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = lease.CommitResolution(pin); !errors.Is(err, connector.ErrEvidence) {
		t.Fatal("unconfirmed directory commit reported success", err)
	}
	// Passive replay must not take the held policy lease: a fresh process can
	// confirm the renamed receipt even while this faulted writer still owns it.
	runProjectHelper(t, f.options.ProfileDirectory, "lookup", pin.Request)
	if err = lease.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("fault cleanup did not retain close evidence", err)
	}
	if err = lease.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("repeated cleanup erased close evidence", err)
	}
	replay, found, err := store.LookupResolution(t.Context(), pin.Request)
	if err != nil || !found || replay.WireIdentity() != pin.WireIdentity() {
		t.Fatal("fresh owner did not confirm exact renamed pin", err)
	}
}

func TestConcurrentProjectQuotaHasOneLastSlotAndReplayStillWorks(t *testing.T) {
	f, store, pin := projectFixture(t)
	seedProjectRecords(t, f.options.ProfileDirectory, pin, protocol.MaxProjectPins-1)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for i := range 2 {
		candidate := pin
		candidate.Request.RequestID = fmt.Sprintf("%032x", protocol.MaxProjectPins+i)
		candidate.Project.Alias = candidate.Request.RequestID
		group.Go(func() {
			lease, err := store.Lock(t.Context())
			if err != nil {
				results <- err
				return
			}
			_, commitErr := lease.CommitResolution(candidate)
			results <- errors.Join(commitErr, lease.Close())
		})
	}
	group.Wait()
	close(results)
	success, limited := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, connector.ErrCapacity) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || limited != 1 {
		t.Fatal("concurrent owners overran durable pin quota", success, limited)
	}
	snapshot, err := store.Snapshot(t.Context())
	if err != nil || snapshot.ProjectBudget.Used != protocol.MaxProjectPins {
		t.Fatal("quota snapshot incorrect", err)
	}
	pin.Request.RequestID = fmt.Sprintf("%032x", 1)
	pin.Project.Alias = pin.Request.RequestID
	commitProject(t, store, pin)
}

func seedProjectRecords(t *testing.T, directory string, pin connector.ProjectPin, count int) {
	t.Helper()
	store, err := openProfile(directory, false, true)
	if err != nil {
		t.Fatal(err)
	}
	next := *store.value
	next.Pins = make([]projectRecord, 0, count)
	for i := range count {
		candidate := pin
		candidate.Request.RequestID = fmt.Sprintf("%032x", i+1)
		candidate.Project.Alias = candidate.Request.RequestID
		next.Pins = append(next.Pins, projectRecord{Request: candidate.Request, Identity: candidate.WireIdentity(), Directory: candidate.Project.Directory, ProjectContext: candidate.Project.ProjectToken})
	}
	if err = store.savePartition(next, true); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProjectPolicyLockIsCrossProcessAndContextBounded(t *testing.T) {
	f, store, pin := projectFixture(t)
	lease, err := store.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	runProjectHelper(t, f.options.ProfileDirectory, "busy", pin.Request)
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	runProjectHelper(t, f.options.ProfileDirectory, "open", pin.Request)
}

func runProjectHelper(t *testing.T, directory, mode string, request protocol.ResolveProjectRequest) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestProjectStoreProcessHelper$")
	command.Env = append(os.Environ(), "GATEWAY_PROJECT_TEST_DIRECTORY="+directory, "GATEWAY_PROJECT_TEST_MODE="+mode, "GATEWAY_PROJECT_TEST_REQUEST="+request.RequestID, "GATEWAY_PROJECT_TEST_WORKSPACE="+request.WorkspaceID)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("owned helper failed: %v: %s", runErr, output)
	}
}

func TestProjectStoreProcessHelper(t *testing.T) {
	directory := os.Getenv("GATEWAY_PROJECT_TEST_DIRECTORY")
	if directory == "" {
		return
	}
	store := newProfileProjects(directory)
	mode := os.Getenv("GATEWAY_PROJECT_TEST_MODE")
	if mode == "lookup" {
		request := protocol.ResolveProjectRequest{RequestID: os.Getenv("GATEWAY_PROJECT_TEST_REQUEST"), WorkspaceID: os.Getenv("GATEWAY_PROJECT_TEST_WORKSPACE"), RelativePath: "project"}
		if _, found, err := store.LookupResolution(t.Context(), request); err != nil || !found {
			t.Fatal("fresh process failed durable lookup", err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()
	lease, err := store.Lock(ctx)
	if mode == "busy" {
		if !errors.Is(err, context.DeadlineExceeded) {
			if lease != nil {
				if closeErr := lease.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			t.Fatal("cross-process file lock ignored deadline", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPinByteBudgetDoesNotConsumeRevocationReserve(t *testing.T) {
	f, store, pin := projectFixture(t)
	pin.Project.ProjectToken = strings.Repeat("p", maxNativeContextBytes)
	seedProjectRecords(t, f.options.ProfileDirectory, pin, 3)
	local, err := ListWorkspaces(t.Context(), f.options.ProfileDirectory)
	if err != nil {
		t.Fatal(err)
	}
	// Pin bytes bind before count. Refusal must leave room for local revocation.
	candidate := pin
	candidate.Request.RequestID = fmt.Sprintf("%032x", 4)
	candidate.Project.Alias = candidate.Request.RequestID
	lease, err := store.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, commitErr := lease.CommitResolution(candidate)
	closeErr := lease.Close()
	if !errors.Is(commitErr, connector.ErrCapacity) || closeErr != nil {
		t.Fatal("pin byte budget did not bind", commitErr, closeErr)
	}
	removed, err := RemoveWorkspace(t.Context(), f.options.ProfileDirectory, local[0].ID, local[0].Revision)
	if err != nil || removed.Enabled {
		t.Fatal("pin budget prevented revocation", err)
	}
}

func TestReservedBaseSpaceAllowsTerminalRevisionRemoval(t *testing.T) {
	f, _, _ := projectFixture(t)
	directory := f.options.ProfileDirectory
	store, err := openProfile(directory, false, true)
	if err != nil {
		t.Fatal(err)
	}
	next := *store.value
	seed := next.Workspaces[0]
	next.Workspaces = make([]workspaceRecord, 4)
	for i := range next.Workspaces {
		w := seed
		w.ID = fmt.Sprintf("%032x", i+1)
		w.Alias = fmt.Sprintf("workspace-%d", i)
		w.NativeContext = strings.Repeat("w", maxNativeContextBytes)
		next.Workspaces[i] = w
	}
	next.Workspaces[0].Revision = ^uint64(0)
	next.Workspaces[3].NativeContext = "t"
	encoded, err := profileEncoding(next, maxProfileBytes)
	if err != nil {
		t.Fatal(err)
	}
	padding := ordinaryBaseLimit(next) - len(encoded)
	if padding < 0 || padding+1 > maxNativeContextBytes {
		t.Fatal("invalid independent boundary fixture")
	}
	next.Workspaces[3].NativeContext += strings.Repeat("x", padding)
	if err = store.save(next); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveWorkspace(t.Context(), directory, next.Workspaces[0].ID, ^uint64(0))
	if err != nil || removed.Enabled || removed.Revision != ^uint64(0) {
		t.Fatal("full ordinary budget or revision overflow blocked terminal removal", err)
	}
	persisted, err := openProfile(directory, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := persisted.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	base := *persisted.value
	base.Pins = nil
	data, err := profileEncoding(base, maxBaseProfileBytes)
	if err != nil || len(data) <= ordinaryBaseLimit(base) {
		t.Fatal("test did not consume reserved revocation bytes", err)
	}
}

func TestRetainedPinLookupRequiresDirectoryDurability(t *testing.T) {
	f, projects, pin := projectFixture(t)
	commitProject(t, projects, pin)
	store, err := openProfile(f.options.ProfileDirectory, false, false)
	if err != nil {
		t.Fatal(err)
	}
	record := store.value.Pins[0]
	if err = store.directory.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = store.confirmProject(record); !errors.Is(err, connector.ErrEvidence) {
		t.Fatal("retained pin returned without directory durability", err)
	}
	if len(store.value.Pins) != 1 || store.value.Pins[0].Identity != pin.WireIdentity() {
		t.Fatal("failed confirmation discarded immutable mapping")
	}
	if err = store.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("fault cleanup lost evidence", err)
	}
	retained, err := projects.LookupPin(t.Context(), pin.Request.RequestID)
	if err != nil || retained.WireIdentity() != pin.WireIdentity() {
		t.Fatal("fresh reader failed exact retained identity confirmation", err)
	}
}
