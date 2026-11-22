package deviceclient

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
)

func TestSelectedRootTokenIsRequiredAndImmutable(t *testing.T) {
	f := newGatewayFixture(t)
	options := f.options
	options.DelegateRootContext = ""
	if _, err := Connect(t.Context(), options); !errors.Is(err, ErrConfiguration) {
		t.Fatal("root token omitted before network", err)
	}
	if _, err := Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	options = f.options
	options.DelegateRootContext = "different selected root"
	if _, err := Connect(t.Context(), options); !errors.Is(err, ErrConflict) {
		t.Fatal("selected root identity silently rebound", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) != 1 || f.issues != 1 {
		t.Fatal("root token conflict performed enrollment")
	}
}

func TestLocalContextIsCopiedAndRedacted(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	local, err := LocalContext(t.Context(), f.options.ProfileDirectory)
	if err != nil || local.DelegateRootContext != f.options.DelegateRootContext || local.DelegateRoot != f.options.DelegateRoot || local.DelegateExecutable != f.options.DelegateExecutable {
		t.Fatal("selected local source not retained", err)
	}
	workspaces, err := ListWorkspaces(t.Context(), f.options.ProfileDirectory)
	if err != nil || len(local.WorkspaceIDs) != 1 || len(workspaces) != 1 || local.WorkspaceIDs[0] != workspaces[0].ID {
		t.Fatal("local context omitted profile-owned workspace identity", err)
	}
	encoded, err := json.Marshal(local)
	if err != nil || strings.Contains(string(encoded), f.options.DelegateRootContext) || strings.Contains(local.String(), f.options.DelegateRootContext) {
		t.Fatal("local root token escaped UI formatting", err)
	}
	local.DelegateRoot = "changed-copy"
	local.WorkspaceIDs[0] = "changed-copy"
	again, err := LocalContext(t.Context(), f.options.ProfileDirectory)
	if err != nil || again.DelegateRoot != f.options.DelegateRoot || again.WorkspaceIDs[0] != workspaces[0].ID {
		t.Fatal("local context reader mutated saved source", err)
	}
}

func TestRuntimeInactiveOwnsOnlyIdentityLeaseAndRejectsPending(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	directory := f.options.ProfileDirectory
	inactive, err := RuntimeInactive(t.Context(), directory)
	if err != nil || !inactive {
		t.Fatal("unowned enrolled identity not observed", err)
	}
	identity, err := deviceidentity.Open(filepath.Join(directory, "identity"))
	if err != nil {
		t.Fatal(err)
	}
	active, observeErr := RuntimeInactive(t.Context(), directory)
	closeErr := identity.Close()
	if errors.Join(observeErr, closeErr) != nil || active {
		t.Fatal("busy identity claimed inactive", observeErr, closeErr)
	}
	inactive, err = RuntimeInactive(t.Context(), directory)
	if err != nil || !inactive {
		t.Fatal("identity lease was not released", err)
	}
}

func TestRuntimeInactiveMissingAndPendingAreExplicitErrors(t *testing.T) {
	if _, err := RuntimeInactive(t.Context(), filepath.Join(t.TempDir(), "missing")); !errors.Is(err, ErrProfile) {
		t.Fatal("missing profile claimed inactive", err)
	}
	f := newGatewayFixture(t)
	f.failNext = true
	if _, err := Connect(t.Context(), f.options); !errors.Is(err, ErrTransport) {
		t.Fatal(err)
	}
	if inactive, err := RuntimeInactive(t.Context(), f.options.ProfileDirectory); !errors.Is(err, ErrEnrollment) || inactive {
		t.Fatal("pending enrollment claimed inactive", err)
	}
}
