package deviceclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func connectedWorkspaceProfile(t *testing.T) *gatewayFixture {
	t.Helper()
	f := newGatewayFixture(t)
	if _, err := Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWorkspaceCRUDRetainsIdentityAndIndependentPolicyRevisions(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	directory := f.options.ProfileDirectory
	initial, err := ListWorkspaces(t.Context(), directory)
	if err != nil || len(initial) != 1 || initial[0].Revision != 1 || !initial[0].Enabled || initial[0].ID == "" {
		t.Fatal("missing durable initial approval", err)
	}
	approval := WorkspaceApproval{Alias: "second", Directory: t.TempDir(), NativeContext: "opaque-second-context"}
	second, err := AllowWorkspace(t.Context(), directory, approval)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := AllowWorkspace(t.Context(), directory, approval)
	if err != nil || retry.ID != second.ID || retry.Revision != 1 {
		t.Fatal("approval retry changed identity", err)
	}
	policy := clonePolicies(second.Providers)
	policy[0].MaxBudgetSeconds = 30
	updated, err := UpdateWorkspace(t.Context(), directory, second.ID, 1, WorkspaceUpdate{Providers: policy})
	if err != nil || updated.ID != second.ID || updated.Revision != 2 {
		t.Fatal("target policy revision failed", err)
	}
	if _, err = UpdateWorkspace(t.Context(), directory, second.ID, 1, WorkspaceUpdate{Alias: "stale"}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale CAS updated policy", err)
	}
	assertWorkspaceIdentityAndRemoval(t, directory, initial[0], updated, approval)
}

func assertWorkspaceIdentityAndRemoval(t *testing.T, directory string, initial, updated Workspace, approval WorkspaceApproval) {
	t.Helper()
	listed, err := ListWorkspaces(t.Context(), directory)
	if err != nil || listed[0].Revision != 1 || listed[0].ID != initial.ID {
		t.Fatal("one workspace update changed another", err)
	}
	renamed, err := UpdateWorkspace(t.Context(), directory, updated.ID, updated.Revision, WorkspaceUpdate{Alias: "renamed"})
	if err != nil || renamed.ID != updated.ID {
		t.Fatal("rename replaced stable identity", err)
	}
	removed, err := RemoveWorkspace(t.Context(), directory, renamed.ID, renamed.Revision)
	if err != nil || removed.Enabled || removed.ID != renamed.ID || removed.Revision != renamed.Revision+1 {
		t.Fatal("removal lost immutable history", err)
	}
	approval.Alias = "renamed"
	replacement, err := AllowWorkspace(t.Context(), directory, approval)
	if err != nil || replacement.ID == removed.ID {
		t.Fatal("removed workspace was silently rebound", err)
	}
	if _, err = UpdateWorkspace(t.Context(), directory, removed.ID, removed.Revision, WorkspaceUpdate{Alias: "revived"}); !errors.Is(err, ErrConflict) {
		t.Fatal("disabled identity revived in place", err)
	}
}

func TestWorkspaceValuesAreCopiedAndContextCannotRetarget(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	directory := f.options.ProfileDirectory
	listed, err := ListWorkspaces(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	encoded, encodeErr := json.Marshal(listed)
	if encodeErr != nil || strings.Contains(string(encoded), f.options.Workspaces[0].NativeContext) {
		t.Fatal("local workspace UI exposed raw Native token", encodeErr)
	}
	listed[0].Providers[0].Permissions[0] = "danger-full-access"
	fresh, err := ListWorkspaces(t.Context(), directory)
	if err != nil || fresh[0].Providers[0].Permissions[0] != "read-only" {
		t.Fatal("UI mutated durable policy", err)
	}
	approval := f.options.Workspaces[0]
	approval.NativeContext = "different opaque context"
	if _, err = AllowWorkspace(t.Context(), directory, approval); !errors.Is(err, ErrConflict) {
		t.Fatal("alias silently retargeted", err)
	}
	approval = f.options.Workspaces[0]
	approval.Providers = []ProviderPolicy{}
	if _, err = AllowWorkspace(t.Context(), directory, approval); !errors.Is(err, ErrConflict) {
		t.Fatal("allow silently changed current provider policy", err)
	}
}

func TestWorkspaceMutationUsesProfileFileLease(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	directory := f.options.ProfileDirectory
	store, err := openProfile(directory, false, true)
	if err != nil {
		t.Fatal(err)
	}
	_, updateErr := AllowWorkspace(t.Context(), directory, WorkspaceApproval{Alias: "blocked", Directory: t.TempDir(), NativeContext: "opaque"})
	closeErr := store.Close()
	if !errors.Is(updateErr, ErrBusy) || closeErr != nil {
		t.Fatal("profile mutation did not preserve exclusive owner", updateErr, closeErr)
	}
}

func TestWorkspaceHistoryAndWholeBundleByteLimitPreservePriorCommit(t *testing.T) {
	t.Run("history lifetime bound", func(t *testing.T) {
		f := connectedWorkspaceProfile(t)
		store, err := openProfile(f.options.ProfileDirectory, false, true)
		if err != nil {
			t.Fatal(err)
		}
		next := *store.value
		seed := next.Workspaces[0]
		next.Workspaces = make([]workspaceRecord, protocol.MaxWorkspaces)
		for i := range next.Workspaces {
			record := seed
			record.ID = fmtWorkspaceID(i)
			record.Enabled = false
			next.Workspaces[i] = record
		}
		if err = store.save(next); err != nil {
			t.Fatal(err)
		}
		if err = store.Close(); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(filepath.Join(f.options.ProfileDirectory, profileName))
		if err != nil {
			t.Fatal(err)
		}
		_, allowErr := AllowWorkspace(t.Context(), f.options.ProfileDirectory, WorkspaceApproval{Alias: "over-limit", Directory: t.TempDir(), NativeContext: "opaque"})
		after, readErr := os.ReadFile(filepath.Join(f.options.ProfileDirectory, profileName))
		if !errors.Is(allowErr, ErrCapacity) || readErr != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("lifetime bound evicted history or changed prior commit", allowErr, readErr)
		}
	})
	t.Run("aggregate bytes", func(t *testing.T) {
		f := connectedWorkspaceProfile(t)
		directory := f.options.ProfileDirectory
		token := strings.Repeat("x", maxNativeContextBytes)
		for i := range 3 {
			if _, err := AllowWorkspace(t.Context(), directory, WorkspaceApproval{Alias: "large-" + fmtWorkspaceID(i), Directory: t.TempDir(), NativeContext: token}); err != nil {
				t.Fatal(err)
			}
		}
		assertOversizeLeavesBundle(t, directory, token)
	})
}

func assertOversizeLeavesBundle(t *testing.T, directory, token string) {
	t.Helper()

	// The base partition is four MiB minus the revocation reserve. Three
	// one-MiB contexts fit; a fourth must not consume pins or revocation space.
	before, err := os.ReadFile(filepath.Join(directory, profileName))
	if err != nil {
		t.Fatal(err)
	}
	_, allowErr := AllowWorkspace(t.Context(), directory, WorkspaceApproval{Alias: "large-fourth", Directory: t.TempDir(), NativeContext: token})

	after, readErr := os.ReadFile(filepath.Join(directory, profileName))
	if !errors.Is(allowErr, ErrCapacity) || readErr != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("oversize changed prior complete bundle", allowErr, readErr)
	}
	if _, err = ListWorkspaces(t.Context(), directory); err != nil {
		t.Fatal("prior committed bundle was unreadable", err)
	}
}

func fmtWorkspaceID(value int) string {
	const alphabet = "0123456789abcdef"
	id := []byte(strings.Repeat("0", 32))
	id[30] = alphabet[(value/16)%16]
	id[31] = alphabet[value%16]
	return string(id)
}

func TestProfileBudgetCountsEachCopiedWorkspacePolicy(t *testing.T) {
	// Five approvals sharing these immutable in-memory strings would encode more
	// than eight MiB. Refuse before allocating that JSON, despite shared backing.
	models := make([]string, 100)
	for i := range models {
		models[i] = fmtWorkspaceID(i) + strings.Repeat("m", 160)
	}
	providers := make([]ProviderPolicy, 100)
	for i := range providers {
		providers[i] = ProviderPolicy{Provider: fmtWorkspaceID(i), Models: models, Permissions: []string{"read-only"}, MaxBudgetSeconds: 60}
	}
	p := profile{Workspaces: make([]workspaceRecord, 5)}
	for i := range p.Workspaces {
		p.Workspaces[i].Providers = providers
	}
	if !p.payloadBytesExceedBudget() {
		t.Fatal("copied policy encoding evaded the total byte bound")
	}
}
