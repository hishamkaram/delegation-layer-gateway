package deviceclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func oldProfileFixture(t *testing.T) (*gatewayFixture, profile, []byte) {
	t.Helper()
	f, projects, pin := projectFixture(t)
	commitProject(t, projects, pin)
	if _, err := Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	store, err := openProfile(f.options.ProfileDirectory, false, true)
	if err != nil {
		t.Fatal(err)
	}
	current := *store.value
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	current.Workspaces[0].Enabled = false
	legacy := legacyProfileDocument{profile: current}
	legacy.Version = 2
	legacy.Providers = []json.RawMessage{json.RawMessage(`{"provider":"private-policy-canary","permissions":["read-only"],"max_budget_seconds":1}`)}
	for _, workspace := range current.Workspaces {
		legacy.Workspaces = append(legacy.Workspaces, legacyWorkspaceRecord{workspaceRecord: workspace, Providers: []json.RawMessage{json.RawMessage(`{"provider":"private-policy-canary"}`)}})
	}
	data, err := protocol.Encode(legacy, maxProfileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.options.ProfileDirectory, profileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return f, current, data
}

func TestProfileMigrationRequiresAcceptanceAndPreservesDisabledHistory(t *testing.T) {
	f, original, bytesBefore := oldProfileFixture(t)
	directory := f.options.ProfileDirectory
	if _, err := LocalContext(t.Context(), directory); !errors.Is(err, ErrMigrationRequired) {
		t.Fatal("old profile executed without explicit migration", err)
	}
	preview, err := PreviewProfileMigration(t.Context(), directory)
	if err != nil || preview != (ProfileMigrationPreview{FromVersion: 2, ToVersion: 3, GatewayID: original.Descriptor.GatewayID, Workspaces: 1, DisabledWorkspaces: 1, Pins: 1, ExecutionPolicies: 2}) {
		t.Fatal("migration preview lost metadata", preview, err)
	}
	if _, err = MigrateProfile(t.Context(), ProfileMigrationOptions{ProfileDirectory: directory}); !errors.Is(err, ErrMigrationAcceptanceRequired) {
		t.Fatal("old execution policy removed without explicit acceptance", err)
	}
	afterPreview, err := os.ReadFile(filepath.Join(directory, profileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bytesBefore, afterPreview) {
		t.Fatal("preview/refusal mutated profile")
	}
	source, err := ProfileMigrationSource(t.Context(), directory)
	if err != nil || source.DelegateRootContext != original.DelegateRootContext || len(source.WorkspaceIDs) != 1 || source.WorkspaceIDs[0] != original.Workspaces[0].ID {
		t.Fatal("readonly migration source lost original identity", err)
	}
	if _, err = MigrateProfile(t.Context(), ProfileMigrationOptions{ProfileDirectory: directory, AcceptExecutionPolicyRemoval: true}); err != nil {
		t.Fatal(err)
	}
	store, err := openProfile(directory, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	original.Version = 3
	if !reflect.DeepEqual(*store.value, original) {
		t.Fatal("migration changed source, workspace approval/revision or immutable pins")
	}
}

func TestInstallationSelectionHandoffPreservesRootAndUsesExpectedSource(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	directory := f.options.ProfileDirectory
	source, err := ProfileMigrationSource(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	expected := source.InstallationSelection()
	selected := expected
	selected.DelegateExecutable = filepath.Join(t.TempDir(), "new-delegate")
	if err = os.WriteFile(selected.DelegateExecutable, []byte("installed executable fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	wrong := selected
	wrong.DelegateRootContext = "other-root"
	if err = UpdateInstallationSelection(t.Context(), directory, expected, wrong); !errors.Is(err, ErrConfiguration) {
		t.Fatal("handoff retargeted original root", err)
	}
	if err = UpdateInstallationSelection(t.Context(), directory, expected, selected); err != nil {
		t.Fatal(err)
	}
	if err = UpdateInstallationSelection(t.Context(), directory, expected, selected); !errors.Is(err, ErrConflict) {
		t.Fatal("stale source CAS accepted", err)
	}
	current, err := LocalContext(t.Context(), directory)
	if err != nil || current.InstallationSelection() != selected {
		t.Fatal("handoff did not publish selected installed executable", err)
	}
}

func TestMigrationObservationsPreserveCredentialIdentity(t *testing.T) {
	f, _, beforeBytes := oldProfileFixture(t)
	directory := f.options.ProfileDirectory
	before, err := Status(t.Context(), directory)
	if err != nil || before.DeviceID == "" {
		t.Fatal("old profile credential observation unavailable", err)
	}
	inactive, err := RuntimeInactive(t.Context(), directory)
	if err != nil || !inactive {
		t.Fatal("old profile quiescence observation unavailable", err)
	}
	if _, err = MigrateProfile(t.Context(), ProfileMigrationOptions{ProfileDirectory: directory, AcceptExecutionPolicyRemoval: true}); err != nil {
		t.Fatal(err)
	}
	after, err := Status(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	if after.DeviceID != before.DeviceID || after.OwnerPrincipal != before.OwnerPrincipal || after.CredentialGeneration != before.CredentialGeneration || after.CertificateExpiresAt != before.CertificateExpiresAt {
		t.Fatal("profile migration changed enrolled credential identity")
	}
	if len(beforeBytes) == 0 {
		t.Fatal("missing old profile evidence")
	}
}

func TestProfileMigrationCannotCutOverWhileIdentityProducerOwnsLease(t *testing.T) {
	f, _, before := oldProfileFixture(t)
	identity, err := openExistingIdentity(f.options.ProfileDirectory)
	if err != nil {
		t.Fatal(err)
	}
	_, migrationErr := MigrateProfile(t.Context(), ProfileMigrationOptions{ProfileDirectory: f.options.ProfileDirectory, AcceptExecutionPolicyRemoval: true})
	if err = identity.Close(); err != nil {
		t.Fatal(err)
	}
	if !IsBusy(migrationErr) {
		t.Fatal("live identity producer did not fence profile schema cutover", migrationErr)
	}
	after, err := os.ReadFile(filepath.Join(f.options.ProfileDirectory, profileName))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("refused cutover changed saved profile", err)
	}
}
