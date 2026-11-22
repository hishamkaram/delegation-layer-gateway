package connectorconfig

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
)

func TestStaticConfigurationMigrationRequiresAcceptanceAndPreservesPins(t *testing.T) {
	f := fixture(t)
	legacy := legacyDocument{document: f.doc}
	legacy.Version = 1
	for _, project := range f.doc.Projects {
		legacy.Projects = append(legacy.Projects, legacyProjectDocument{projectDocument: project, Providers: []json.RawMessage{json.RawMessage(`{"provider":"old-provider","permissions":["read-only"],"max_budget_seconds":60}`)}})
	}
	before, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(f.path); !errors.Is(err, ErrMigrationRequired) {
		t.Fatal("old configuration ran without explicit migration", err)
	}
	preview, err := PreviewMigration(f.path)
	if err != nil || preview != (MigrationPreview{FromVersion: 1, ToVersion: 2, Projects: 1, ExecutionPolicies: 1}) {
		t.Fatal("invalid migration preview", preview, err)
	}
	if _, err = Migrate(t.Context(), f.path, false); !errors.Is(err, ErrMigrationAcceptanceRequired) {
		t.Fatal("saved execution policy removed without acceptance", err)
	}
	after, err := os.ReadFile(f.path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("preview/refusal rewrote configuration", err)
	}
	if _, err = Migrate(t.Context(), f.path, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Adapter(); !reflect.DeepEqual(got.Projects, []connector.Project{f.doc.Projects[0].value()}) || loaded.IdentityDirectory() != f.doc.IdentityDirectory || got.Executable != f.doc.Executable {
		t.Fatal("migration changed installed source, credentials or context pins")
	}
	assertCurrentMigrationReplay(t, f.path)
}

func assertCurrentMigrationReplay(t *testing.T, path string) {
	t.Helper()
	published, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Migrate(t.Context(), path, false)
	if err != nil || preview != (MigrationPreview{FromVersion: 2, ToVersion: 2, Projects: 1}) {
		t.Fatal("current configuration retry required another removal acceptance", err)
	}
	replayed, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(replayed, published) {
		t.Fatal("current configuration retry changed already-published bytes", err)
	}
}
