package connector

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestMetadataPublicationRejectsReloadInsideApprovalRecheck(t *testing.T) {
	f, original, _ := newRoutedFixture(t)
	command := filesystemCommand(t, f, protocol.FileSelection{ScopeID: "workspace-one", RelativePath: "file"})
	r, err := f.adapter.decodeRequest(t.Context(), f.adapter.snapshot(), command)
	if err != nil {
		t.Fatal(err)
	}
	state, err := original.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	state.Workspaces[0].Enabled = false
	config := f.adapter.snapshot().Config
	config.ProjectStore = &workspaceTestStore{state: state, pins: make(map[string]ProjectPin)}
	var reloadErr error
	original.beforeLock = func(*WorkspaceSnapshot) {
		// Reentrant replacement proves no Adapter mutex spans owner callbacks.
		reloadErr = f.adapter.Reload(t.Context(), config)
	}
	value := protocol.FilesystemResponse{SchemaVersion: 1, Operation: "read", ObservedAt: time.Now().UTC(), Read: &protocol.FileRange{DataBase64: base64.StdEncoding.EncodeToString([]byte("private")), NextOffset: 7, EOF: true, Version: "file-version"}}
	if value.ValidateFor(command.Operation, *r.filesystem) != nil {
		t.Fatal("test output is not an independently valid Native observation")
	}
	reply := f.adapter.publishMetadata(t.Context(), r, value)
	if reloadErr != nil || len(reply.Body) != 0 {
		t.Fatal("publication released output or held a mutex over the owner callback", reloadErr)
	}
	assertCode(t, reply, "context_mismatch")
}

func TestMetadataReloadDuringNativeControlWithholdsOldOwnerOutput(t *testing.T) {
	cases := []struct {
		name    string
		blocked string
		command func(*testing.T, *fixture, protocol.ModelQuery) protocol.Command
	}{
		{"read_file", "filesystem", func(t *testing.T, f *fixture, _ protocol.ModelQuery) protocol.Command {
			if err := os.WriteFile(filepath.Join(f.config.Projects[0].Directory, "file.txt"), []byte("old owner private bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filesystemCommand(t, f, protocol.FileSelection{ScopeID: "workspace-one", RelativePath: "file.txt"})
		}},
		{"select_project", "providers", func(t *testing.T, f *fixture, query protocol.ModelQuery) protocol.Command {
			return protocol.Command{Operation: protocol.SelectProject, Root: modelCommand(t, f, query).Root, Body: encoded(t, protocol.SelectionRequest{Selection: query.Selection})}
		}},
		{"provider_models", "models", modelCommand},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f, store, query := newModelsFixture(t)
			assertMetadataReloadWithholds(t, f, store, test.command(t, f, query), test.blocked)
		})
	}
}

func assertMetadataReloadWithholds(t *testing.T, f *fixture, original *workspaceTestStore, command protocol.Command, blocked string) {
	t.Helper()
	f.state.Block = blocked
	f.writeState()
	replies := make(chan protocol.Reply, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		replies <- f.adapter.Execute(t.Context(), command)
	}()
	t.Cleanup(func() {
		f.release()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("replaced metadata control owner did not join")
		}
	})
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+blocked))
	state, err := original.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	state.Workspaces[0].Enabled = false
	replacement := &workspaceTestStore{state: state, pins: make(map[string]ProjectPin)}
	config := f.adapter.snapshot().Config
	config.ProjectStore = replacement
	if err = f.adapter.Reload(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	f.release()
	reply := <-replies
	if len(reply.Body) != 0 {
		t.Fatal("replaced configuration released old owner output")
	}
	assertCode(t, reply, "context_mismatch")
	prior, err := original.Snapshot(t.Context())
	if err != nil || !prior.Workspaces[0].Enabled {
		t.Fatal("test mutated old approval instead of replacing its owner", err)
	}
	if status := f.adapter.Status(); status.Active != 0 || status.CleanupPending != 0 {
		t.Fatal("reloaded metadata publication retained its process owner")
	}
}
