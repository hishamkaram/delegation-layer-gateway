package connector

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func helperFilesystem(flags map[string]string, action string, state helperState) int {
	if state.FilesystemFailure != "" {
		return emitHelperResponse(map[string]any{"schema_version": 1, "command": "filesystem", "failure": map[string]any{"code": state.FilesystemFailure, "stage": "file_read", "retryable": true}}, "")
	}
	data, err := os.ReadFile(flags["request"])
	if err != nil {
		return 91
	}
	var request cliFilesystemRequest
	if json.Unmarshal(data, &request) != nil {
		return 92
	}
	if request.ExpectedRoot != strings.Repeat("a", 64) {
		return emitHelperResponse(map[string]any{"schema_version": 1, "command": "filesystem", "failure": map[string]any{"code": "changed", "stage": "root_guard", "retryable": true}}, "")
	}
	result := cliFilesystemResult{FilesystemResponse: protocol.FilesystemResponse{SchemaVersion: 1, Operation: action, ObservedAt: time.Now().UTC()}}
	if action == "scopes" {
		if request.Scope != (filesystemScope{}) {
			return emitHelperResponse(map[string]any{"schema_version": 1, "command": "filesystem", "failure": map[string]any{"code": "invalid_request", "stage": "scopes", "retryable": false}}, "")
		}
		result.Scopes = &struct {
			Scopes []cliFilesystemScope `json:"scopes"`
		}{Scopes: []cliFilesystemScope{{ID: "native-shared-id", Kind: "shared_temp", Name: "Native shared temporary files", Directory: state.AutomaticDirectory}}}
	} else {
		directory := request.Scope.Directory
		if directory == "" {
			directory = state.AutomaticDirectory
		}
		path := request.RelativePath
		if request.RelativePathBase64 != "" {
			raw, decodeErr := base64.StdEncoding.Strict().DecodeString(request.RelativePathBase64)
			if decodeErr != nil {
				return 93
			}
			path = string(raw)
		}
		value, readErr := os.ReadFile(filepath.Join(directory, path))
		if readErr != nil {
			return 94
		}
		result.Read = &protocol.FileRange{DataBase64: base64.StdEncoding.EncodeToString(value), Offset: request.Offset, NextOffset: request.Offset + int64(len(value)), EOF: true, Version: "native-file-version"}
	}
	return emitHelperResponse(map[string]any{"schema_version": 1, "command": "filesystem", "filesystem": result}, "")
}

func filesystemCommand(t *testing.T, f *fixture, selection protocol.FileSelection) protocol.Command {
	t.Helper()
	return protocol.Command{Operation: protocol.ReadFile, Root: protocol.WireContextGuard(f.config.Projects[0].RootToken), Body: encoded(t, protocol.FilesystemRequest{Selection: selection})}
}

func TestFilesystemReadPreservesExactBytesAndCreatesNoPins(t *testing.T) {
	f, store, _ := newRoutedFixture(t)
	bytes := []byte{0, 1, 255, 'p', 'r', 'i', 'v', 'a', 't', 'e'}
	name := string([]byte{'f', 255})
	if err := os.WriteFile(filepath.Join(f.config.Projects[0].Directory, name), bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	selection := protocol.FileSelection{ScopeID: "workspace-one", RelativePathBase64: base64.StdEncoding.EncodeToString([]byte(name))}
	reply := f.adapter.Execute(t.Context(), filesystemCommand(t, f, selection))
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var result protocol.FilesystemResponse
	if protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes) != nil || result.Read == nil || result.Read.DataBase64 != base64.StdEncoding.EncodeToString(bytes) {
		t.Fatal("connector changed requested bytes")
	}
	if len(store.pins) != 0 {
		t.Fatal("filesystem read saved a project pin")
	}
}

func TestAutomaticScopeDiscoveryNormalizesNativeDirectories(t *testing.T) {
	f, _, task := newRoutedFixture(t)
	f.state.AutomaticDirectory = t.TempDir()
	f.writeState()
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.FilesystemScopes, Root: task.Context.Root, Body: encoded(t, protocol.FilesystemRequest{})})
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var result protocol.FilesystemResponse
	if protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes) != nil || result.Scopes == nil || len(result.Scopes.Scopes) != 1 || result.Scopes.Scopes[0].ID != protocol.SharedTempScope {
		t.Fatal("Native automatic scope was not mapped to stable wire identity")
	}
	if strings.Contains(string(reply.Body), f.state.AutomaticDirectory) {
		t.Fatal("Native temporary directory entered remote metadata")
	}
}

func TestFilesystemRevocationDuringNativeReadWithholdsBytes(t *testing.T) {
	f, store, _ := newRoutedFixture(t)
	if err := os.WriteFile(filepath.Join(f.config.Projects[0].Directory, "file.txt"), []byte("withheld bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.state.Block = "filesystem"
	f.writeState()
	result := make(chan protocol.Reply, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- f.adapter.Execute(t.Context(), filesystemCommand(t, f, protocol.FileSelection{ScopeID: "workspace-one", RelativePath: "file.txt"}))
	}()
	t.Cleanup(func() {
		f.release()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("filesystem owner did not join")
		}
	})
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-filesystem"))
	store.mu.Lock()
	store.state.Workspaces[0].Enabled = false
	store.mu.Unlock()
	f.release()
	reply := <-result
	if reply.Error == nil || len(reply.Body) != 0 {
		t.Fatal("revoked approval released Native file bytes")
	}
}
