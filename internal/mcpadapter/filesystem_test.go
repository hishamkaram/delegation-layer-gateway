package mcpadapter

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type filesystemCall struct {
	actor     domain.Actor
	device    domain.DeviceID
	operation protocol.Operation
	request   protocol.FilesystemRequest
}

type filesystemBackend struct {
	calls chan filesystemCall
	read  func(context.Context, filesystemCall) (protocol.FilesystemResponse, error)
	check func(context.Context, domain.Actor, gateway.MetadataSource, domain.ScopeSet) error
}

func (b *filesystemBackend) ObserveFilesystem(ctx context.Context, actor domain.Actor, device domain.DeviceID, operation protocol.Operation, request protocol.FilesystemRequest) (gateway.MetadataObservation[protocol.FilesystemResponse], error) {
	call := filesystemCall{actor: actor, device: device, operation: operation, request: request}
	b.calls <- call
	value, err := b.read(ctx, call)
	return gateway.MetadataObservation[protocol.FilesystemResponse]{Value: value, Source: testMetadataSource(device, operation)}, err
}

func (b *filesystemBackend) CheckMetadataObservation(ctx context.Context, actor domain.Actor, source gateway.MetadataSource, additional domain.ScopeSet) error {
	if source.Validate() != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if b.check != nil {
		return b.check(ctx, actor, source, additional)
	}
	return checkTestMetadataScopes(ctx, nil, actor, source, additional)
}

// These source values support consumer-boundary tests only. The workspace
// service tests independently exercise real SQLite credentials and WSS routing.
func testMetadataSource(device domain.DeviceID, operation protocol.Operation) gateway.MetadataSource {
	return gateway.MetadataSource{Binding: domain.OwnedRootBinding{Route: domain.RootRoute{Device: device, Root: domain.RootGuard(protocol.WireContextGuard("root"))}, Credential: domain.CredentialRef{Device: device, Epoch: "fixture-credential", Generation: 1}, Connection: domain.ConnectionGeneration{BootEpoch: "fixture-connection", Counter: 1}}, Operation: operation}
}

func ownedFilesystemDevice(t *testing.T, f *fixture) domain.DeviceID {
	t.Helper()
	check(t, f.store.PutOwnerPolicy(t.Context(), f.alice.Principal, domain.OwnerPolicy{Enabled: true, Scopes: f.alice.Scopes, MaxDevices: 1}))
	device, err := f.store.CreateOwnedEnrollment(t.Context(), f.alice.Principal, "filesystem-device", domain.Hash([]byte("filesystem-bootstrap")), f.clock.now())
	check(t, err)
	return device.ID
}

func filesystemFixture(t *testing.T, recorder Recorder, read func(context.Context, filesystemCall) (protocol.FilesystemResponse, error)) (*fixture, domain.DeviceID, *filesystemBackend) {
	t.Helper()
	backend := &filesystemBackend{calls: make(chan filesystemCall, 16), read: read}
	f := newConfiguredFixture(t, 0, recorder, func(options *Options) { options.Filesystem = backend })
	return f, ownedFilesystemDevice(t, f), backend
}

func fileResponse(data []byte, text *string) protocol.FilesystemResponse {
	return protocol.FilesystemResponse{SchemaVersion: 1, Operation: "read", ObservedAt: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), Read: &protocol.FileRange{DataBase64: base64.StdEncoding.EncodeToString(data), Text: text, NextOffset: int64(len(data)), EOF: true, Version: "file-version"}}
}

func TestRegisteredFilesystemToolsAdvertiseClosedAllOfAuthorization(t *testing.T) {
	f, device, backend := filesystemFixture(t, nil, func(context.Context, filesystemCall) (protocol.FilesystemResponse, error) {
		return fileResponse([]byte{0xff, 0}, nil), nil
	})
	assertFilesystemCatalog(t, f)
	input := FileReadInput{DeviceID: string(device), ScopeID: protocol.SharedTempScope, RelativePath: "requested", Limit: 64}
	for _, token := range []string{"inventory", "read", "dispatch", "bob"} {
		code := "forbidden"
		if token == "bob" {
			code = "not_found"
		}
		expectError[protocol.FilesystemResponse](t, f.call(t, f.session(t, token), "read_file", args(t, input)), code)
	}
	if len(backend.calls) != 0 {
		t.Fatal("partial token or other owner reached filesystem backend")
	}
	result := decodeResult[protocol.FilesystemResponse](t, f.call(t, f.session(t, "alice"), "read_file", args(t, input)))
	if result.Error != nil || result.Data == nil || result.Data.Read == nil || result.Data.Read.DataBase64 != "/wA=" || result.Data.Read.Text != nil {
		t.Fatalf("binary bytes lost: %+v", result)
	}
	call := <-backend.calls
	if call.actor.Principal != f.alice.Principal || call.device != device || call.request.Selection.RelativePath != "requested" || call.request.Limit != 64 {
		t.Fatal("authenticated actor or selector changed before backend")
	}
}

func assertFilesystemCatalog(t *testing.T, f *fixture) {
	t.Helper()
	listed, err := f.session(t, "alice").ListTools(t.Context(), nil)
	check(t, err)
	seen := map[string]bool{}
	for _, tool := range listed.Tools {
		if tool.Name != "list_directory" && tool.Name != "read_file" && tool.Name != "inspect_git" {
			continue
		}
		wire := sdkValue[toolWire](t, tool)
		assertClosed(t, wire.Input)
		assertClosed(t, wire.Output)
		assertToolHints(t, wire, toolExpectation{read: true, idempotent: true})
		if len(wire.Meta.Schemes) != 1 || wire.Meta.Schemes[0].Type != "oauth2" || !slices.Equal(wire.Meta.Schemes[0].Scopes, []string{"task:dispatch", "task:read"}) {
			t.Fatal("file tool advertised OR scopes or anonymous access")
		}
		seen[tool.Name] = true
	}
	if len(seen) != 3 {
		t.Fatal("filesystem tool registration incomplete")
	}
}

func TestFilesystemLongLiveCursorAndRawNameSelectorsReachBackend(t *testing.T) {
	name := string([]byte{'n', '\\', ':', 1, 0xff})
	selector := base64.StdEncoding.EncodeToString([]byte(name))
	cursor := strings.Repeat("x", 512)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	f, device, backend := filesystemFixture(t, nil, func(_ context.Context, call filesystemCall) (protocol.FilesystemResponse, error) {
		if call.operation == protocol.ReadFile {
			return fileResponse([]byte{0xff, 0}, nil), nil
		}
		return protocol.FilesystemResponse{SchemaVersion: 1, Operation: "list", ObservedAt: now, List: &protocol.DirectoryPage{Entries: []protocol.FileEntry{{NameBase64: selector, RelativePathBase64: selector, Kind: "fifo", Size: 0, ModifiedAt: now, Version: "entry-version"}}, Version: "directory-version", NextCursor: cursor, EOF: false}}, nil
	})
	input := DirectoryInput{DeviceID: string(device), ScopeID: protocol.SharedTempScope, Cursor: cursor, Limit: 1}
	page := decodeResult[protocol.FilesystemResponse](t, f.call(t, f.session(t, "alice"), "list_directory", args(t, input)))
	if page.Error != nil || page.Data == nil || page.Data.List == nil || page.Data.List.NextCursor != cursor || page.Data.List.Entries[0].Kind != "fifo" {
		t.Fatalf("live cursor or special/raw entry failed: %+v", page)
	}
	call := <-backend.calls
	if call.request.Cursor != cursor || call.request.Selection.ScopeID != protocol.SharedTempScope {
		t.Fatal("directory cursor or scope was changed")
	}
	read := FileReadInput{DeviceID: string(device), ScopeID: protocol.SharedTempScope, RelativePathBase64: page.Data.List.Entries[0].RelativePathBase64}
	result := decodeResult[protocol.FilesystemResponse](t, f.call(t, f.session(t, "alice"), "read_file", args(t, read)))
	if result.Error != nil || result.Data == nil {
		t.Fatal("lossless raw selector was rejected")
	}
	call = <-backend.calls
	if call.request.Selection.RelativePathBase64 != selector || call.request.Selection.RelativePath != "" {
		t.Fatal("raw Unix selector was normalized or replaced")
	}
}

func TestFilesystemNativeFailuresAndInvalidEvidenceReleaseNoData(t *testing.T) {
	for _, code := range []string{"not_regular_file", "outside_scope", "os_permission_denied", "changed", "temp_unavailable"} {
		t.Run(code, func(t *testing.T) {
			f, device, _ := filesystemFixture(t, nil, func(context.Context, filesystemCall) (protocol.FilesystemResponse, error) {
				return protocol.FilesystemResponse{}, &gateway.RemoteError{Failure: protocol.Failure{Code: code, Stage: "file_kind"}}
			})
			result := f.call(t, f.session(t, "alice"), "read_file", args(t, FileReadInput{DeviceID: string(device), ScopeID: "scope", RelativePath: "requested"}))
			expectError[protocol.FilesystemResponse](t, result, code)
			if decodeResult[protocol.FilesystemResponse](t, result).Error.Stage != "file_kind" {
				t.Fatal("bounded Native failure stage was lost")
			}
			assertPublic(t, result)
		})
	}
	f, device, _ := filesystemFixture(t, nil, func(context.Context, filesystemCall) (protocol.FilesystemResponse, error) {
		response := fileResponse([]byte("bytes"), pointer("different text"))
		return response, nil
	})
	expectError[protocol.FilesystemResponse](t, f.call(t, f.session(t, "alice"), "read_file", args(t, FileReadInput{DeviceID: string(device), ScopeID: "scope"})), "evidence_invalid")
}

func TestFilesystemRechecksRegistryAuthorityAfterNativeAndFinalEncoding(t *testing.T) {
	for _, boundary := range []string{"native", "encoding", "read-scope"} {
		t.Run(boundary, func(t *testing.T) { filesystemRevocationAtBoundary(t, boundary) })
	}
}

func filesystemRevocationAtBoundary(t *testing.T, boundary string) {
	t.Helper()
	gate := &handoffRecorder{entered: make(chan struct{}), unblock: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(gate.unblock) }) }
	var recorder Recorder
	if boundary != "native" {
		recorder = gate
	}
	f, device, _ := filesystemFixture(t, recorder, func(context.Context, filesystemCall) (protocol.FilesystemResponse, error) {
		return fileResponse([]byte(privateCanary), pointer(privateCanary)), nil
	})
	if boundary == "native" {
		backend, ok := f.adapter.options.Filesystem.(*filesystemBackend)
		if !ok {
			t.Fatal("fixture backend missing")
		}
		backend.read = func(ctx context.Context, _ filesystemCall) (protocol.FilesystemResponse, error) {
			return fileResponse([]byte(privateCanary), pointer(privateCanary)), f.store.DisableOwnerPolicy(ctx, f.alice.Principal)
		}
	}
	input := args(t, FileReadInput{DeviceID: string(device), ScopeID: "scope"})
	results := beginBoundaryToolCall(t, f, f.session(t, "alice"), "read_file", input)
	t.Cleanup(release)
	if boundary != "native" {
		awaitBoundaryGate(t, gate.entered, results)
		if boundary == "read-scope" {
			check(t, f.store.PutOwnerPolicy(t.Context(), f.alice.Principal, domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch}, MaxDevices: 1}))
		} else {
			check(t, f.store.DisableOwnerPolicy(t.Context(), f.alice.Principal))
		}
		release()
	}
	result := <-results
	check(t, result.err)
	expectError[protocol.FilesystemResponse](t, result.result, "forbidden")
	assertPublic(t, result.result)
}

func TestFilesystemRequestedContentStaysOutOfAuditAndMetrics(t *testing.T) {
	directory := t.TempDir()
	check(t, os.Chmod(directory, 0o700))
	audit, err := observability.Open(directory, time.Now)
	check(t, err)
	t.Cleanup(func() { check(t, audit.Close()) })
	metrics := &observability.Metrics{}
	recorder, err := observability.NewRecorder(audit, metrics)
	check(t, err)
	f, device, _ := filesystemFixture(t, recorder, func(context.Context, filesystemCall) (protocol.FilesystemResponse, error) {
		return fileResponse([]byte(privateCanary), pointer(privateCanary)), nil
	})
	result := decodeResult[protocol.FilesystemResponse](t, f.call(t, f.session(t, "alice"), "read_file", args(t, FileReadInput{DeviceID: string(device), ScopeID: "scope", RelativePath: privateCanary})))
	if result.Data == nil || result.Data.Read.Text == nil || *result.Data.Read.Text != privateCanary {
		t.Fatal("authorized requested content was filtered")
	}
	entries, err := os.ReadDir(directory)
	check(t, err)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "audit-") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		check(t, readErr)
		if strings.Contains(string(data), privateCanary) || strings.Contains(string(data), base64.StdEncoding.EncodeToString([]byte(privateCanary))) {
			t.Fatal("requested path/content entered audit")
		}
	}
	writer := httptest.NewRecorder()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://unix/metrics", nil)
	check(t, err)
	metrics.ServeHTTP(writer, request)
	if strings.Contains(writer.Body.String(), privateCanary) || strings.Contains(writer.Body.String(), string(device)) {
		t.Fatal("requested content or routing identity entered metric labels")
	}
	if !recorder.Health().AuditHealthy {
		t.Fatal("file metadata recording failed")
	}
}

func TestRegisteredInspectGitForwardsSelectionAndKeepsPartialEvidence(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	f, device, backend := filesystemFixture(t, nil, func(context.Context, filesystemCall) (protocol.FilesystemResponse, error) {
		name := "repository"
		return protocol.FilesystemResponse{SchemaVersion: 1, Operation: "git", ObservedAt: now, Inspect: &protocol.FileInspection{Entry: protocol.FileEntry{Name: &name, NameBase64: "cmVwb3NpdG9yeQ==", RelativePathBase64: "cmVwb3NpdG9yeQ==", Kind: "directory", ModifiedAt: now, Version: "git-directory"}, Git: &protocol.GitInspection{Status: "partial", Kind: "linked_worktree", Reason: "external_metadata"}}}, nil
	})
	input := FileInspectInput{DeviceID: string(device), ScopeID: "scope", RelativePath: "repository"}
	result := decodeResult[protocol.FilesystemResponse](t, f.call(t, f.session(t, "alice"), "inspect_git", args(t, input)))
	if result.Error != nil || result.Data == nil || result.Data.Inspect.Git.Status != "partial" {
		t.Fatal("partial Git marker was rejected or promoted to validated")
	}
	call := <-backend.calls
	if call.operation != protocol.InspectGit || call.request.Selection.ScopeID != "scope" || call.request.Selection.RelativePath != "repository" {
		t.Fatal("Git selection was retargeted")
	}
}
