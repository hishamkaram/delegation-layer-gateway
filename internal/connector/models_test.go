package connector

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func helperModels(flags map[string]string, state helperState) int {
	if flags["cwd"] != "" || flags["expected-root"] != strings.Repeat("a", 64) || flags["expected-workspace-file"] == "" || flags["relative-project"] == "" || flags["control-timeout"] != "" {
		return 91
	}
	var response map[string]any
	if json.Unmarshal(state.ModelCatalog, &response) != nil {
		return 92
	}
	response["schema_version"], response["command"], response["provider"], response["observed_at"] = 1, "models", flags["provider"], time.Now().UTC().Format(time.RFC3339Nano)
	if state.ModelsFailure != "" {
		response["failure"] = map[string]any{"code": state.ModelsFailure, "stage": "validate-request", "next_action": "PRIVATE-CANARY"}
		response["error"] = "PRIVATE-CANARY"
	}
	if code := emitHelperResponse(response, ""); code != 0 {
		return code
	}
	return state.ModelsExit
}

func newModelsFixture(t *testing.T) (*fixture, *workspaceTestStore, protocol.ModelQuery) {
	t.Helper()
	f, store, task := newRoutedFixture(t)
	f.state.Features = append(f.state.Features, protocol.FeatureScopedModels)
	f.state.ModelCatalog = json.RawMessage(`{"status":"available","reason_code":"discovered","complete":true,"source":"native actual catalog","models":[{"id":"zeta","efforts":null},{"id":"alpha with space","name":"Reported Name","efforts":["high","low"],"default_effort":"low"},{"id":"beta","efforts":[]}],"efforts":["high","low"]}`)
	f.writeState()
	return f, store, protocol.ModelQuery{Selection: task.Route.Selection, Provider: "actual-provider", Limit: 1}
}

func modelCommand(t *testing.T, f *fixture, query protocol.ModelQuery) protocol.Command {
	t.Helper()
	return protocol.Command{Operation: protocol.ProviderModels, Root: protocol.WireContextGuard(f.config.Projects[0].RootToken), Body: encoded(t, query)}
}

func readModelPage(t *testing.T, query protocol.ModelQuery, reply protocol.Reply) protocol.ModelPage {
	t.Helper()
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var page protocol.ModelPage
	if protocol.DecodeStrict(reply.Body, &page, protocol.MaxFrameBytes) != nil || page.ValidateFor(query) != nil {
		t.Fatal("invalid model page")
	}
	return page
}

func TestModelsUseGuardedNativeScopeAndStableCatalogPagination(t *testing.T) {
	f, store, query := newModelsFixture(t)
	first := readModelPage(t, query, f.adapter.Execute(t.Context(), modelCommand(t, f, query)))
	assertModelRow(t, first, "alpha with space", false)
	if !first.CatalogComplete {
		t.Fatal("complete Native catalog became partial")
	}
	query.Cursor = first.NextCursor
	f.state.ModelCatalog = json.RawMessage(`{"status":"available","reason_code":"discovered","complete":true,"source":"native actual catalog","models":[{"id":"beta","efforts":[]},{"id":"zeta","efforts":null},{"id":"alpha with space","name":"Reported Name","efforts":["low","high"],"default_effort":"low"}],"efforts":["low","high"]}`)
	f.writeState()
	second := readModelPage(t, query, f.adapter.Execute(t.Context(), modelCommand(t, f, query)))
	assertModelRow(t, second, "beta", false)
	if second.Version != first.Version || !second.ObservedAt.After(first.ObservedAt) {
		t.Fatal("observation time changed the catalog version or cursor position")
	}
	query.Cursor = second.NextCursor
	third := readModelPage(t, query, f.adapter.Execute(t.Context(), modelCommand(t, f, query)))
	assertModelRow(t, third, "zeta", true)
	assertGuardedModelCalls(t, f, store.state.Workspaces[0].NativeContext)
	if len(store.pins) != 0 || strings.Contains(string(encoded(t, first)), store.state.Workspaces[0].NativeContext) {
		t.Fatal("model discovery saved pins or exposed local approval tokens")
	}
}

func assertModelRow(t *testing.T, page protocol.ModelPage, expected string, eof bool) {
	t.Helper()
	if len(page.Models) != 1 || page.Models[0].ID != expected || page.EOF != eof {
		t.Fatal("model page did not preserve the expected sorted row and EOF")
	}
}

func assertGuardedModelCalls(t *testing.T, f *fixture, workspace string) {
	t.Helper()
	for _, call := range f.calls() {
		if call.Command != "models" {
			continue
		}
		flags, _, _, _ := helperArguments(call.Args)
		if flags["cwd"] != "" || flags["expected-project"] != "" || flags["origin"] != "" || flags["expected-root"] != f.config.Projects[0].RootToken || flags["relative-project"] != "." || call.ExpectedWorkspaceToken != workspace || call.WorkspaceMode != 0o600 {
			t.Fatal("models lost exact private scope custody")
		}
	}
}

func TestModelDiscoveryUsesNativeCatalogResourceBound(t *testing.T) {
	for _, count := range []int{4096, 4097} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			f, _, query := newModelsFixture(t)
			models := make([]map[string]any, 0, count)
			for i := range count {
				models = append(models, map[string]any{"id": "provider model " + strconv.Itoa(i), "efforts": nil})
			}
			data, err := json.Marshal(map[string]any{"status": "available", "reason_code": "discovered", "complete": true, "source": "Native", "models": models, "efforts": nil})
			if err != nil {
				t.Fatal(err)
			}
			f.state.ModelCatalog = data
			f.writeState()
			query.Limit = 0
			reply := f.adapter.Execute(t.Context(), modelCommand(t, f, query))
			if count == 4097 {
				assertCode(t, reply, "evidence_invalid")
				return
			}
			page := readModelPage(t, query, reply)
			if len(page.Models) != 100 || page.EOF {
				t.Fatal("full Native catalog was truncated or ignored the wire page bound")
			}
		})
	}
}

func TestModelCursorRejectsChangedCatalogOrBinding(t *testing.T) {
	for _, change := range []string{"catalog", "provider", "position"} {
		t.Run(change, func(t *testing.T) {
			f, _, query := newModelsFixture(t)
			page := readModelPage(t, query, f.adapter.Execute(t.Context(), modelCommand(t, f, query)))
			query.Cursor = page.NextCursor
			switch change {
			case "catalog":
				f.state.ModelCatalog = json.RawMessage(strings.ReplaceAll(string(f.state.ModelCatalog), "zeta", "omega"))
				f.writeState()
			case "provider":
				query.Provider = "another-provider"
			case "position":
				data, err := base64.RawURLEncoding.Strict().DecodeString(query.Cursor)
				var cursor protocol.ModelCursor
				if err != nil || json.Unmarshal(data, &cursor) != nil {
					t.Fatal("could not read returned cursor")
				}
				cursor.Next = 4096
				query.Cursor, err = protocol.EncodeModelCursor(cursor)
				if err != nil {
					t.Fatal(err)
				}
			}
			assertCode(t, f.adapter.Execute(t.Context(), modelCommand(t, f, query)), "catalog_changed")
		})
	}
}

func TestModelsRejectInvalidFactsAndOperationalFailure(t *testing.T) {
	for _, fault := range []string{"duplicate", "failure"} {
		t.Run(fault, func(t *testing.T) {
			f, _, query := newModelsFixture(t)
			if fault == "duplicate" {
				f.state.ModelCatalog = json.RawMessage(strings.ReplaceAll(string(f.state.ModelCatalog), `"id":"zeta"`, `"id":"beta"`))
			} else {
				f.state.ModelsFailure, f.state.ModelsExit = "context_mismatch", 1
			}
			f.writeState()
			reply := f.adapter.Execute(t.Context(), modelCommand(t, f, query))
			code := "evidence_invalid"
			if fault == "failure" {
				code = "context_mismatch"
			}
			assertCode(t, reply, code)
			if len(reply.Body) != 0 || strings.Contains(string(encoded(t, reply)), "PRIVATE-CANARY") {
				t.Fatal("invalid facts or diagnostics became advisory success")
			}
		})
	}
}

func TestModelDiscoveryRechecksApprovalBeforeStart(t *testing.T) {
	f, store, query := newModelsFixture(t)
	store.mu.Lock()
	store.beforeLock = func(state *WorkspaceSnapshot) { state.Workspaces[0].Enabled = false }
	store.mu.Unlock()
	assertCode(t, f.adapter.Execute(t.Context(), modelCommand(t, f, query)), "context_mismatch")
	for _, call := range f.calls() {
		if call.Command == "models" {
			t.Fatal("revoked approval reached Native model inspection")
		}
	}
}

func TestModelDiscoveryWithholdsFactsRevokedDuringInspection(t *testing.T) {
	f, store, query := newModelsFixture(t)
	f.state.Block = "models"
	f.writeState()
	replies := make(chan protocol.Reply, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		replies <- f.adapter.Execute(t.Context(), modelCommand(t, f, query))
	}()
	t.Cleanup(func() {
		f.release()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("model inspection owner did not join")
		}
	})
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-models"))
	store.mu.Lock()
	store.state.Workspaces[0].Enabled = false
	store.mu.Unlock()
	f.release()
	reply := <-replies
	if reply.Error == nil || len(reply.Body) != 0 {
		t.Fatal("revoked approval released Native model facts")
	}
}

func TestAutomaticSelectionAndModelsKeepNativeScopeRootConstraint(t *testing.T) {
	f, store, query := newModelsFixture(t)
	f.state.AutomaticDirectory = t.TempDir()
	f.writeState()
	if err := os.Mkdir(filepath.Join(f.state.AutomaticDirectory, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	query.Selection = protocol.FileSelection{ScopeID: protocol.SharedTempScope, RelativePath: "child"}
	selection := protocol.SelectionRequest{Selection: query.Selection}
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.SelectProject, Root: modelCommand(t, f, query).Root, Body: encoded(t, selection)})
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var observed protocol.SelectionObservation
	if protocol.DecodeStrict(reply.Body, &observed, protocol.MaxFrameBytes) != nil || observed.WorkspaceGuard != protocol.WireContextGuard(f.config.Projects[0].ProjectToken) {
		t.Fatal("automatic selection did not freeze the Native scope-root guard")
	}
	readModelPage(t, query, f.adapter.Execute(t.Context(), modelCommand(t, f, query)))
	for _, call := range f.calls() {
		flags, _, _, _ := helperArguments(call.Args)
		if call.Command == "context" && flags["cwd"] != "" && flags["cwd"] != f.state.AutomaticDirectory {
			t.Fatal("automatic selection inspected an unconstrained joined child")
		}
		if call.Command == "models" && (call.ExpectedWorkspaceToken != f.config.Projects[0].ProjectToken || flags["relative-project"] != "child") {
			t.Fatal("models discarded the Native scope-root token")
		}
	}
	if len(store.pins) != 0 {
		t.Fatal("automatic scope added local approval or pin history")
	}
}

func TestAutomaticTaskBindingKeepsNativeScopeRootForAdmissionAndRecovery(t *testing.T) {
	f, _, task := newRoutedFixture(t)
	f.state.AutomaticDirectory = t.TempDir()
	f.writeState()
	task.Route.Selection = protocol.FileSelection{ScopeID: protocol.SharedTempScope, RelativePath: "child"}
	task.Route.WorkspaceGuard = protocol.WireContextGuard(f.config.Projects[0].ProjectToken)
	task.SpecSHA256 = ""
	admission := protocol.Admission{Task: task, Native: protocol.NativeOptions{Version: 1, Provider: "fixture", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}}, Brief: f.state.Brief}
	r, err := f.adapter.decodeRequest(t.Context(), f.adapter.snapshot(), protocol.Command{Operation: protocol.Admit, Project: task.Origin.OperationID, Body: encoded(t, admission)})
	if err != nil {
		t.Fatal(err)
	}
	owner := &controlOwner{temporary: t.TempDir()}
	r, _, err = f.adapter.bindRoutedProject(t.Context(), r, owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []protocol.Operation{protocol.Admit, protocol.ResumeExisting} {
		r.command.Operation = operation
		if operation == protocol.ResumeExisting {
			r.task.SpecSHA256 = strings.Repeat("c", 64)
		}
		call, callErr := r.invocation(t.Context(), owner)
		if callErr != nil {
			t.Fatal(callErr)
		}
		flags, _, _, _ := helperArguments(call.args)
		if flags["expected-workspace"] != f.config.Projects[0].ProjectToken || flags["relative-project"] != "child" || flags["expected-project"] != f.config.Projects[0].ProjectToken || flags["expected-project-sha256"] != "" {
			t.Fatal("new admission/recovery lost exact live scope-root custody")
		}
	}
	r.task.Route.WorkspaceGuard = protocol.WireContextGuard("another scope-root token")
	if _, err = f.adapter.bindScopedProject(t.Context(), r, &controlOwner{temporary: t.TempDir()}); err == nil {
		t.Fatal("changed automatic scope-root guard reached new admission")
	}
}

func TestHistoricalAutomaticTaskControlsNeverReopenNativeScope(t *testing.T) {
	f, _, task := newRoutedFixture(t)
	task.Route.Selection = protocol.FileSelection{ScopeID: protocol.SharedTempScope, RelativePath: "child"}
	task.Route.WorkspaceGuard = protocol.WireContextGuard("saved automatic scope-root token")
	f.state.FrozenWorkspaceToken, f.state.FrozenRelativePath = "saved automatic scope-root token", "child"
	f.writeState()
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.Status, Project: task.Origin.OperationID, Body: encoded(t, protocol.TaskControl{Task: task})})
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	for _, call := range f.calls() {
		flags, _, _, _ := helperArguments(call.Args)
		if call.Command == "filesystem" || flags["cwd"] != "" || flags["expected-workspace"] != "" {
			t.Fatal("historical task control reopened a current automatic scope")
		}
	}
}
