package connector

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func newRoutedFixture(t *testing.T) (*fixture, *workspaceTestStore, protocol.TaskBinding) {
	t.Helper()
	f, store, _ := newWorkspaceFixture(t)
	f.state.Features = append(f.state.Features, protocol.FeaturePathProject, protocol.FeatureFilesystem, protocol.FeatureNativeOptions, protocol.FeatureProjectHashGuard)
	f.state.FrozenWorkspaceToken = store.state.Workspaces[0].NativeContext
	f.state.FrozenRelativePath = "."
	f.writeState()
	t.Setenv("GATEWAY_CONNECTOR_HELPER_ROOT", f.config.Projects[0].Root)
	task := f.task()
	task.Route = protocol.TaskRoute{Version: 1, Selection: protocol.FileSelection{ScopeID: "workspace-one", RelativePath: "."}, WorkspaceGuard: protocol.WireContextGuard(store.state.Workspaces[0].NativeContext), GuardFormat: protocol.FeatureProjectHashGuard}
	return f, store, task
}

func TestOperationRouteControlsNeedNoPinOrCurrentProject(t *testing.T) {
	f, store, task := newRoutedFixture(t)
	store.mu.Lock()
	store.state.Workspaces[0].Enabled = false
	store.mu.Unlock()
	if err := os.Remove(f.config.Projects[0].Directory); err != nil {
		t.Fatal(err)
	}
	command := protocol.Command{Operation: protocol.Status, Project: task.Origin.OperationID, Body: encoded(t, protocol.TaskControl{Task: task})}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
		t.Fatal("historical route required project/pin/approval", reply.Error.Code)
	}
	for _, call := range f.calls() {
		if call.Command == "resolve" || call.Command == "status" {
			flags, _, _, _ := helperArguments(call.Args)
			if flags["expected-project"] != "" || flags["expected-project-sha256"] != strings.TrimPrefix(task.Context.Project, "ctx1_") {
				t.Fatal("historical control did not use explicit saved project hash")
			}
		}
	}
}

func TestProjectSelectionUsesNativeCatalogWithoutCommittingPin(t *testing.T) {
	f, store, task := newRoutedFixture(t)
	request := protocol.SelectionRequest{Selection: task.Route.Selection}
	command := protocol.Command{Operation: protocol.SelectProject, Root: task.Context.Root, Body: encoded(t, request)}
	reply := f.adapter.Execute(t.Context(), command)
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var result protocol.SelectionObservation
	if protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes) != nil || result.ValidateFor(request) != nil || len(result.Providers) != 1 || result.Providers[0].Provider != "compiled-provider" {
		t.Fatal("selection did not expose actual compiled Native metadata")
	}
	if len(store.pins) != 0 {
		t.Fatal("read-only selection committed a pin")
	}
	if strings.Contains(string(reply.Body), store.state.Workspaces[0].NativeContext) || strings.Contains(string(reply.Body), f.config.Projects[0].Root) {
		t.Fatal("selection exposed local source/token")
	}
}

func TestNativeOptionsArePassedExactlyAndDefaultsStayOmitted(t *testing.T) {
	f, _, task := newRoutedFixture(t)
	r := request{config: f.adapter.snapshot(), project: f.config.Projects[0], task: task, command: protocol.Command{Operation: protocol.Admit}}
	r.admission = &protocol.Admission{Task: task, Native: protocol.NativeOptions{Version: 1, Provider: "new-provider", Model: protocol.Selection{Kind: "explicit", Value: "new-model"}, Effort: protocol.Selection{Kind: "explicit", Value: "new-effort"}, Permission: "future-permission", Budget: "7m", ReviewTarget: "HEAD~1", NativeTimeout: "3m", OutputSilenceTimeout: "20s"}, Brief: "requested brief"}
	owner := &controlOwner{temporary: t.TempDir()}
	call, err := r.admissionInvocation(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	flags, _, _, _ := helperArguments(call.args)
	for key, expected := range map[string]string{"provider": "new-provider", "model": "new-model", "effort": "new-effort", "permission": "future-permission", "budget": "7m", "review-target": "HEAD~1", "native-timeout": "3m", "output-silence-timeout": "20s"} {
		if flags[key] != expected {
			t.Fatalf("Native option %s changed", key)
		}
	}
	owner = &controlOwner{temporary: t.TempDir()}
	r.admission.Native = protocol.NativeOptions{Version: 1, Provider: "new-provider", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}}
	call, err = r.admissionInvocation(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	flags, _, _, _ = helperArguments(call.args)
	for _, key := range []string{"permission", "budget", "model", "effort", "review-target", "native-timeout", "output-silence-timeout"} {
		if _, present := flags[key]; present {
			t.Fatalf("omitted Native option %s acquired a Gateway default", key)
		}
	}
}

func TestFreshOperationRouteRechecksWorkspaceAtStart(t *testing.T) {
	f, store, task := newRoutedFixture(t)
	r := request{config: f.adapter.snapshot(), project: f.config.Projects[0], task: task, scoped: &scopedRequest{selection: task.Route.Selection}, command: protocol.Command{Operation: protocol.ContextInspect}}
	owner := &controlOwner{temporary: t.TempDir()}
	r, err := f.adapter.bindScopedProject(t.Context(), r, owner)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.beforeLock = func(state *WorkspaceSnapshot) { state.Workspaces[0].Enabled = false }
	store.mu.Unlock()
	if _, err = f.adapter.invoke(t.Context(), r, owner); !errors.Is(err, ErrConflict) {
		t.Fatal("revoked workspace reached fresh context inspection", err)
	}
	if len(f.calls()) != 0 {
		t.Fatal("revoked workspace started a Native process")
	}
}

func TestNativeAdmissionDoesNotVetoProviderMissingFromCatalog(t *testing.T) {
	f, store, task := newRoutedFixture(t)
	task.SpecSHA256 = ""
	admission := protocol.Admission{Task: task, Native: protocol.NativeOptions{Version: 1, Provider: "future-provider", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}}, Brief: f.state.Brief}
	r, err := f.adapter.decodeRequest(t.Context(), f.adapter.snapshot(), protocol.Command{Operation: protocol.Admit, Project: task.Origin.OperationID, Body: encoded(t, admission)})
	if err != nil {
		t.Fatal("Native intent was vetoed", err)
	}
	owner := &controlOwner{temporary: t.TempDir()}
	catalog, err := f.adapter.providerCatalog(t.Context(), r, owner)
	if err != nil || len(catalog) != 1 || catalog[0].Provider != "compiled-provider" {
		t.Fatal("fixture did not advertise an independent actual catalog", err)
	}
	call, err := r.admissionInvocation(t.Context(), owner)
	if err != nil {
		t.Fatal("actual catalog vetoed execution intent", err)
	}
	flags, _, _, _ := helperArguments(call.args)
	if flags["provider"] != "future-provider" {
		t.Fatal("Native intent was replaced by catalog metadata")
	}
	if len(store.pins) != 0 {
		t.Fatal("operation route created durable pins")
	}
}

func TestProviderModelsRequiresNativeScopeGuardUpgrade(t *testing.T) {
	f, store, task := newRoutedFixture(t)
	query := protocol.ModelQuery{Selection: task.Route.Selection, Provider: "requested-provider"}
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.ProviderModels, Root: task.Context.Root, Body: encoded(t, query)})
	assertCode(t, reply, "delegate_upgrade_required")
	for _, call := range f.calls() {
		if call.Command != "context" {
			t.Fatal("models used unguarded Native fallback")
		}
	}
	if len(store.pins) != 0 {
		t.Fatal("models saved a pin")
	}
}

func TestFreshOperationRouteRequiresNativeIntentBindingUpgrade(t *testing.T) {
	for _, operation := range []protocol.Operation{protocol.Admit, protocol.ResumeExisting} {
		t.Run(string(operation), func(t *testing.T) {
			f, store, task := newRoutedFixture(t)
			body := encoded(t, protocol.TaskControl{Task: task})
			if operation == protocol.Admit {
				task.SpecSHA256 = ""
				body = encoded(t, protocol.Admission{Task: task, Native: protocol.NativeOptions{Version: 1, Provider: "fixture", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}}, Brief: f.state.Brief})
			}
			reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: operation, Project: task.Origin.OperationID, Body: body})
			assertCode(t, reply, "delegate_upgrade_required")
			if len(f.calls()) != 0 || len(store.pins) != 0 {
				t.Fatal("new execution used legacy Native intent evidence or saved a pin")
			}
		})
	}
}

func TestNativeAdmissionRequiresExactFrozenBrief(t *testing.T) {
	f, store, task := newRoutedFixture(t)
	admission := protocol.Admission{Task: task, Native: protocol.NativeOptions{Version: 1, Provider: "fixture", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}}, Brief: "different frozen request"}
	r := request{project: f.config.Projects[0], task: task, admission: &admission}
	receipt := &cliReceipt{RootToken: r.project.RootToken, ProjectToken: r.project.ProjectToken, TaskID: task.TaskID, Origin: task.Origin, SpecSHA256: task.SpecSHA256, BriefSHA256: briefHash(f.state.Brief), ExecutionOptions: executionOptions{Provider: "fixture", Permission: "read-only", BudgetNanoseconds: f.state.Budget, Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}}, WorkspaceConstraint: &workspaceConstraint{Token: store.state.Workspaces[0].NativeContext, RelativeProject: "."}}
	response := cliResponse{TaskID: task.TaskID, Connector: &cliConnector{ContractVersion: 1, Features: f.state.Features, RootToken: r.project.RootToken, ProjectToken: r.project.ProjectToken, Receipt: receipt}}
	if !errors.Is(r.receipt(response), ErrEvidence) {
		t.Fatal("receipt accepted a different frozen brief")
	}
	receipt.BriefSHA256 = briefHash(admission.Brief)
	if err := r.receipt(response); err != nil {
		t.Fatal("matching frozen brief failed the independent receipt binding", err)
	}
}
