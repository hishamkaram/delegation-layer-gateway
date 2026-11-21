package connector

import (
	"os"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestRoute1CanonicalReceiptRequestsSavedWorkspaceProjection(t *testing.T) {
	for _, operation := range []protocol.Operation{protocol.Admit, protocol.Continue, protocol.Status, protocol.ResumeExisting} {
		t.Run(string(operation), func(t *testing.T) {
			f, command := savedWorkspaceProjectionFixture(t, operation)
			if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
				t.Fatalf("valid saved workspace receipt was hidden by Native's default projection: %s", reply.Error.Code)
			}
			assertSavedWorkspaceProjectionCalls(t, f.calls())
			assertNativeFeaturesSettled(t, f)
		})
	}
}

func savedWorkspaceProjectionFixture(t *testing.T, operation protocol.Operation) (*fixture, protocol.Command) {
	t.Helper()
	if operation == protocol.Continue {
		f, _, continuation := compactContinuationFixture(t, false, "")
		return f, protocol.Command{Operation: operation, Project: continuation.Task.Origin.OperationID, Body: encoded(t, continuation)}
	}
	f, store, admission := compactAdmissionFixture(t)
	task, body := admission.Task, encoded(t, admission)
	if operation != protocol.Admit {
		task.SpecSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		body = encoded(t, protocol.TaskControl{Task: task})
		store.mu.Lock()
		store.state.Workspaces = nil
		store.mu.Unlock()
		if err := os.Remove(f.config.Projects[0].Directory); err != nil {
			t.Fatal(err)
		}
	}
	return f, protocol.Command{Operation: operation, Project: task.Origin.OperationID, Body: body}
}

func assertSavedWorkspaceProjectionCalls(t *testing.T, calls []helperCall) {
	t.Helper()
	for _, call := range calls {
		if call.Command == "context" {
			continue
		}
		flags, _, _, _ := helperArguments(call.Args)
		if flags["include-workspace-constraint"] != "true" {
			t.Fatal("Route1 receipt validation relied on an unrequested workspace projection")
		}
		if call.Command == "continue" && flags["expected-workspace"] != "" {
			t.Fatal("continuation replaced Native's inherited workspace context")
		}
	}
}

func TestOwnedCLIFixtureRequiresExplicitWorkspaceProjection(t *testing.T) {
	state := helperState{FrozenWorkspaceToken: "saved-workspace", FrozenRelativePath: "nested"}
	flags := map[string]string{"expected-origin": "saved-origin.json"}
	projected := map[string]any{}
	helperAttachFrozenWorkspace(flags, state, projected)
	if _, present := projected["workspace_constraint"]; present {
		t.Fatal("fixture exposed a saved workspace that Native omits by default")
	}
	flags["include-workspace-constraint"] = "true"
	helperAttachFrozenWorkspace(flags, state, projected)
	if _, present := projected["workspace_constraint"]; !present {
		t.Fatal("fixture omitted the explicitly requested saved workspace")
	}
}

func TestRoute1HeaderOmissionDoesNotReplaceCanonicalProjectProof(t *testing.T) {
	for _, resolution := range []string{"absent", "permanently_refused"} {
		t.Run(resolution, func(t *testing.T) {
			f, _, task := newRoutedFixture(t)
			r := request{config: f.adapter.snapshot(), project: f.config.Projects[0], task: task}
			response := cliResponse{TaskID: task.TaskID, Connector: &cliConnector{ContractVersion: 1, Features: f.state.Features, RootToken: r.project.RootToken, Resolution: resolution}}
			if err := r.receipt(response); err != nil {
				t.Fatal("taskless root/task proof required a project header", err)
			}
			response.Connector.Resolution = "existing"
			if err := r.receipt(response); err == nil {
				t.Fatal("missing project header authorized an existing task without its canonical receipt")
			}
			response.Connector.Resolution = resolution
			response.Connector.ProjectToken = "conflicting-project-header"
			if err := r.receipt(response); err == nil {
				t.Fatal("present conflicting project header was accepted")
			}
		})
	}
}
