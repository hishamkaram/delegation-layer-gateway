package connector

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestRestoredOpenNamespaceResumesOriginalTaskWithoutCreating(t *testing.T) {
	f := newFixture(t)
	f.state.OriginGeneration = "restored-generation"
	f.writeState()
	got := observation(t, f.adapter.Execute(t.Context(), f.command(protocol.ResumeExisting)))
	if got.Task != f.task() {
		t.Fatal("restore rewrote immutable task origin")
	}
	resumes := 0
	for _, call := range f.calls() {
		if call.Command == "dispatch" {
			t.Fatal("existing recovery used new admission")
		}
		if slicesContains(call.Args, "--resume-admission") {
			resumes++
		}
	}
	if resumes != 1 {
		t.Fatalf("existing resume calls: %d", resumes)
	}
	// Creation still requires the current generation. Existing-task authority
	// cannot be reused to create a task under its older immutable origin.
	task := f.task()
	task.SpecSHA256 = ""
	request := protocol.Admission{Task: task, Provider: "fixture", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}, Permission: "read-only", BudgetSeconds: 120, Brief: f.state.Brief}
	assertCode(t, f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.Admit, Project: "project-one", Body: encoded(t, request)}), "device_not_ready")
	for _, call := range f.calls() {
		if call.Command == "dispatch" {
			t.Fatal("stale creation reached Delegate")
		}
	}
}

func TestRestoredClosedNamespaceCannotResumeOriginalTask(t *testing.T) {
	f := newFixture(t)
	f.state.OriginGeneration = "restored-generation"
	f.state.Closed = true
	f.writeState()
	assertCode(t, f.adapter.Execute(t.Context(), f.command(protocol.ResumeExisting)), "device_not_ready")
	for _, call := range f.calls() {
		if slicesContains(call.Args, "--resume-admission") {
			t.Fatal("closed root reached resume")
		}
	}
}
