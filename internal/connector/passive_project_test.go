package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func passiveProjectCommand(t *testing.T, f *fixture, operation protocol.Operation) protocol.Command {
	t.Helper()
	switch operation {
	case protocol.Cancel:
		return protocol.Command{Operation: operation, Project: "project-one", Body: encoded(t, protocol.Cancellation{Task: f.task(), CancellationID: strings.Repeat("2", 32)})}
	case protocol.ResultChunk:
		return protocol.Command{Operation: operation, Project: "project-one", Body: encoded(t, protocol.RangeRequest{Task: f.task(), Descriptor: protocol.Descriptor{SHA256: helperHash("accepted result"), Length: int64(len("accepted result"))}, Limit: 65536})}
	case protocol.Admit, protocol.ContextInspect, protocol.ResumeExisting, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen, protocol.Resolve, protocol.FenceAbsent, protocol.Status, protocol.Collect:
		return f.command(operation)
	default:
		t.Fatal("unknown test operation")
		return protocol.Command{}
	}
}

func TestExistingTaskControlsSurviveMissingProject(t *testing.T) {
	for _, operation := range []protocol.Operation{protocol.Resolve, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel, protocol.FenceAbsent} {
		t.Run(string(operation), func(t *testing.T) {
			f := newFixture(t)
			if err := os.Remove(f.config.Projects[0].Directory); err != nil {
				t.Fatal(err)
			}
			reply := f.adapter.Execute(t.Context(), passiveProjectCommand(t, f, operation))
			if reply.Error != nil {
				t.Fatalf("frozen task control requires removed live project: %s", reply.Error.Code)
			}
			for _, call := range f.calls() {
				if call.Command == "context" {
					t.Fatal("task control required live context inspection")
				}
			}
		})
	}
}

func TestRetainedMissingProjectConfigurationIsNotExecutionReady(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(f.config.Projects[0].Directory); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter(f.config, time.Now)
	if err != nil {
		t.Fatalf("retained pins rejected because project was removed: %v", err)
	}
	report := adapter.Probe(t.Context())
	if len(report.Projects) != 1 || report.Projects[0].Ready || adapter.Status().Ready {
		t.Fatal("missing project was advertised execution-ready")
	}
	if reply := adapter.Execute(t.Context(), f.command(protocol.ResumeExisting)); reply.Error == nil {
		t.Fatal("missing project allowed resume")
	}
	task := f.task()
	task.SpecSHA256 = ""
	admission := protocol.Admission{Task: task, Provider: "fixture", Permission: "read-only", BudgetSeconds: 120, Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}, Brief: f.state.Brief}
	if reply := adapter.Execute(t.Context(), protocol.Command{Operation: protocol.Admit, Project: "project-one", Body: encoded(t, admission)}); reply.Error == nil {
		t.Fatal("missing project allowed admission")
	}
	assertNoNewExecution(t, f.calls())
}

func TestReplacedProjectRetainsFrozenControlsAndDeniesExecution(t *testing.T) {
	f := newFixture(t)
	path := f.config.Projects[0].Directory
	if err := os.Rename(path, path+"-original"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path + "-original"); err != nil {
			t.Error(err)
		}
	})
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	f.state.LiveProjectMismatch = true
	f.writeState()
	if reply := f.adapter.Execute(t.Context(), f.command(protocol.Status)); reply.Error != nil {
		t.Fatalf("frozen control followed replacement directory: %s", reply.Error.Code)
	}
	if reply := f.adapter.Execute(t.Context(), f.command(protocol.ResumeExisting)); reply.Error == nil {
		t.Fatal("replacement project allowed resume")
	}
	task := f.task()
	task.SpecSHA256 = ""
	admission := protocol.Admission{Task: task, Provider: "fixture", Permission: "read-only", BudgetSeconds: 120, Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}, Brief: f.state.Brief}
	if reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.Admit, Project: "project-one", Body: encoded(t, admission)}); reply.Error == nil {
		t.Fatal("replacement project allowed admission")
	}
	report := f.adapter.Probe(t.Context())
	if report.Projects[0].Ready {
		t.Fatal("replacement project automatically repinned")
	}
	assertNoNewExecution(t, f.calls())
}

func TestPassiveReceiptMismatchBlocksOtherNativeControls(t *testing.T) {
	for _, fault := range []string{"root-header", "root", "project", "origin", "spec", "feature"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.state.ReceiptFault = fault
			f.writeState()
			reply := f.adapter.Execute(t.Context(), f.command(protocol.Status))
			if reply.Error == nil {
				t.Fatal("mismatching frozen identity accepted")
			}
			for _, call := range f.calls() {
				if call.Command == "status" {
					t.Fatal("native status started before verified frozen receipt")
				}
			}
		})
	}
}

func TestPassiveControlUsesOwnedCWDAndScrubsAmbientRoot(t *testing.T) {
	f := newFixture(t)
	t.Setenv("DELEGATE_ROOT", "ambient-root-PRIVATE-CANARY")
	t.Setenv("PWD", "ambient-project-PRIVATE-CANARY")
	if reply := f.adapter.Execute(t.Context(), f.command(protocol.Status)); reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	for _, call := range f.calls() {
		if filepath.Dir(call.Directory) != f.config.TemporaryDirectory || call.Directory == f.config.Projects[0].Root {
			t.Fatal("CLI cwd not connector-owned")
		}
		if call.DelegateRootEnvironment != "" || call.PWDEnvironment != call.Directory {
			t.Fatal("ambient root/project environment changed invocation authority")
		}
	}
}

func TestAbsentResolutionDoesNotAttestProjectOrReadiness(t *testing.T) {
	f := newFixture(t)
	f.state.Absent = true
	f.writeState()
	got := observation(t, f.adapter.Execute(t.Context(), f.command(protocol.Resolve)))
	if got.Resolution != "absent" || f.adapter.Status().Ready {
		t.Fatal("absent echo promoted execution readiness")
	}
	before := len(f.calls())
	reply := f.adapter.Execute(t.Context(), f.command(protocol.Status))
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	for _, call := range f.calls()[before:] {
		if call.Command != "resolve" {
			t.Fatal("absent project echo authorized another control")
		}
	}
}

func TestPartialPreparationVerifiesRootBeforeGuardedFence(t *testing.T) {
	f := newFixture(t)
	f.state.Partial = true
	f.writeState()
	result := observation(t, f.adapter.Execute(t.Context(), f.command(protocol.FenceAbsent)))
	if result.Resolution != "permanently_refused" {
		t.Fatal("partial preparation did not reach native refusal proof")
	}
	calls := f.calls()
	if len(calls) != 3 || calls[0].Command != "resolve" || calls[1].Command != "context" || calls[2].Command != "resolve" {
		t.Fatal("partial preparation did not verify root before guarded native fence")
	}
	flags, _, _, _ := helperArguments(calls[2].Args)
	if flags["fence-if-absent"] != "true" || flags["expected-root"] != f.config.Projects[0].RootToken || flags["expected-project"] != f.config.Projects[0].ProjectToken || flags["expected-spec-sha256"] != f.task().SpecSHA256 || calls[2].OriginMode != 0o600 {
		t.Fatal("partial fence lost immutable guards")
	}
}

func assertNoNewExecution(t *testing.T, calls []helperCall) {
	t.Helper()
	for _, call := range calls {
		if call.Command == "dispatch" || slicesContains(call.Args, "--resume-admission") {
			t.Fatal("forbidden admission/resume process started")
		}
	}
}

func TestRootOnlyInspectionDoesNotPromoteOrRefreshProjectEvidence(t *testing.T) {
	f := newFixture(t)
	before := f.adapter.Probe(t.Context())
	if !before.Projects[0].Ready {
		t.Fatal("fixture did not establish live project observation")
	}
	f.adapter.invalidateRootReadiness(f.adapter.Generation(), f.config.Projects[0].RootToken)
	f.clock.advance(time.Second)
	command := protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: encoded(t, protocol.InspectRequest{GatewayID: "gateway-one", RootOnly: true})}
	reply := f.adapter.Execute(t.Context(), command)
	if reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	var report protocol.RootCapability
	if err := protocol.DecodeStrict(reply.Body, &report, protocol.MaxFrameBytes); err != nil || report.Validate() != nil {
		t.Fatal("invalid root-only proof")
	}
	after := f.adapter.Capabilities()
	if after.Projects[0].Ready || f.adapter.Status().Ready || !after.ObservedAt.Equal(before.ObservedAt) {
		t.Fatal("root proof promoted or refreshed project/provider evidence")
	}
	if strings.Contains(string(reply.Body), "project") || strings.Contains(string(reply.Body), f.config.Projects[0].RootToken) {
		t.Fatal("root proof invented project attestation or leaked raw root token")
	}
}

func TestRootNamespaceControlsWorkWithAllProjectsRemoved(t *testing.T) {
	f := newFixture(t)
	before := f.adapter.Probe(t.Context())
	if err := os.Remove(f.config.Projects[0].Directory); err != nil {
		t.Fatal(err)
	}
	root := f.task().Context.Root
	for _, command := range []protocol.Command{
		{Operation: protocol.OriginBarrier, Project: "project-one", Body: encoded(t, protocol.OriginBarrierRequest{GatewayID: "gateway-one", RecoveryID: "recovery-new", ExpectedGeneration: "origin-one", Generation: "generation-new", ExpectedRoot: root})},
		{Operation: protocol.OriginInventory, Project: "project-one", Body: encoded(t, protocol.OriginInventoryRequest{GatewayID: "gateway-one", Generation: "generation-new", Limit: 100, ExpectedRoot: root})},
		{Operation: protocol.OriginReopen, Project: "project-one", Body: encoded(t, protocol.OriginReopenRequest{GatewayID: "gateway-one", RecoveryID: "recovery-new", Generation: "generation-new", CompletenessReceipt: strings.Repeat("f", 64), ExpectedRoot: root})},
	} {
		if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
			t.Fatalf("root-wide %s required a live project: %s", command.Operation, reply.Error.Code)
		}
		cached := f.adapter.Capabilities()
		if cached.Projects[0].Ready || !cached.ObservedAt.Equal(before.ObservedAt) {
			t.Fatal("namespace transition promoted readiness or fabricated provider freshness")
		}
	}
	calls := f.calls()
	// The one earlier full project probe is separate from these root-only proofs.
	for _, call := range calls[1:] {
		if call.Command == "context" && slicesContains(call.Args, "--cwd") {
			t.Fatal("namespace proof accessed the deleted live project")
		}
	}
}

func TestRootNamespaceRequiresGenuineCurrentRootProof(t *testing.T) {
	f := newFixture(t)
	f.state.ReceiptFault = "root-header"
	f.writeState()
	command := protocol.Command{Operation: protocol.OriginBarrier, Project: "project-one", Body: encoded(t, protocol.OriginBarrierRequest{GatewayID: "gateway-one", RecoveryID: "recovery-new", Generation: "generation-new", ExpectedRoot: f.task().Context.Root})}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error == nil {
		t.Fatal("root replacement authorized namespace mutation")
	}
	for _, call := range f.calls() {
		if call.Command == "origin" {
			t.Fatal("namespace mutation started after wrong root proof")
		}
	}
}

func TestStatusLearnsSpecBeforeNativeControl(t *testing.T) {
	f := newFixture(t)
	task := f.task()
	task.SpecSHA256 = ""
	command := protocol.Command{Operation: protocol.Status, Project: "project-one", Body: encoded(t, protocol.TaskControl{Task: task})}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	for _, call := range f.calls() {
		if call.Command == "status" {
			flags, _, _, _ := helperArguments(call.Args)
			if flags["expected-spec-sha256"] != f.task().SpecSHA256 {
				t.Fatal("native status did not retain learned canonical spec")
			}
		}
	}
}
