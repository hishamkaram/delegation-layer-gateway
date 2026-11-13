package connector

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestActiveOwnerCancellationDoesNotRequireRefusalExclusion(t *testing.T) {
	for _, knownSpec := range []bool{true, false} {
		name := "unknown-spec"
		if knownSpec {
			name = "known-spec"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			exhaustOrdinaryCancellationCapacity(t, f)
			f.state.LiveOwner = true
			f.writeState()
			task := f.task()
			if !knownSpec {
				task.SpecSHA256 = ""
			}
			fence := protocol.Command{Operation: protocol.FenceAbsent, Project: "project-one", Body: encoded(t, protocol.TaskControl{Task: task})}
			resolved := observation(t, f.adapter.Execute(t.Context(), fence))
			if resolved.Resolution != "existing" || resolved.Task.SpecSHA256 != f.task().SpecSHA256 || resolved.ExecutionClosure != nil || resolved.ExecutionClosurePending != "owner_busy" {
				t.Fatal("active existing task did not supply matching receipt without closure")
			}
			cancel := protocol.Command{Operation: protocol.Cancel, Project: "project-one", Body: encoded(t, protocol.Cancellation{Task: task, CancellationID: strings.Repeat("2", 32)})}
			stopped := observation(t, f.adapter.Execute(t.Context(), cancel))
			assertStopAcknowledgementWithoutClosure(t, stopped)
			assertActiveCancellationCalls(t, f)
			f.state.Closure = true
			f.writeState()
			closed := observation(t, f.adapter.Execute(t.Context(), cancel))
			if closed.ExecutionClosure == nil || closed.ExecutionClosure.ReferenceSHA256 != strings.Repeat("d", 64) {
				t.Fatal("genuine configured canonical closure was lost")
			}
		})
	}
}

func TestPartialProbeNeverLearnsPoisonedReceipt(t *testing.T) {
	f := newFixture(t)
	if err := os.RemoveAll(f.config.Projects[0].Directory); err != nil {
		t.Fatal(err)
	}
	f.state.Partial, f.state.ProbeFault = true, "receipt"
	f.writeState()
	task := f.task()
	task.SpecSHA256 = ""
	command := protocol.Command{Operation: protocol.FenceAbsent, Project: "project-one", Body: encoded(t, protocol.TaskControl{Task: task})}
	result := observation(t, f.adapter.Execute(t.Context(), command))
	if result.Resolution != "permanently_refused" || result.Task != task || result.ExecutionClosure != nil {
		t.Fatal("partial receipt became identity or closure evidence")
	}
	calls := f.calls()
	if len(calls) != 3 {
		t.Fatal("partial probe did not reach independently guarded fence")
	}
	if calls[1].Command != "context" {
		t.Fatal("partial fallback did not inspect root before fencing")
	}
	for _, call := range calls {
		if slicesContains(call.Args, "--cwd") {
			t.Fatal("historical partial fencing accessed the removed project")
		}
	}
	assertOriginalPartialFenceGuards(t, f, calls[2], task)
}

func TestPartialFenceRequiresSuccessfulCompatibleRootInspection(t *testing.T) {
	for _, fault := range []string{"old-features", "failed", "busy", "failure", "root", "project"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.state.Partial = true
			switch fault {
			case "old-features":
				f.state.Features = []string{"namespace-admission-v1"}
			case "root":
				f.state.ReceiptFault = "root-header"
			default:
				f.state.ContextFault = fault
			}
			f.writeState()
			if reply := f.adapter.Execute(t.Context(), f.command(protocol.FenceAbsent)); reply.Error == nil {
				t.Error("invalid root inspection authorized partial fence")
			}
			calls := f.calls()
			if len(calls) != 2 || calls[0].Command != "resolve" || calls[1].Command != "context" {
				t.Fatalf("expected passive lookup and root inspection only, got %+v", calls)
			}
			for _, call := range calls {
				if slicesContains(call.Args, "--fence-if-absent") || slicesContains(call.Args, "--cwd") {
					t.Error("invalid root inspection reached fence or project path")
				}
			}
		})
	}
}

func TestAbsentResolveWithOldFeaturesNeverFences(t *testing.T) {
	f := newFixture(t)
	f.state.Absent = true
	f.state.Features = []string{"namespace-admission-v1"}
	f.writeState()
	assertCode(t, f.adapter.Execute(t.Context(), f.command(protocol.FenceAbsent)), "evidence_invalid")
	calls := f.calls()
	if len(calls) != 1 || calls[0].Command != "resolve" || slicesContains(calls[0].Args, "--fence-if-absent") {
		t.Fatal("unsupported absent proof reached mutation")
	}
}

func TestPartialProbeNearMissesNeverFence(t *testing.T) {
	for _, fault := range []string{"error", "failure", "task", "contract", "exit"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.state.Partial, f.state.ProbeFault = true, fault
			f.writeState()
			if reply := f.adapter.Execute(t.Context(), f.command(protocol.FenceAbsent)); reply.Error == nil {
				t.Fatal("nonmatching partial envelope accepted")
			}
			calls := f.calls()
			if len(calls) != 1 || slicesContains(calls[0].Args, "--fence-if-absent") {
				t.Fatal("invalid partial probe triggered native fence")
			}
		})
	}
}

func TestPassiveAndFencedRefusalProduceSameObservation(t *testing.T) {
	f := newFixture(t)
	f.state.Absent = true
	f.writeState()
	fenced := observation(t, f.adapter.Execute(t.Context(), f.command(protocol.FenceAbsent)))
	f.state.Absent, f.state.Refused = false, true
	f.writeState()
	before := len(f.calls())
	passive := observation(t, f.adapter.Execute(t.Context(), f.command(protocol.FenceAbsent)))
	if !reflect.DeepEqual(passive, fenced) || len(f.calls()) != before+1 {
		t.Fatal("durable passive refusal differed from independently fenced refusal")
	}
}

func assertActiveCancellationCalls(t *testing.T, f *fixture) {
	t.Helper()
	cancels := 0
	for _, call := range f.calls() {
		flags, command, task, _ := helperArguments(call.Args)
		if flags["fence-if-absent"] != "" || command != "resolve" && command != "cancel" {
			t.Fatal("complete active task required native refusal or unrelated control")
		}
		if task != f.task().TaskID || flags["expected-root"] != f.config.Projects[0].RootToken || flags["expected-project"] != f.config.Projects[0].ProjectToken || call.OriginMode != 0o600 || call.ExpectedOrigin != f.task().Origin {
			t.Fatal("control lost original task or frozen guards")
		}
		if command == "cancel" {
			cancels++
			if flags["id"] != strings.Repeat("2", 32) || flags["expected-spec-sha256"] != f.task().SpecSHA256 {
				t.Fatal("cancel lost stable ID or validated native spec")
			}
		}
	}
	if cancels != 1 {
		t.Fatal("stop request did not reach native cancellation exactly once")
	}
}

func TestCancellationLookupFailuresNeverFenceOrCancel(t *testing.T) {
	for _, operation := range []protocol.Operation{protocol.FenceAbsent, protocol.Cancel} {
		for _, fault := range []string{"root-header", "root", "project", "origin", "spec", "feature", "liveness", "passive-error", "unknown"} {
			t.Run(string(operation)+"/"+fault, func(t *testing.T) {
				f := newFixture(t)
				if fault == "passive-error" || fault == "unknown" {
					f.state.Mode = fault
				} else {
					f.state.ReceiptFault = fault
				}
				f.writeState()
				assertLookupRejectedWithoutMutation(t, f, operation)
			})
		}
	}
}

func exhaustOrdinaryCancellationCapacity(t *testing.T, f *fixture) {
	t.Helper()
	for range 4 {
		held, err := f.adapter.limits.acquire(protocol.ContextInspect)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(held.release)
	}
	assertCode(t, f.adapter.Execute(t.Context(), f.command(protocol.Resolve)), "resource_limit")
}

func assertStopAcknowledgementWithoutClosure(t *testing.T, stopped protocol.TaskObservation) {
	t.Helper()
	if stopped.Stop == nil || !stopped.Stop.Requested || stopped.Stop.RequestID != strings.Repeat("2", 32) || stopped.Stop.Terminated || stopped.ExecutionClosure != nil || stopped.ExecutionClosurePending != "owner_busy" {
		t.Fatal("stop acknowledgement fabricated native closure")
	}
}

func assertLookupRejectedWithoutMutation(t *testing.T, f *fixture, operation protocol.Operation) {
	t.Helper()
	if reply := f.adapter.Execute(t.Context(), passiveProjectCommand(t, f, operation)); reply.Error == nil {
		t.Fatal("invalid passive lookup accepted")
	}
	for _, call := range f.calls() {
		flags, command, _, _ := helperArguments(call.Args)
		if command != "resolve" || flags["fence-if-absent"] != "" {
			t.Fatal("lookup failure caused native fence or cancellation")
		}
	}
}

func TestCancellationDoesNotMutateAbsentOrPartialTasks(t *testing.T) {
	for _, state := range []string{"absent", "partial"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			f.state.Absent, f.state.Partial = state == "absent", state == "partial"
			f.writeState()
			assertLookupRejectedWithoutMutation(t, f, protocol.Cancel)
		})
	}
}

func TestCancellationRejectsStopReceiptForWrongOrMissingNativeTask(t *testing.T) {
	for _, fault := range []string{"wrong", "missing"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.state.LiveOwner, f.state.CancelTaskFault = true, fault
			f.writeState()
			reply := f.adapter.Execute(t.Context(), passiveProjectCommand(t, f, protocol.Cancel))
			if reply.Error == nil {
				result := observation(t, reply)
				t.Fatalf("foreign native stop accepted: stop=%+v canonical_closure=%v pending=%s", result.Stop, result.ExecutionClosure, result.ExecutionClosurePending)
			}
			assertCode(t, reply, "evidence_invalid")
		})
	}
}

func TestCancellationRejectsStopReceiptForWrongOrMissingNativeRoot(t *testing.T) {
	for _, fault := range []string{"wrong", "missing"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.state.LiveOwner, f.state.CancelRootFault = true, fault
			f.writeState()
			reply := f.adapter.Execute(t.Context(), passiveProjectCommand(t, f, protocol.Cancel))
			if reply.Error == nil {
				result := observation(t, reply)
				t.Fatalf("foreign root stop accepted: task=%s stop=%+v canonical_closure=%v pending=%s", result.Task.TaskID, result.Stop, result.ExecutionClosure, result.ExecutionClosurePending)
			}
			assertCode(t, reply, "evidence_invalid")
		})
	}
}

func assertOriginalPartialFenceGuards(t *testing.T, f *fixture, call helperCall, task protocol.TaskBinding) {
	t.Helper()
	flags, commandName, taskID, _ := helperArguments(call.Args)
	if commandName != "resolve" || flags["fence-if-absent"] != "true" || flags["expected-spec-sha256"] != "" || taskID != task.TaskID || flags["expected-root"] != f.config.Projects[0].RootToken || flags["expected-project"] != f.config.Projects[0].ProjectToken || call.ExpectedOrigin != task.Origin {
		t.Fatal("partial probe changed original fence guards")
	}
}
