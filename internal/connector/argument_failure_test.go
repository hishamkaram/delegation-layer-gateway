package connector

import (
	"os"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func helperArgumentExit(command, mode string) (int, bool) {
	if command != "dispatch" && command != "continue" && command != "resolve" {
		return 0, false
	}
	switch mode {
	case "argument-usage", "argument-output", "argument-other-exit":
		if _, err := os.Stderr.WriteString("PRIVATE-CANARY argument usage\n"); err != nil {
			return 1, true
		}
		if mode == "argument-output" {
			if _, err := os.Stdout.WriteString("PRIVATE-CANARY non-JSON output\n"); err != nil {
				return 1, true
			}
		}
		if mode == "argument-other-exit" {
			return 1, true
		}
		return 2, true
	default:
		return 0, false
	}
}

func TestNativeArgumentExitMappingIsLimitedToNewAdmission(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      string
		routed    bool
		operation protocol.Operation
		code      string
	}{
		{"new invalid input", "argument-usage", true, protocol.Admit, "invalid_request"},
		{"legacy invalid input", "argument-usage", false, protocol.Admit, "evidence_invalid"},
		{"historical control", "argument-usage", true, protocol.Resolve, "evidence_invalid"},
		{"unexpected output", "argument-output", true, protocol.Admit, "evidence_invalid"},
		{"different exit", "argument-other-exit", true, protocol.Admit, "evidence_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _, task := newRoutedFixture(t)
			f.state.Mode = test.mode
			f.writeState()
			r := argumentFailureRequest(t, f, task, test.operation, test.routed)
			owner, err := f.adapter.begin(t.Context(), r.config)
			if err != nil {
				t.Fatal(err)
			}
			reply := f.adapter.invokeReply(t.Context(), r, owner)
			if err = f.adapter.settle(owner, permit{}); err != nil {
				t.Fatal(err)
			}
			assertArgumentReply(t, reply, test.code)
			if calls := f.calls(); len(calls) != 1 {
				t.Fatal("argument exit started a fallback control")
			}
		})
	}
}

func argumentFailureRequest(t *testing.T, f *fixture, task protocol.TaskBinding, operation protocol.Operation, routed bool) request {
	t.Helper()
	if !routed {
		task.Route = protocol.TaskRoute{}
	}
	task.SpecSHA256 = ""
	r := request{config: f.adapter.snapshot(), project: f.config.Projects[0], task: task, command: protocol.Command{Operation: operation}}
	if operation == protocol.Admit {
		admission := protocol.Admission{Task: task, Brief: f.state.Brief, Native: protocol.NativeOptions{Version: 1, Provider: "fixture", Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}, Budget: "Native must validate this budget"}}
		if !routed {
			admission.Native = protocol.NativeOptions{}
			admission.Provider, admission.Permission, admission.BudgetSeconds = "fixture", "read-only", 30
			admission.Model, admission.Effort = protocol.Selection{Kind: "native_default"}, protocol.Selection{Kind: "native_default"}
		}
		if admission.Validate() != nil {
			t.Fatal("Gateway parsed Native semantics or rejected the valid transport shape")
		}
		r.admission = &admission
	}
	return r
}

func assertArgumentReply(t *testing.T, reply protocol.Reply, code string) {
	t.Helper()
	assertCode(t, reply, code)
	if code == "invalid_request" && (reply.Error.Retryable || reply.Error.Stage != "validate-request") {
		t.Fatal("invalid Native arguments lost their fixed nonretryable classification")
	}
	if len(reply.Body) != 0 || strings.Contains(string(encoded(t, reply)), "PRIVATE-CANARY") {
		t.Fatal("argument failure exposed diagnostics or fabricated task-state proof")
	}
}
