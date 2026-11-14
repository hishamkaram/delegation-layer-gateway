package connector

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestCollectRejectedOutcomeRequiresRealCollectionAndFreshProof(t *testing.T) {
	for _, failure := range []string{"", "provider_output_rejected", "task_idle_timed_out"} {
		t.Run("failure_"+failure, func(t *testing.T) {
			f := newFixture(t)
			f.state.Publication = "rejected"
			f.state.CollectExit = 4
			f.state.CollectFailure = failure
			f.state.Closure = true
			if failure == "" {
				// A pending preflight must not replace the post-collection proof.
				rejected := f.state
				f.state.Publication = ""
				f.state.AfterCollect = &rejected
			}
			f.writeState()
			reply := f.adapter.Execute(t.Context(), f.command(protocol.Collect))
			got := observation(t, reply)
			if got.Verdict != "rejected" || got.Publication != "rejected" || got.Result != nil || got.ExecutionClosure == nil {
				t.Fatalf("rejected collection lost bounded outcome/closure: %+v", got)
			}
			if strings.Contains(string(reply.Body), "PRIVATE-CANARY") {
				t.Fatal("rejected payload or diagnostic escaped")
			}
			assertCollectCallsJoined(t, f, "resolve", "collect", "resolve")
		})
	}
}

func TestCollectRejectionRefusesFreshUnhealthyOrUnboundOutcome(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*helperState)
		code   string
	}{
		{"unhealthy", func(s *helperState) { s.Mode = "passive-error" }, "pending"},
		{"missing outcome", func(s *helperState) { s.OutcomeFault = "missing" }, "evidence_invalid"},
		{"committed outcome", func(s *helperState) { s.Publication = "committed" }, "evidence_invalid"},
		{"outcome schema", func(s *helperState) { s.OutcomeFault = "schema" }, "evidence_invalid"},
		{"outcome task", func(s *helperState) { s.OutcomeFault = "task" }, "evidence_invalid"},
		{"outcome spec", func(s *helperState) { s.OutcomeFault = "spec" }, "evidence_invalid"},
		{"receipt spec", func(s *helperState) { s.ReceiptFault = "spec" }, "evidence_invalid"},
		{"origin", func(s *helperState) { s.ReceiptFault = "origin" }, "evidence_invalid"},
		{"workspace", func(s *helperState) { s.ReceiptFault = "workspace" }, "evidence_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			next := f.state
			next.Publication = "rejected"
			test.change(&next)
			f.state.CollectExit = 4
			f.state.AfterCollect = &next
			f.writeState()
			reply := f.adapter.Execute(t.Context(), f.command(protocol.Collect))
			assertCode(t, reply, test.code)
			if len(reply.Body) != 0 || strings.Contains(string(encoded(t, reply)), "PRIVATE-CANARY") {
				t.Fatal("invalid fresh evidence exposed a payload or native diagnostic")
			}
			assertCollectCallsJoined(t, f, "resolve", "collect", "resolve")
		})
	}
}

func TestCollectFaultDoesNotStartFallbackResolve(t *testing.T) {
	for _, test := range []struct {
		name string
		exit int
		mode string
		code string
	}{
		{"independent native fault", 1, "", "pending"},
		{"invoker decode fault despite exit4", 4, "unknown", "evidence_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			f.state.Publication = "rejected"
			f.state.CollectExit = test.exit
			f.state.CollectMode = test.mode
			f.writeState()
			assertCode(t, f.adapter.Execute(t.Context(), f.command(protocol.Collect)), test.code)
			assertCollectCallsJoined(t, f, "resolve", "collect")
		})
	}
}

func TestCollectPendingAndCommittedOutcomesRemainUnchanged(t *testing.T) {
	for _, publication := range []string{"", "committed"} {
		t.Run("publication_"+publication, func(t *testing.T) {
			f := newFixture(t)
			f.state.Publication = publication
			f.writeState()
			got := observation(t, f.adapter.Execute(t.Context(), f.command(protocol.Collect)))
			if publication == "committed" {
				if got.Verdict != "committed" || got.Result == nil || got.Result.SHA256 != "d0a3cafa219da8cb8657edd1ef9c6ac00d71a48f666b6ba43ad7419dd0cd204b" || got.Result.Length != 14 {
					t.Fatalf("committed result changed: %+v", got)
				}
			} else if got.Publication != "pending" || got.Verdict != "" || got.Result != nil {
				t.Fatalf("pending publication became a terminal outcome: %+v", got)
			}
			assertCollectCallsJoined(t, f, "resolve", "collect", "resolve")
		})
	}
}

func assertCollectCallsJoined(t *testing.T, f *fixture, want ...string) {
	t.Helper()
	var commands []string
	for _, call := range f.calls() {
		commands = append(commands, call.Command)
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("public CLI calls=%v want=%v", commands, want)
	}
	if status := f.adapter.Status(); status.Active != 0 || status.CleanupPending != 0 {
		t.Fatalf("collection retained unjoined control ownership: %+v", status)
	}
	if entries, err := os.ReadDir(f.config.TemporaryDirectory); err != nil || len(entries) != 0 {
		t.Fatalf("collection control paths remain after join: entries=%v err=%v", entries, err)
	}
}
