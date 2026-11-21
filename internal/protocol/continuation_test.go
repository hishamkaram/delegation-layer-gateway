package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func continuationExample() Continuation {
	predecessor := taskBinding()
	predecessor.SpecSHA256 = strings.Repeat("a", 64)
	predecessor.Route = TaskRoute{Version: 1, Selection: FileSelection{ScopeID: "workspace", RelativePath: "project"}, WorkspaceGuard: WireContextGuard("workspace"), GuardFormat: FeatureProjectHashGuard}
	successor := predecessor
	successor.SpecSHA256 = ""
	successor.TaskID = strings.Repeat("f", 32)
	successor.Origin.OperationID = "successor"
	successor.Origin.Binding = "opaque-successor-binding"
	return Continuation{Task: successor, Predecessor: predecessor, Overrides: ContinuationOverrides{Version: 1}}
}

func TestContinuationWirePreservesOmissionAndNativeOverrides(t *testing.T) {
	value := continuationExample()
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(value, MaxFrameBytes)
	if err != nil || bytes.Contains(encoded, []byte(`"brief":`)) || !bytes.Contains(encoded, []byte(`"brief_present":false`)) || !bytes.Contains(encoded, []byte(`"overrides":{"version":1}`)) {
		t.Fatalf("continuation invented inherited values: %s, %v", encoded, err)
	}
	value.BriefPresent, value.Brief = true, "exact follow-up\n"
	value.SelectionExplicit = true
	value.Overrides = ContinuationOverrides{Version: 1, Budget: "future-native-budget", Model: "future-model", Effort: "future-effort", OutputSilenceTimeout: "0"}
	encoded, err = Encode(value, MaxFrameBytes)
	var decoded Continuation
	if err != nil || DecodeStrict(encoded, &decoded, MaxFrameBytes) != nil || decoded != value || decoded.Validate() != nil {
		t.Fatalf("continuation altered literal Native intent: %v", err)
	}
	command := Command{Operation: Continue, Project: value.Task.Origin.OperationID, Body: encoded}
	if command.ValidateVersion(WireVersion2) != nil || command.ValidateVersion(Version) == nil || Continue.AllowedRecoveryOnly() || !Continue.ScanConsumer() || Continue.ProtectedControl() {
		t.Fatal("continuation escaped its ordinary v2-only fresh-admission boundary")
	}
}

func TestContinuationRejectsRetargetedOrIncompleteBinding(t *testing.T) {
	for name, mutate := range map[string]func(*Continuation){
		"same task":                func(c *Continuation) { c.Task.TaskID = c.Predecessor.TaskID },
		"same operation":           func(c *Continuation) { c.Task.Origin.OperationID = c.Predecessor.Origin.OperationID },
		"different root":           func(c *Continuation) { c.Task.Context.Root = WireContextGuard("another-root") },
		"different project":        func(c *Continuation) { c.Task.Context.Project = WireContextGuard("another-project") },
		"different workspace":      func(c *Continuation) { c.Task.Route.WorkspaceGuard = WireContextGuard("another-workspace") },
		"different gateway":        func(c *Continuation) { c.Task.Origin.GatewayID = "another-gateway" },
		"different owner":          func(c *Continuation) { c.Task.Origin.PrincipalRef = "another-owner" },
		"missing predecessor spec": func(c *Continuation) { c.Predecessor.SpecSHA256 = "" },
		"missing compact origin":   func(c *Continuation) { c.Task.Origin.Binding = "" },
		"unrequested brief":        func(c *Continuation) { c.Brief = "unrequested" },
		"empty explicit brief":     func(c *Continuation) { c.BriefPresent = true },
		"nul option":               func(c *Continuation) { c.Overrides.Model = "bad\x00model" },
	} {
		t.Run(name, func(t *testing.T) {
			value := continuationExample()
			mutate(&value)
			if value.Validate() == nil {
				t.Fatal("invalid continuation was accepted")
			}
		})
	}
}
