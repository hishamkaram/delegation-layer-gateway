package connector

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func compactAdmissionFixture(t *testing.T, budgets ...string) (*fixture, *workspaceTestStore, protocol.Admission) {
	t.Helper()
	f, store, task := newRoutedFixture(t)
	f.state.Features = append(f.state.Features, protocol.FeatureOriginBinding, protocol.FeatureGuardedContinuation)
	f.writeState()
	task.SpecSHA256 = ""
	var budget string
	if len(budgets) > 0 {
		budget = budgets[0]
	}
	native := protocol.NativeOptions{Version: 1, Provider: "fixture", Budget: budget, Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "native_default"}}
	request := domain.FrozenRequest{Native: domain.NativeOptions{Version: 1, Provider: "fixture", Budget: budget, Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}}, Brief: f.state.Brief, BriefPresent: true}
	c := domain.Correlation{RequestVersion: domain.CompactRequestVersion, Kind: domain.RequestKindDispatch, Operation: domain.OperationID(task.Origin.OperationID), Task: domain.TaskID(task.TaskID), Gateway: "gateway-one", AdmissionGeneration: domain.AdmissionGeneration(task.Origin.AdmissionGeneration), Owner: domain.OperationOwner{Kind: domain.Owned, Principal: "principal-one"}, Destination: domain.Destination{Device: "device-one", Project: domain.ProjectAlias(task.Origin.OperationID)}, Context: domain.ContextBinding{Root: domain.RootGuard(task.Context.Root), Project: domain.ProjectGuard(task.Context.Project)}, BriefPresent: true, BriefDigest: domain.Hash([]byte(request.Brief)), Route: domain.OperationRoute{Version: 1, RequestID: domain.RequestID(strings.Repeat("f", 32)), InputFormat: domain.DispatchInputV1, ScopeID: task.Route.Selection.ScopeID, RelativePath: task.Route.Selection.RelativePath, WorkspaceGuard: task.Route.WorkspaceGuard}}
	input, err := domain.DispatchInputDigestV1(c.Destination.Device, domain.RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}, request.Options(), c.BriefDigest)
	if err != nil {
		t.Fatal(err)
	}
	c.Route.InputDigest = input
	task.Origin = compactTestOrigin(t, c, request)
	return f, store, protocol.Admission{Task: task, Native: native, Brief: request.Brief}
}

func compactTestOrigin(t *testing.T, c domain.Correlation, request domain.FrozenRequest) protocol.Origin {
	t.Helper()
	digest, err := domain.RequestDigest(c, request)
	if err != nil {
		t.Fatal(err)
	}
	c.RequestDigest = digest
	origin, err := protocol.OriginFromCorrelation(c)
	if err != nil {
		t.Fatal(err)
	}
	return origin
}

func compactContinuationFixture(t *testing.T, explicit bool, brief string) (*fixture, *workspaceTestStore, protocol.Continuation) {
	t.Helper()
	f, store, admission := compactAdmissionFixture(t)
	prior := admission.Task
	prior.SpecSHA256 = strings.Repeat("c", 64)
	c, err := domain.ParseOriginBinding(prior.Origin.Binding)
	if err != nil {
		t.Fatal(err)
	}
	predecessor := domain.ContinuationPredecessor{Operation: c.Operation, Task: c.Task, SpecDigest: compactTestDigest(t, prior.SpecSHA256), RequestDigest: c.RequestDigest}
	c.Operation, c.Task, c.Destination.Project = "successor-operation", domain.TaskID(strings.Repeat("2", 32)), "successor-operation"
	c.Kind, c.Predecessor, c.BriefPresent, c.BriefDigest = domain.RequestKindContinuation, predecessor, brief != "", domain.Digest{}
	c.Route.RequestID, c.Route.InputFormat = domain.RequestID(strings.Repeat("e", 32)), domain.ContinuationInputV1
	if brief != "" {
		c.BriefDigest = domain.Hash([]byte(brief))
	}
	overrides := domain.ContinuationOverrides{Version: 1, Budget: "7m", Model: "requested-model", Effort: "requested-effort", OutputSilenceTimeout: "0"}
	selection := domain.RequestSelector{}
	if explicit {
		selection = domain.RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}
	}
	c.Route.InputDigest, err = domain.ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, selection, explicit, overrides, c.BriefPresent, c.BriefDigest)
	if err != nil {
		t.Fatal(err)
	}
	origin := compactTestOrigin(t, c, domain.FrozenRequest{Continuation: overrides, Brief: brief, BriefPresent: c.BriefPresent, SelectionExplicit: explicit})
	successor := prior
	successor.TaskID, successor.SpecSHA256, successor.Origin = string(c.Task), "", origin
	value := protocol.Continuation{Task: successor, Predecessor: prior, SelectionExplicit: explicit, BriefPresent: brief != "", Brief: brief, Overrides: protocol.ContinuationOverrides{Version: 1, Budget: overrides.Budget, Model: overrides.Model, Effort: overrides.Effort, OutputSilenceTimeout: overrides.OutputSilenceTimeout}}
	if value.Validate() != nil {
		t.Fatal("invalid continuation fixture")
	}
	return f, store, value
}

func compactTestDigest(t *testing.T, value string) domain.Digest {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil || len(data) != 32 {
		t.Fatal("invalid test digest")
	}
	var result domain.Digest
	copy(result[:], data)
	return result
}

func TestCompactAdmissionRejectsChangedRequestedIntentBeforeNative(t *testing.T) {
	f, _, admission := compactAdmissionFixture(t)
	admission.Native.Model = protocol.Selection{Kind: "explicit", Value: "uncommitted model"}
	command := protocol.Command{Operation: protocol.Admit, Project: admission.Task.Origin.OperationID, Body: encoded(t, admission)}
	if _, err := f.adapter.decodeRequest(t.Context(), f.adapter.snapshot(), command); err == nil {
		t.Fatal("compact Origin accepted a different requested execution intent")
	}
	if len(f.calls()) != 0 {
		t.Fatal("invalid requested intent started Native")
	}
}

func TestCompactAdmissionUsesNativePublicCLI(t *testing.T) {
	f, _, admission := compactAdmissionFixture(t)
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.Admit, Project: admission.Task.Origin.OperationID, Body: encoded(t, admission)})
	if reply.Error != nil {
		t.Fatalf("valid compact admission did not reach Native: %s", reply.Error.Code)
	}
	if result := observation(t, reply); result.Task.Origin != admission.Task.Origin || result.Task.TaskID != admission.Task.TaskID {
		t.Fatal("compact receipt changed immutable task/Origin")
	}
	assertNativeFeaturesSettled(t, f)
}

func TestCompactContinuationUsesGuardedNativeCommand(t *testing.T) {
	f, _, value := compactContinuationFixture(t, false, "")
	command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
	reply := f.adapter.Execute(t.Context(), command)
	if reply.Error != nil {
		t.Fatalf("typed continuation did not reach Native: %s", reply.Error.Code)
	}
	continued := 0
	for _, call := range f.calls() {
		if call.Command == "dispatch" {
			t.Fatal("continuation fell back to fresh dispatch")
		}
		if call.Command != "continue" {
			continue
		}
		continued++
		assertContinuationCall(t, call, value)
	}
	if continued != 1 {
		t.Fatalf("Native continuation calls=%d, want 1", continued)
	}
	if result := observation(t, reply); result.Task.Origin != value.Task.Origin || result.Task.TaskID != value.Task.TaskID {
		t.Fatal("continuation reply used predecessor correlation")
	}
	assertNativeFeaturesSettled(t, f)
}

func assertContinuationCall(t *testing.T, call helperCall, value protocol.Continuation) {
	t.Helper()
	flags, _, _, _ := helperArguments(call.Args)
	if flags["task"] != value.Predecessor.TaskID || flags["id"] != value.Task.TaskID || flags["expected-spec-sha256"] != value.Predecessor.SpecSHA256 || flags["expected-project-sha256"] != strings.TrimPrefix(value.Predecessor.Context.Project, "ctx1_") {
		t.Fatal("Native continuation used the wrong predecessor/successor guards")
	}
	if flags["brief"] != "" || flags["provider"] != "" || flags["permission"] != "" || flags["cwd"] != "" || flags["resume-task"] != "" {
		t.Fatal("continuation invented inherited execution options or brief")
	}
	for key, want := range map[string]string{"budget": "7m", "model": "requested-model", "effort": "requested-effort", "output-silence-timeout": "0"} {
		if flags[key] != want {
			t.Fatalf("literal continuation override %s changed", key)
		}
	}
}

func TestConnectorOriginFileUsesNativeInputRecordBound(t *testing.T) {
	f := newFixture(t)
	r := request{config: f.adapter.snapshot(), project: f.config.Projects[0], task: f.task()}
	r.task.Origin.Binding = strings.Repeat("b", MaxStdoutBytes+1)
	owner := &controlOwner{temporary: t.TempDir()}
	call, err := r.guarded(t.Context(), owner, "resolve")
	if err != nil {
		t.Fatalf("valid Native input was limited by stdout capture capacity: %v", err)
	}
	flags, _, _, _ := helperArguments(call.args)
	data, err := os.ReadFile(flags["expected-origin"])
	if err != nil || len(data) <= MaxStdoutBytes || len(data) > protocol.NativeInputRecordBytes {
		t.Fatal("Origin input record did not use its semantic bound")
	}
}

func TestCompactInventoryOmitsObservedOptionsOnlyOnBoundWireReceipt(t *testing.T) {
	f, _, admission := compactAdmissionFixture(t)
	r := inventoryRequestFixture()
	entry := localInventoryEntry("1", f.config.Projects[0].ProjectToken)
	origin := admission.Task.Origin
	entry.Origin, entry.Receipt.Origin = &origin, origin
	wire, err := r.normalizeInventory(localInventory(entry))
	if err != nil || len(wire.Entries) != 1 || wire.Entries[0].Receipt.ExecutionOptions != (protocol.InventoryExecutionOptions{}) {
		t.Fatalf("bound wire inventory retained observed execution options: %v", err)
	}
	if entry.Receipt.ExecutionOptions.Provider == "" || wire.Entries[0].Origin.Binding != origin.Binding {
		t.Fatal("wire normalization changed Native facts or compact binding")
	}
}

func TestCompactContinuationRejectsChangedCommitmentBeforeNative(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*protocol.Continuation)
	}{
		{"override", func(c *protocol.Continuation) { c.Overrides.Budget = "8m" }},
		{"brief presence", func(c *protocol.Continuation) { c.BriefPresent, c.Brief = true, "different brief" }},
		{"explicit selection", func(c *protocol.Continuation) { c.SelectionExplicit = true }},
		{"predecessor spec", func(c *protocol.Continuation) { c.Predecessor.SpecSHA256 = strings.Repeat("d", 64) }},
		{"predecessor origin", func(c *protocol.Continuation) { c.Predecessor.Origin.RequestSHA256 = strings.Repeat("d", 64) }},
		{"successor route", func(c *protocol.Continuation) { c.Task.Route.Selection.ScopeID = "different-scope" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _, value := compactContinuationFixture(t, false, "")
			test.change(&value)
			command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
			if reply := f.adapter.Execute(t.Context(), command); reply.Error == nil {
				t.Fatal("changed continuation commitment was accepted")
			}
			if len(f.calls()) != 0 {
				t.Fatal("invalid continuation reached Native")
			}
			assertNativeFeaturesSettled(t, f)
		})
	}
}

func TestCompactContinuationUsesNewExplicitScopeWithoutOldApproval(t *testing.T) {
	f, store, value := compactContinuationFixture(t, true, "")
	store.mu.Lock()
	store.state.Workspaces[0].ID = "replacement-scope"
	store.mu.Unlock()
	value.Task.Route.Selection.ScopeID = "replacement-scope"
	recommitContinuation(t, &value)
	command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
		t.Fatal("new approved scope reauthorized predecessor's removed scope", reply.Error.Code)
	}
	for _, call := range f.calls() {
		if call.Command == "continue" && (call.ExpectedOrigin != value.Predecessor.Origin || call.SuccessorOrigin != value.Task.Origin) {
			t.Fatal("continuation rewrote immutable predecessor or successor Origin")
		}
	}
	assertNativeFeaturesSettled(t, f)
}

func recommitContinuation(t *testing.T, value *protocol.Continuation) {
	t.Helper()
	c, err := domain.ParseOriginBinding(value.Task.Origin.Binding)
	if err != nil {
		t.Fatal(err)
	}
	c.Route.ScopeID, c.Route.RelativePath = value.Task.Route.Selection.ScopeID, value.Task.Route.Selection.RelativePath
	o := value.Overrides
	overrides := domain.ContinuationOverrides{Version: o.Version, Budget: o.Budget, Model: o.Model, Effort: o.Effort, OutputSilenceTimeout: o.OutputSilenceTimeout}
	selector := domain.RequestSelector{}
	if value.SelectionExplicit {
		selector = domain.RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}
	}
	c.Route.InputDigest, err = domain.ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, selector, value.SelectionExplicit, overrides, value.BriefPresent, c.BriefDigest)
	if err != nil {
		t.Fatal(err)
	}
	value.Task.Origin = compactTestOrigin(t, c, domain.FrozenRequest{Continuation: overrides, Brief: value.Brief, BriefPresent: value.BriefPresent, SelectionExplicit: value.SelectionExplicit})
}

func TestCompactContinuationAcceptsLegacyPredecessorAndOptionalBrief(t *testing.T) {
	f, _, value := compactContinuationFixture(t, false, "replacement brief")
	value.Predecessor.Origin.Binding = ""
	f.state.Brief = value.Brief
	f.writeState()
	command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
	for range 2 {
		if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
			t.Fatal("stable continuation/replay failed", reply.Error.Code)
		}
	}
	count := 0
	for _, call := range f.calls() {
		if call.Command == "dispatch" {
			t.Fatal("continuation replay dispatched a replacement task")
		}
		if call.Command != "continue" {
			continue
		}
		count++
		flags, _, _, _ := helperArguments(call.Args)
		if flags["id"] != value.Task.TaskID || flags["task"] != value.Predecessor.TaskID || call.ExpectedOrigin != value.Predecessor.Origin || call.SuccessorOrigin != value.Task.Origin || call.BriefMode != 0o600 || call.BriefSHA256 != briefHash(value.Brief) {
			t.Fatal("replay changed task identity, Origins or optional brief file")
		}
	}
	if count != 2 {
		t.Fatalf("continuation calls=%d, want 2 stable invocations", count)
	}
	assertNativeFeaturesSettled(t, f)
}

func TestCompactResumeUsesCanonicalSavedTokensAfterApprovalRemoval(t *testing.T) {
	f, store, admission := compactAdmissionFixture(t)
	task := admission.Task
	task.SpecSHA256 = strings.Repeat("c", 64)
	store.mu.Lock()
	store.state.Workspaces = nil
	store.mu.Unlock()
	if err := os.Remove(f.config.Projects[0].Directory); err != nil {
		t.Fatal(err)
	}
	command := protocol.Command{Operation: protocol.ResumeExisting, Project: task.Origin.OperationID, Body: encoded(t, protocol.TaskControl{Task: task})}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
		t.Fatal("existing-only recovery required current approval", reply.Error.Code)
	}
	reads, resumes := 0, 0
	for _, call := range f.calls() {
		flags, _, _, _ := helperArguments(call.Args)
		if call.Command == "dispatch" || call.Command == "continue" {
			t.Fatal("existing-only resume admitted a fresh task")
		}
		if call.Command != "resolve" {
			continue
		}
		if assertCompactResumeCall(t, flags, task, f) {
			resumes++
		} else {
			reads++
		}
	}
	if reads != 2 || resumes != 1 {
		t.Fatalf("reads=%d resumes=%d, want 2 and 1", reads, resumes)
	}
	assertNativeFeaturesSettled(t, f)
}

func assertCompactResumeCall(t *testing.T, flags map[string]string, task protocol.TaskBinding, f *fixture) bool {
	t.Helper()
	if flags["resume-admission"] == "true" {
		if flags["expected-project"] != f.config.Projects[0].ProjectToken || flags["expected-project-sha256"] != "" || flags["expected-workspace"] != f.state.FrozenWorkspaceToken || flags["expected-spec-sha256"] != task.SpecSHA256 {
			t.Fatal("existing-only resume guessed or lost canonical raw guards")
		}
		return true
	}
	if flags["expected-project"] != "" || flags["expected-project-sha256"] != strings.TrimPrefix(task.Context.Project, "ctx1_") {
		t.Fatal("canonical recovery read used live project state")
	}
	return false
}

func TestCompactResumeNeverAdmitsAbsentOrRefusedTask(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "refused"}[refused], func(t *testing.T) {
			f, _, admission := compactAdmissionFixture(t)
			f.state.Absent, f.state.Refused = !refused, refused
			f.writeState()
			task := admission.Task
			task.SpecSHA256 = strings.Repeat("c", 64)
			command := protocol.Command{Operation: protocol.ResumeExisting, Project: task.Origin.OperationID, Body: encoded(t, protocol.TaskControl{Task: task})}
			assertCode(t, f.adapter.Execute(t.Context(), command), "forbidden")
			for _, call := range f.calls() {
				flags, _, _, _ := helperArguments(call.Args)
				if call.Command == "dispatch" || call.Command == "continue" || flags["resume-admission"] != "" {
					t.Fatal("absent/refused task started admission")
				}
			}
			assertNativeFeaturesSettled(t, f)
		})
	}
}

func TestCompactContinuationRejectsFreshReceiptConflict(t *testing.T) {
	for _, fault := range []string{"root", "project", "origin", "feature", "workspace"} {
		t.Run(fault, func(t *testing.T) {
			f, _, value := compactContinuationFixture(t, false, "")
			f.state.ReceiptFault = fault
			f.writeState()
			command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
			if reply := f.adapter.Execute(t.Context(), command); reply.Error == nil {
				t.Fatal("conflicting fresh successor receipt was accepted")
			}
			for _, call := range f.calls() {
				if call.Command == "resolve" {
					t.Fatal("invalid fresh receipt was masked by a passive resolve")
				}
			}
			assertNativeFeaturesSettled(t, f)
		})
	}
}

func TestCompactInventoryStillValidatesNativeOptions(t *testing.T) {
	f, _, admission := compactAdmissionFixture(t)
	r := inventoryRequestFixture()
	entry := localInventoryEntry("1", f.config.Projects[0].ProjectToken)
	origin := admission.Task.Origin
	entry.Origin, entry.Receipt.Origin = &origin, origin
	entry.Receipt.ExecutionOptions.BudgetNanoseconds = 0
	if _, err := r.normalizeInventory(localInventory(entry)); err == nil {
		t.Fatal("wire omission bypassed Native receipt validation")
	}
}

func TestCompactContinuationPreservesOmittedOverrides(t *testing.T) {
	f, _, value := compactContinuationFixture(t, false, "")
	value.Overrides = protocol.ContinuationOverrides{Version: 1}
	recommitContinuation(t, &value)
	command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
		t.Fatal(reply.Error.Code)
	}
	for _, call := range f.calls() {
		if call.Command != "continue" {
			continue
		}
		flags, _, _, _ := helperArguments(call.Args)
		for _, key := range []string{"brief", "budget", "model", "effort", "output-silence-timeout"} {
			if _, present := flags[key]; present {
				t.Fatalf("omitted continuation option %s acquired an override", key)
			}
		}
	}
	assertNativeFeaturesSettled(t, f)
}

func TestCompactContinuationRechecksCurrentScopeBeforeStart(t *testing.T) {
	f, store, value := compactContinuationFixture(t, false, "")
	command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
	r, err := f.adapter.decodeRequest(t.Context(), f.adapter.snapshot(), command)
	if err != nil {
		t.Fatal(err)
	}
	owner := &controlOwner{temporary: t.TempDir()}
	r, err = f.adapter.bindScopedProject(t.Context(), r, owner)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.beforeLock = func(state *WorkspaceSnapshot) { state.Workspaces[0].Enabled = false }
	store.mu.Unlock()
	if _, err = f.adapter.invoke(t.Context(), r, owner); err == nil {
		t.Fatal("revoked successor approval reached Continue")
	}
	if len(f.calls()) != 0 {
		t.Fatal("revoked successor approval started a Native process")
	}
}

func TestCompactContinuationRequiresNativeFeatures(t *testing.T) {
	for _, feature := range []string{protocol.FeatureOriginBinding, protocol.FeatureGuardedContinuation, protocol.FeatureProjectHashGuard} {
		t.Run(feature, func(t *testing.T) {
			f, _, value := compactContinuationFixture(t, false, "")
			features := make([]string, 0, len(f.state.Features))
			for _, actual := range f.state.Features {
				if actual != feature {
					features = append(features, actual)
				}
			}
			f.state.Features = features
			f.writeState()
			command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
			assertCode(t, f.adapter.Execute(t.Context(), command), "unsupported_feature")
			for _, call := range f.calls() {
				if call.Command != "context" {
					t.Fatal("unsupported Native received continuation or task mutation")
				}
			}
			assertNativeFeaturesSettled(t, f)
		})
	}
}

func TestCompactContinuationNativeArgumentRefusalIsTruthful(t *testing.T) {
	f, _, value := compactContinuationFixture(t, false, "")
	f.state.Mode = "argument-usage"
	f.writeState()
	command := protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)}
	assertArgumentReply(t, f.adapter.Execute(t.Context(), command), "invalid_request")
	for _, call := range f.calls() {
		if call.Command == "resolve" || call.Command == "dispatch" {
			t.Fatal("Native argument refusal started fallback control")
		}
	}
	assertNativeFeaturesSettled(t, f)
}

func TestCompactHistoricalControlUsesBoundOriginAfterWorkspaceRemoval(t *testing.T) {
	f, store, admission := compactAdmissionFixture(t)
	task := admission.Task
	task.SpecSHA256 = strings.Repeat("c", 64)
	store.mu.Lock()
	store.state.Workspaces = nil
	store.mu.Unlock()
	if err := os.Remove(f.config.Projects[0].Directory); err != nil {
		t.Fatal(err)
	}
	command := protocol.Command{Operation: protocol.Status, Project: task.Origin.OperationID, Body: encoded(t, protocol.TaskControl{Task: task})}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
		t.Fatal("historical bound control required live workspace", reply.Error.Code)
	}
	for _, call := range f.calls() {
		if call.Command == "context" {
			continue
		}
		flags, _, _, _ := helperArguments(call.Args)
		if flags["expected-project"] != "" || flags["expected-project-sha256"] != strings.TrimPrefix(task.Context.Project, "ctx1_") || call.ExpectedOrigin != task.Origin {
			t.Fatal("historical control changed saved guards")
		}
	}
	assertNativeFeaturesSettled(t, f)
}

func TestCompactOperationCannotEnterLegacyStaticRoute(t *testing.T) {
	f, _, admission := compactAdmissionFixture(t)
	cfg, err := checkedConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	command := protocol.Command{Operation: protocol.Admit, Project: f.config.Projects[0].Alias, Body: encoded(t, admission)}
	if _, err = decodeRequest(cfg, command); err == nil {
		t.Fatal("operation-bound intent entered legacy static routing without a ProjectStore")
	}
	if len(f.calls()) != 0 {
		t.Fatal("unsupported routing started Native")
	}
}

func TestCompactResumeDoesNotMutateAfterFailedCanonicalRead(t *testing.T) {
	f, _, admission := compactAdmissionFixture(t)
	f.state.ReceiptFault = "failure"
	f.writeState()
	task := admission.Task
	task.SpecSHA256 = strings.Repeat("c", 64)
	command := protocol.Command{Operation: protocol.ResumeExisting, Project: task.Origin.OperationID, Body: encoded(t, protocol.TaskControl{Task: task})}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error == nil {
		t.Fatal("failed canonical read became successful recovery")
	}
	for _, call := range f.calls() {
		flags, _, _, _ := helperArguments(call.Args)
		if flags["resume-admission"] != "" {
			t.Fatal("structured failure from canonical read reached admission mutation")
		}
	}
	assertNativeFeaturesSettled(t, f)
}

func TestUnlimitedAdmissionRequiresNativeCapabilityBeforeDispatch(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(map[bool]string{false: "historical-peer", true: "capable-peer"}[supported], func(t *testing.T) {
			f, _, admission := compactAdmissionFixture(t, "unlimited")
			f.state.Budget, f.state.BudgetUnlimited = 0, true
			if supported {
				f.state.Features = append(f.state.Features, protocol.FeatureExecutionBudget)
			}
			f.writeState()
			reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.Admit, Project: admission.Task.Origin.OperationID, Body: encoded(t, admission)})
			if supported && reply.Error != nil || !supported && reply.Error == nil {
				t.Fatalf("capability support %v: %+v", supported, reply.Error)
			}
			want := 0
			if supported {
				want = 1
			}
			assertUnlimitedDispatchCalls(t, f, want)
		})
	}
}

func assertUnlimitedDispatchCalls(t *testing.T, f *fixture, want int) {
	t.Helper()
	dispatched := 0
	for _, call := range f.calls() {
		if call.Command != "dispatch" {
			continue
		}
		dispatched++
		flags, _, _, _ := helperArguments(call.Args)
		if flags["budget"] != "unlimited" {
			t.Fatal("connector changed explicit unlimited choice")
		}
	}
	if dispatched != want {
		t.Fatalf("dispatch count %d, want %d", dispatched, want)
	}
}
