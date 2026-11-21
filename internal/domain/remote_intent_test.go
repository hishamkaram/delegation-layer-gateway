package domain

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func intentFixture(t *testing.T, kind RequestKind) (Correlation, FrozenRequest) {
	t.Helper()
	c := Correlation{RequestVersion: 4, Kind: kind, Operation: "op", Task: "0123456789abcdef0123456789abcdef", Gateway: "gw", AdmissionGeneration: "generation", Owner: OperationOwner{Kind: Owned, Principal: "principal"}, Destination: Destination{Device: "device", Project: "op"}, Context: ContextBinding{Root: RootGuard("ctx1_" + strings.Repeat("1", 64)), Project: ProjectGuard("ctx1_" + strings.Repeat("2", 64))}, Route: OperationRoute{Version: 1, RequestID: RequestID(strings.Repeat("a", 32)), ScopeID: "workspace", RelativePath: "repo<&>", WorkspaceGuard: "ctx1_" + strings.Repeat("3", 64)}}
	r := FrozenRequest{Native: NativeOptions{Version: 1, Provider: "native", Model: Selection{Kind: Explicit, Value: "model<>&"}, Effort: Selection{Kind: NativeDefault}, Budget: "1s", OutputSilenceTimeout: "0"}, Brief: "hello", BriefPresent: true}
	var err error
	selection := RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}
	if kind == RequestKindDispatch {
		c.Route.InputFormat = DispatchInputV1
		c.BriefPresent = true
		c.BriefDigest = Hash([]byte(r.Brief))
		c.Route.InputDigest, err = DispatchInputDigestV1(c.Destination.Device, selection, r.Options(), c.BriefDigest)
	} else {
		c.Route.InputFormat = ContinuationInputV1
		c.Predecessor = ContinuationPredecessor{Operation: "prior", Task: TaskID(strings.Repeat("f", 32)), SpecDigest: Hash([]byte("predecessor spec")), RequestDigest: Hash([]byte("predecessor origin request"))}
		r = FrozenRequest{Continuation: ContinuationOverrides{Version: 1}}
		c.Route.InputDigest, err = ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, RequestSelector{}, false, r.Continuation, false, Digest{})
	}
	if err != nil {
		t.Fatal(err)
	}
	c.RequestDigest, err = RequestDigest(c, r)
	if err != nil {
		t.Fatal(err)
	}
	return c, r
}

func sequentialDigest() Digest {
	return Digest{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
}

func TestDispatchInputV1KeepsOriginalBytes(t *testing.T) {
	_, r := intentFixture(t, RequestKindDispatch)
	selector := RequestSelector{ScopeID: "workspace", RelativePath: "repo<&>"}
	const original = `{"Device":"device","Selection":{"scope_id":"workspace","relative_path":"repo\u003c\u0026\u003e"},"Options":{"Native":{"version":1,"provider":"native","model":{"Kind":"explicit","Value":"model\u003c\u003e\u0026"},"effort":{"Kind":"native_default","Value":""},"budget":"1s","output_silence_timeout":"0"},"Provider":"","Model":{"Kind":"","Value":""},"Effort":{"Kind":"","Value":""},"Permission":"","BudgetSeconds":0},"Brief":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]}`
	got, err := DispatchInputDigestV1("device", selector, r.Options(), sequentialDigest())
	if err != nil || got != sha256.Sum256([]byte(original)) {
		t.Fatalf("original dispatch fingerprint changed: %x, %v", got, err)
	}
	// Base64 is retained only in this legacy input representation, never silently
	// decoded or normalized into the text selector of a compact route.
	selector.RelativePath, selector.RelativePathBase64 = "", "cmVwbw=="
	encoded, err := DispatchInputDigestV1("device", selector, r.Options(), sequentialDigest())
	if err != nil || encoded == got {
		t.Fatal("selector representation disappeared from the legacy fingerprint")
	}
}

func TestVersionedInputRejectsInvalidSelectorRepresentations(t *testing.T) {
	_, request := intentFixture(t, RequestKindDispatch)
	for _, path := range []string{"/absolute", "../parent", "a/../b", "bad\x00path", string([]byte{0xff}), strings.Repeat("a", 256)} {
		selector := RequestSelector{ScopeID: "workspace", RelativePath: path}
		if _, err := DispatchInputDigestV1("device", selector, request.Options(), sequentialDigest()); err == nil {
			t.Fatalf("invalid selector was encoded into a reusable commitment: %q", path)
		}
	}
	selector := RequestSelector{ScopeID: "workspace", RelativePathBase64: "cmVwbw=="}
	if _, err := ContinuationInputDigestV1("device", "prior", selector, true, ContinuationOverrides{Version: 1}, false, Digest{}); err == nil {
		t.Fatal("compact continuation accepted a selector representation its route cannot retain")
	}
}

func TestLegacyV3AndAbsentNewFieldsKeepBytes(t *testing.T) {
	c, r := intentFixture(t, RequestKindDispatch)
	c.RequestVersion, c.Kind, c.BriefPresent, c.Route.InputFormat = 0, "", false, ""
	r.BriefPresent = false
	c.Route.InputDigest = sequentialDigest()
	const preimage = `{"Version":3,"Operation":"op","Task":"0123456789abcdef0123456789abcdef","Gateway":"gw","Generation":"generation","Owner":{"Kind":"owned","Principal":"principal"},"Destination":{"Device":"device","Project":"op"},"Context":{"Root":"ctx1_1111111111111111111111111111111111111111111111111111111111111111","Project":"ctx1_2222222222222222222222222222222222222222222222222222222222222222"},"Options":{"Native":{"version":1,"provider":"native","model":{"Kind":"explicit","Value":"model\u003c\u003e\u0026"},"effort":{"Kind":"native_default","Value":""},"budget":"1s","output_silence_timeout":"0"},"Provider":"","Model":{"Kind":"","Value":""},"Effort":{"Kind":"","Value":""},"Permission":"","BudgetSeconds":0},"BriefSHA256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","Route":{"Version":1,"RequestID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","InputDigest":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],"ScopeID":"workspace","RelativePath":"repo\u003c\u0026\u003e","WorkspaceGuard":"ctx1_3333333333333333333333333333333333333333333333333333333333333333","Predecessor":""}}`
	got, err := RequestDigest(c, r)
	if err != nil || got != sha256.Sum256([]byte(preimage)) {
		t.Fatalf("legacy v3 bytes changed: %x, %v", got, err)
	}
	c.RequestDigest = got
	request, err := json.Marshal(r)
	const requestJSON = `{"Native":{"version":1,"provider":"native","model":{"Kind":"explicit","Value":"model\u003c\u003e\u0026"},"effort":{"Kind":"native_default","Value":""},"budget":"1s","output_silence_timeout":"0"},"Provider":"","Model":{"Kind":"","Value":""},"Effort":{"Kind":"","Value":""},"Permission":"","BudgetSeconds":0,"Brief":"hello"}`
	if err != nil || string(request) != requestJSON {
		t.Fatal("zero new request fields changed legacy JSON", err)
	}
	origin := TaskOrigin{Gateway: "gw", AdmissionGeneration: "generation", Operation: "op", Principal: "principal", RequestDigest: sequentialDigest()}
	encoded, err := json.Marshal(origin)
	const originJSON = `{"Gateway":"gw","AdmissionGeneration":"generation","Operation":"op","Principal":"principal","RequestDigest":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]}`
	if err != nil || string(encoded) != originJSON {
		t.Fatal("absent binding changed legacy Origin JSON", err)
	}
	correlation, err := json.Marshal(c)
	if err != nil || strings.Contains(string(correlation), "InputFormat") || strings.Contains(string(correlation), "RequestVersion") || strings.Contains(string(correlation), "BriefPresent") {
		t.Fatal("zero compact correlation fields leaked into legacy JSON", err)
	}
}

func TestCompactBindingIndependentGoldens(t *testing.T) {
	const dispatch = `{"v":4,"kind":"dispatch","gateway":"gw","generation":"generation","operation":"op","task":"0123456789abcdef0123456789abcdef","principal":"principal","device":"device","project_alias":"op","context":{"root":"ctx1_1111111111111111111111111111111111111111111111111111111111111111","project":"ctx1_2222222222222222222222222222222222222222222222222222222222222222"},"route":{"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","input_format":"dispatch-v1","input_sha256":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","scope_id":"workspace","relative_path":"repo<&>","workspace_guard":"ctx1_3333333333333333333333333333333333333333333333333333333333333333"},"brief":{"present":true,"sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}`
	const continuation = `{"v":4,"kind":"continuation","gateway":"gw","generation":"generation","operation":"op","task":"0123456789abcdef0123456789abcdef","principal":"principal","device":"device","project_alias":"op","context":{"root":"ctx1_1111111111111111111111111111111111111111111111111111111111111111","project":"ctx1_2222222222222222222222222222222222222222222222222222222222222222"},"route":{"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","input_format":"continuation-v1","input_sha256":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","scope_id":"workspace","relative_path":"repo<&>","workspace_guard":"ctx1_3333333333333333333333333333333333333333333333333333333333333333"},"brief":{"present":false},"predecessor":{"operation":"prior","task":"ffffffffffffffffffffffffffffffff","spec_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","request_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}`
	for _, test := range []struct {
		kind RequestKind
		wire string
	}{{RequestKindDispatch, dispatch}, {RequestKindContinuation, continuation}} {
		t.Run(string(test.kind), func(t *testing.T) {
			c, _ := intentFixture(t, test.kind)
			c.Route.InputDigest = sequentialDigest()
			if test.kind == RequestKindContinuation {
				c.Predecessor.SpecDigest, c.Predecessor.RequestDigest = repeatedDigest(0xdd), repeatedDigest(0xee)
			}
			requireCompactBindingGolden(t, c, test.wire)
		})
	}
}

func requireCompactBindingGolden(t *testing.T, c Correlation, wire string) {
	t.Helper()
	binding, err := BuildOriginBinding(c)
	if err != nil || binding != wire {
		t.Fatalf("compact preimage differs from independent golden: %s, %v", binding, err)
	}
	c.RequestDigest = sha256.Sum256([]byte(wire))
	decoded, err := ParseOriginBinding(wire)
	if err != nil || decoded != c || c.Validate() != nil {
		t.Fatal("canonical binding lost comparable correlation", err)
	}
	origin, err := CompactOrigin(c)
	if err != nil || origin.Binding != wire || origin.RequestDigest != c.RequestDigest {
		t.Fatal("Origin did not retain the exact hashed preimage", err)
	}
	if OriginFromCorrelation(c) != (TaskOrigin{}) {
		t.Fatal("legacy Origin helper emitted an unbound compact Origin")
	}
	invalid := c
	invalid.RequestDigest = Hash([]byte("changed commitment"))
	if _, originErr := CompactOrigin(invalid); originErr == nil {
		t.Fatal("invalid compact correlation emitted an Origin without an error")
	}
	if _, err = RequestBindingDigest(c, ExecutionOptions{}, c.BriefDigest); err == nil {
		t.Fatal("compact request accepted legacy options-column provenance")
	}
}

func repeatedDigest(value byte) Digest {
	var digest Digest
	for i := range digest {
		digest[i] = value
	}
	return digest
}

func TestCompactRequestVerifiesRetainedDispatchBody(t *testing.T) {
	c, r := intentFixture(t, RequestKindDispatch)
	changes := []struct {
		name   string
		change func(*FrozenRequest)
	}{
		{"provider", func(r *FrozenRequest) { r.Native.Provider = "other" }},
		{"model", func(r *FrozenRequest) { r.Native.Model.Value = "other" }},
		{"effort", func(r *FrozenRequest) { r.Native.Effort = Selection{Kind: Explicit, Value: "high"} }},
		{"permission", func(r *FrozenRequest) { r.Native.Permission = "future-mode" }},
		{"budget", func(r *FrozenRequest) { r.Native.Budget = "2s" }},
		{"review target", func(r *FrozenRequest) { r.Native.ReviewTarget = "base" }},
		{"native timeout", func(r *FrozenRequest) { r.Native.NativeTimeout = "1s" }},
		{"output silence", func(r *FrozenRequest) { r.Native.OutputSilenceTimeout = "1s" }},
		{"brief", func(r *FrozenRequest) { r.Brief = "other" }},
		{"brief presence", func(r *FrozenRequest) { r.BriefPresent = false }},
		{"legacy options", func(r *FrozenRequest) { r.Provider = "legacy" }},
		{"continuation", func(r *FrozenRequest) { r.Continuation = ContinuationOverrides{Version: 1} }},
		{"selection flag", func(r *FrozenRequest) { r.SelectionExplicit = true }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			changed := r
			test.change(&changed)
			if _, digestErr := RequestDigest(c, changed); digestErr == nil {
				t.Fatal("changed body reused a copied input commitment")
			}
		})
	}
}

func TestCompactBodyRecomputesSelectedInput(t *testing.T) {
	for _, kind := range []RequestKind{RequestKindDispatch, RequestKindContinuation} {
		c, r := intentFixture(t, kind)
		if kind == RequestKindContinuation {
			r.SelectionExplicit = true
			var err error
			c.Route.InputDigest, err = ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}, true, r.Continuation, false, Digest{})
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, mutation := range []struct {
			name   string
			change func(*Correlation)
		}{
			{"device", func(c *Correlation) { c.Destination.Device = "other" }},
			{"scope", func(c *Correlation) { c.Route.ScopeID = "other" }},
			{"path", func(c *Correlation) { c.Route.RelativePath = "other" }},
		} {
			t.Run(string(kind)+"/"+mutation.name, func(t *testing.T) {
				changed := c
				mutation.change(&changed)
				binding, err := BuildOriginBinding(changed)
				if err != nil {
					t.Fatal(err)
				}
				changed.RequestDigest = Hash([]byte(binding))
				if changed.Validate() != nil {
					t.Fatal("bodyless correlation was not internally coherent")
				}
				if _, digestErr := RequestDigest(changed, r); digestErr == nil {
					t.Fatal("body validation trusted a copied input hash")
				}
			})
		}
	}
}

func TestContinuationInputV1GoldenAndBodySemantics(t *testing.T) {
	selector := RequestSelector{ScopeID: "workspace", RelativePath: "."}
	overrides := ContinuationOverrides{Version: 1, Budget: "1s", Model: "literal", Effort: "high", OutputSilenceTimeout: "0"}
	const canonical = `{"Version":1,"Kind":"continuation","Device":"device","Predecessor":"prior","Selection":{"scope_id":"workspace","relative_path":"."},"SelectionExplicit":true,"Overrides":{"version":1,"budget":"1s","model":"literal","effort":"high","output_silence_timeout":"0"},"BriefPresent":false,"Brief":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	got, err := ContinuationInputDigestV1("device", "prior", selector, true, overrides, false, Digest{})
	if err != nil || got != sha256.Sum256([]byte(canonical)) {
		t.Fatal("continuation input encoding changed", err)
	}
	c, r := intentFixture(t, RequestKindContinuation)
	for _, test := range []struct {
		name   string
		change func(*FrozenRequest)
	}{
		{"budget", func(r *FrozenRequest) { r.Continuation.Budget = "1s" }},
		{"model", func(r *FrozenRequest) { r.Continuation.Model = "literal" }},
		{"effort", func(r *FrozenRequest) { r.Continuation.Effort = "high" }},
		{"silence disable", func(r *FrozenRequest) { r.Continuation.OutputSilenceTimeout = "0" }},
		{"explicit selection", func(r *FrozenRequest) { r.SelectionExplicit = true }},
		{"brief presence", func(r *FrozenRequest) { r.BriefPresent, r.Brief = true, "new brief" }},
		{"unmarked brief", func(r *FrozenRequest) { r.Brief = "unmarked" }},
		{"dispatch options", func(r *FrozenRequest) { r.Native = NativeOptions{Version: 1, Provider: "provider"} }},
		{"version", func(r *FrozenRequest) { r.Continuation.Version = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := r
			test.change(&changed)
			if _, digestErr := RequestDigest(c, changed); digestErr == nil {
				t.Fatal("continuation body changed without input verification")
			}
		})
	}
	// Explicitly requesting a brief is supported, but its digest is independent
	// of the Native predecessor's inherited brief.
	r.BriefPresent, r.Brief = true, "new brief"
	c.BriefPresent, c.BriefDigest = true, Hash([]byte(r.Brief))
	c.Route.InputDigest, err = ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, RequestSelector{}, false, r.Continuation, true, c.BriefDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RequestDigest(c, r); err != nil {
		t.Fatal("valid explicit continuation brief rejected", err)
	}
}

func TestImplicitContinuationFingerprintNeedsNoCapturedRoute(t *testing.T) {
	c, r := intentFixture(t, RequestKindContinuation)
	const callerInput = `{"Version":1,"Kind":"continuation","Device":"device","Predecessor":"prior","Selection":{"scope_id":""},"SelectionExplicit":false,"Overrides":{"version":1},"BriefPresent":false,"Brief":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	if c.Route.InputDigest != sha256.Sum256([]byte(callerInput)) {
		t.Fatal("implicit caller fingerprint depended on resolved predecessor selection")
	}
	changed := c
	changed.Route.ScopeID, changed.Route.RelativePath = "replacement-approval", "other"
	digest, err := RequestDigest(changed, r)
	if err != nil || digest == c.RequestDigest || changed.Route.InputDigest != c.Route.InputDigest {
		t.Fatal("captured route was not independently bound from implicit caller input", err)
	}
	selector := RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}
	if _, err = ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, selector, false, r.Continuation, false, Digest{}); err == nil {
		t.Fatal("implicit fingerprint accepted a captured selector")
	}
	first, err := ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, selector, true, r.Continuation, false, Digest{})
	if err != nil {
		t.Fatal(err)
	}
	selector.RelativePath = "other"
	second, err := ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, selector, true, r.Continuation, false, Digest{})
	if err != nil || first == second {
		t.Fatal("changed explicit selector reused its caller commitment", err)
	}
}

func TestPresentOriginBindingNeverFallsBack(t *testing.T) {
	c, _ := intentFixture(t, RequestKindDispatch)
	origin, err := CompactOrigin(c)
	if err != nil {
		t.Fatal(err)
	}
	key := NativeTaskKey{Device: c.Destination.Device, Root: c.Context.Root, Task: c.Task}
	for _, test := range []struct {
		name    string
		binding string
	}{
		{"malformed", "{"},
		{"empty", ""},
		{"null", "null"},
		{"unknown field", strings.TrimSuffix(origin.Binding, "}") + `,"extra":true}`},
		{"duplicate field", strings.Replace(origin.Binding, `"v":4`, `"v":4,"v":4`, 1)},
		{"wrong case", strings.Replace(origin.Binding, `"v":4`, `"V":4`, 1)},
		{"unknown version", strings.Replace(origin.Binding, `"v":4`, `"v":5`, 1)},
		{"space", " " + origin.Binding},
		{"alternate escape", strings.Replace(origin.Binding, "<", `\u003c`, 1)},
		{"trailing JSON", origin.Binding + "{}"},
		{"invalid UTF8", origin.Binding + string([]byte{0xff})},
		{"invalid kind", strings.Replace(origin.Binding, `"kind":"dispatch"`, `"kind":"unknown"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := origin
			changed.Binding = test.binding
			_, err := VerifyOriginBinding(c.Gateway, key, changed)
			requireIntentEvidenceInvalid(t, err)
		})
	}
	for _, field := range []string{"gateway", "generation", "operation", "principal", "request digest", "device", "root", "task"} {
		t.Run(field, func(t *testing.T) {
			changed, facts := origin, key
			switch field {
			case "gateway":
				changed.Gateway = "other"
			case "generation":
				changed.AdmissionGeneration = "other"
			case "operation":
				changed.Operation = "other"
			case "principal":
				changed.Principal = "other"
			case "request digest":
				changed.RequestDigest = Hash([]byte("other"))
			case "device":
				facts.Device = "other"
			case "root":
				facts.Root = RootGuard("ctx1_" + strings.Repeat("4", 64))
			case "task":
				facts.Task = TaskID(strings.Repeat("b", 32))
			}
			_, err := VerifyOriginBinding(c.Gateway, facts, changed)
			requireIntentEvidenceInvalid(t, err)
		})
	}
}

func requireIntentEvidenceInvalid(t *testing.T, err error) {
	t.Helper()
	var classified *Error
	if !errors.As(err, &classified) || classified.Code != EvidenceInvalid {
		t.Fatalf("want evidence_invalid, got %v", err)
	}
}

func TestBindingCoversEveryCompactCorrelationField(t *testing.T) {
	c, _ := intentFixture(t, RequestKindContinuation)
	for _, test := range []struct {
		name   string
		change func(*Correlation)
	}{
		{"request version", func(c *Correlation) { c.RequestVersion = 5 }},
		{"kind", func(c *Correlation) { c.Kind = RequestKindDispatch }},
		{"input format", func(c *Correlation) { c.Route.InputFormat = DispatchInputV1 }},
		{"brief presence", func(c *Correlation) { c.BriefPresent = true }},
		{"absent brief digest", func(c *Correlation) { c.BriefDigest = Hash([]byte("unrequested")) }},
		{"legacy predecessor representation", func(c *Correlation) { c.Route.Predecessor = "prior" }},
		{"gateway", func(c *Correlation) { c.Gateway = "other" }},
		{"generation", func(c *Correlation) { c.AdmissionGeneration = "other" }},
		{"operation", func(c *Correlation) { c.Operation = "other" }},
		{"task", func(c *Correlation) { c.Task = TaskID(strings.Repeat("b", 32)) }},
		{"principal", func(c *Correlation) { c.Owner.Principal = "other" }},
		{"device", func(c *Correlation) { c.Destination.Device = "other" }},
		{"project alias", func(c *Correlation) { c.Destination.Project = "other" }},
		{"root", func(c *Correlation) { c.Context.Root = RootGuard("ctx1_" + strings.Repeat("4", 64)) }},
		{"project", func(c *Correlation) { c.Context.Project = ProjectGuard("ctx1_" + strings.Repeat("4", 64)) }},
		{"request key", func(c *Correlation) { c.Route.RequestID = RequestID(strings.Repeat("b", 32)) }},
		{"input", func(c *Correlation) { c.Route.InputDigest = Hash([]byte("other")) }},
		{"scope", func(c *Correlation) { c.Route.ScopeID = "other" }},
		{"path", func(c *Correlation) { c.Route.RelativePath = "other" }},
		{"workspace guard", func(c *Correlation) { c.Route.WorkspaceGuard = "ctx1_" + strings.Repeat("4", 64) }},
		{"predecessor operation", func(c *Correlation) { c.Predecessor.Operation = "other" }},
		{"predecessor task", func(c *Correlation) { c.Predecessor.Task = TaskID(strings.Repeat("c", 32)) }},
		{"predecessor spec", func(c *Correlation) { c.Predecessor.SpecDigest = Hash([]byte("other")) }},
		{"predecessor request", func(c *Correlation) { c.Predecessor.RequestDigest = Hash([]byte("other")) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := c
			test.change(&changed)
			if changed.Validate() == nil {
				t.Fatal("changed field retained an unchanged compact commitment")
			}
		})
	}
}

func TestIdentityReceiptPreservesAbsentRequestedBrief(t *testing.T) {
	for _, kind := range []RequestKind{RequestKindDispatch, RequestKindContinuation} {
		t.Run(string(kind), func(t *testing.T) {
			c, receipt := identityReceiptFixture(t, kind)
			requireIdentityReceipt(t, c, receipt)
		})
	}
	legacy, receipt := attributionFixture(t)
	receipt.Options = HistoricalExecutionOptions{}
	if receipt.Validate() == nil || RequestedBriefMatches(legacy, Hash([]byte("different"))) {
		t.Fatal("identity-only branch weakened absent-binding legacy validation")
	}
}

func requireIdentityReceipt(t *testing.T, c Correlation, receipt NativeTaskReceipt) {
	t.Helper()
	key := NativeTaskKey{Device: c.Destination.Device, Root: c.Context.Root, Task: c.Task}
	got, err := VerifyBoundNativeReceipt(c.Gateway, key, receipt)
	if err != nil || got != c || receipt.Options != (HistoricalExecutionOptions{}) {
		t.Fatal("identity receipt fabricated requested options or brief", err)
	}
	encoded, encodeErr := json.Marshal(receipt)
	if encodeErr != nil || strings.Contains(string(encoded), `"Options":`) {
		t.Fatal("identity receipt serialized fabricated observed options", encodeErr)
	}
	candidate := ProjectRegistration{Destination: c.Destination, Context: c.Context}
	attributed, options, matched, err := AttributeNativeReceipt(c.Gateway, key.Device, candidate, receipt)
	if err != nil || !matched || attributed != c || options != (ExecutionOptions{}) {
		t.Fatal("bound attribution did not preserve identity-only provenance", err)
	}
	if !c.BriefPresent && got.BriefDigest != (Digest{}) {
		t.Fatal("Native inherited brief overwrote absent requested digest")
	}
	receipt.BriefDigest = Hash([]byte("different observed brief"))
	_, err = VerifyBoundNativeReceipt(c.Gateway, key, receipt)
	if c.BriefPresent {
		requireIntentEvidenceInvalid(t, err)
	} else if err != nil {
		t.Fatal("absent requested brief was compared with an inherited Native brief", err)
	}
}

func identityReceiptFixture(t *testing.T, kind RequestKind) (Correlation, NativeTaskReceipt) {
	t.Helper()
	c, _ := intentFixture(t, kind)
	origin, err := CompactOrigin(c)
	if err != nil {
		t.Fatal(err)
	}
	observedBrief := Hash([]byte("inherited Native brief"))
	if c.BriefPresent {
		observedBrief = c.BriefDigest
	}
	return c, NativeTaskReceipt{Binding: NativeTaskBinding{Task: c.Task, Context: c.Context, Origin: origin, SpecDigest: Hash([]byte("actual successor task"))}, BriefDigest: observedBrief}
}

func TestIdentityReceiptRejectsInvalidPresentEvidence(t *testing.T) {
	_, legacy := attributionFixture(t)
	for _, kind := range []RequestKind{RequestKindDispatch, RequestKindContinuation} {
		c, receipt := identityReceiptFixture(t, kind)
		candidate := ProjectRegistration{Destination: c.Destination, Context: c.Context}
		for _, mutation := range []struct {
			name   string
			change func(*NativeTaskReceipt)
		}{
			{"options", func(r *NativeTaskReceipt) { r.Options = legacy.Options }},
			{"spec", func(r *NativeTaskReceipt) { r.Binding.SpecDigest = Digest{} }},
			{"context", func(r *NativeTaskReceipt) {
				r.Binding.Context.Project = ProjectGuard("ctx1_" + strings.Repeat("4", 64))
			}},
			{"binding", func(r *NativeTaskReceipt) { r.Binding.Origin.Binding = "invalid-present" }},
			{"owner", func(r *NativeTaskReceipt) { r.Binding.Origin.Principal = "other" }},
		} {
			t.Run(string(kind)+"/"+mutation.name, func(t *testing.T) {
				changed := receipt
				mutation.change(&changed)
				_, _, matched, err := AttributeNativeReceipt(c.Gateway, c.Destination.Device, candidate, changed)
				requireIntentEvidenceInvalid(t, err)
				if matched {
					t.Fatal("invalid present binding/receipt fell back to unattributed")
				}
			})
		}
	}
}
