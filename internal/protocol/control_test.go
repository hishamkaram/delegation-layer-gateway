package protocol

import (
	"encoding/base64"
	"strings"
	"testing"
)

func taskBinding() TaskBinding {
	return TaskBinding{TaskID: strings.Repeat("a", 32), Context: ContextBinding{Root: WireContextGuard("local root token"), Project: WireContextGuard("local project token")}, Origin: Origin{GatewayID: "gateway", AdmissionGeneration: "generation", OperationID: "operation", PrincipalRef: "principal", RequestSHA256: strings.Repeat("b", 64)}, SpecSHA256: strings.Repeat("c", 64)}
}

func TestWireGuardHidesPathBearingCLIToken(t *testing.T) {
	if WireContextGuard("abc") != "ctx1_ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("wire guard changed its versioned digest")
	}
	binding := taskBinding()
	if err := binding.Validate(true); err != nil {
		t.Fatal(err)
	}
	binding.Context.Project = base64.RawURLEncoding.EncodeToString([]byte(`{"project":{"path":"/private/project"}}`))
	if binding.Validate(true) == nil {
		t.Fatal("path-bearing CLI token accepted as wire guard")
	}
}

func TestExplicitModelSupportsProviderNamespaces(t *testing.T) {
	if (Selection{Kind: "explicit", Value: "provider/model-v1"}).Validate() != nil {
		t.Fatal("namespaced model rejected")
	}
	for _, value := range []string{"", "model\nsecret", "model\u0085name"} {
		if (Selection{Kind: "explicit", Value: value}).Validate() == nil {
			t.Fatal("invalid model accepted")
		}
	}
}

func TestRangeMustMatchDescriptorAndExactCursor(t *testing.T) {
	request := RangeRequest{Task: taskBinding(), Descriptor: Descriptor{SHA256: strings.Repeat("d", 64), Length: 3}, Offset: 1, Limit: 2}
	valid := ResultRange{Descriptor: request.Descriptor, Offset: 1, DataBase64: base64.StdEncoding.EncodeToString([]byte("bc")), NextOffset: 3, EOF: true}
	if err := valid.ValidateFor(request); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ResultRange){
		"descriptor": func(r *ResultRange) { r.Descriptor.SHA256 = strings.Repeat("e", 64) },
		"cursor":     func(r *ResultRange) { r.NextOffset = 2 },
		"eof":        func(r *ResultRange) { r.EOF = false },
		"offset":     func(r *ResultRange) { r.Offset = 0 },
		"oversize":   func(r *ResultRange) { r.DataBase64 = "YWJj" },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			change(&value)
			if value.ValidateFor(request) == nil {
				t.Fatal("unbound result range accepted")
			}
		})
	}
}

func TestAcceptedOutcomeDoesNotInventLiveness(t *testing.T) {
	observation := TaskObservation{Task: taskBinding(), BriefSHA256: strings.Repeat("e", 64), Resolution: "existing", Admission: "unknown", Liveness: "undetermined", Publication: "committed", Verdict: "committed"}
	if err := observation.Validate(); err != nil {
		t.Fatal("valid outcome was coupled to independent liveness observation", err)
	}
	observation.Publication = "unknown"
	if observation.Validate() == nil {
		t.Fatal("uncommitted verdict accepted")
	}
}
