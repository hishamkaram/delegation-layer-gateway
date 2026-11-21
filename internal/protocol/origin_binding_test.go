package protocol

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestOriginBindingWireRoundTripAndInverse(t *testing.T) {
	const wire = `{"gateway_id":"gateway","admission_generation":"generation","operation_id":"operation","principal_ref":"principal","gateway_request_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","binding":"opaque:<>&雪"}`
	var origin Origin
	if err := DecodeStrict([]byte(wire), &origin, MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(origin, MaxFrameBytes)
	if err != nil || string(encoded) != wire {
		t.Fatalf("origin wire bytes changed: %s, %v", encoded, err)
	}
	value, err := origin.DomainOrigin()
	if err != nil {
		t.Fatal(err)
	}
	result, err := OriginFromDomain(value)
	if err != nil || result != origin || value.Binding != "opaque:<>&雪" {
		t.Fatalf("origin conversion lost immutable binding: %+v, %v", result, err)
	}
	other := value
	other.Binding = "different"
	if value == other || value.Binding != "opaque:<>&雪" {
		t.Fatal("origin binding lost independent value equality")
	}
}

func TestBindingAbsentPreservesLegacyOriginWire(t *testing.T) {
	const wire = `{"gateway_id":"gateway","admission_generation":"generation","operation_id":"operation","principal_ref":"principal","gateway_request_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`
	var origin Origin
	if err := DecodeStrict([]byte(wire), &origin, MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(origin, MaxFrameBytes)
	if err != nil || string(encoded) != wire {
		t.Fatalf("legacy origin bytes changed: %s, %v", encoded, err)
	}
}

func TestBoundInventoryCarriesIdentityWithoutObservedOptions(t *testing.T) {
	report, request := inventoryExample()
	entry := &report.Entries[0]
	entry.Origin.Binding = "opaque-immutable-intent"
	entry.Receipt.Task.Origin = *entry.Origin
	if report.ValidateFor(request) == nil {
		t.Fatal("bound inventory mixed observed execution options with identity")
	}
	entry.Receipt.ExecutionOptions = InventoryExecutionOptions{}
	if err := report.ValidateFor(request); err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(report, MaxFrameBytes)
	if err != nil || bytes.Contains(encoded, []byte(`"execution_options"`)) {
		t.Fatalf("identity-only inventory retained observed options: %v", err)
	}
	var decoded OriginInventoryReport
	if DecodeStrict(encoded, &decoded, MaxFrameBytes) != nil || decoded.ValidateFor(request) != nil || decoded.Entries[0].Receipt.Task.Origin != *entry.Origin {
		t.Fatal("identity-only inventory lost binding or pagination authority")
	}
	entry.Origin.Binding = ""
	entry.Receipt.Task.Origin = *entry.Origin
	if report.ValidateFor(request) == nil {
		t.Fatal("legacy inventory accepted absent required execution options")
	}
}

func TestOriginBindingShapeUsesNativeInputBound(t *testing.T) {
	origin := taskBinding().Origin
	for _, binding := range []string{"", "opaque\n\x01雪", strings.Repeat("x", NativeInputRecordBytes)} {
		origin.Binding = binding
		if origin.Validate() != nil {
			t.Fatal("transport shape interpreted opaque binding meaning")
		}
	}
	for _, binding := range []string{"embedded\x00nul", string([]byte{0xff}), strings.Repeat("x", NativeInputRecordBytes+1)} {
		origin.Binding = binding
		if origin.Validate() == nil {
			t.Fatal("invalid native origin-input shape was accepted")
		}
	}
}

func TestUnifiedOriginConstructorPreservesCompactCommitment(t *testing.T) {
	c := domain.Correlation{
		RequestVersion: domain.CompactRequestVersion, Kind: domain.RequestKindDispatch, BriefPresent: true,
		Operation: "operation", Task: domain.TaskID(strings.Repeat("a", 32)), Gateway: "gateway", AdmissionGeneration: "generation",
		Owner: domain.OperationOwner{Kind: domain.Owned, Principal: "principal"}, Destination: domain.Destination{Device: "device", Project: "operation"},
		Context: domain.ContextBinding{Root: domain.RootGuard(WireContextGuard("root")), Project: domain.ProjectGuard(WireContextGuard("project"))}, BriefDigest: domain.Hash([]byte("brief")),
		Route: domain.OperationRoute{Version: 1, RequestID: domain.RequestID(strings.Repeat("b", 32)), InputFormat: domain.DispatchInputV1, InputDigest: domain.Hash([]byte("caller input")), ScopeID: "workspace", RelativePath: ".", WorkspaceGuard: WireContextGuard("workspace")},
	}
	binding, err := domain.BuildOriginBinding(c)
	if err != nil {
		t.Fatal(err)
	}
	c.RequestDigest = domain.Hash([]byte(binding))
	origin, err := OriginFromCorrelation(c)
	if err != nil || origin.Binding != binding || origin.RequestSHA256 != c.RequestDigest.Hex() {
		t.Fatalf("unified constructor lost compact commitment: %+v, %v", origin, err)
	}
	recovered, err := origin.DomainOrigin()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := domain.VerifyOriginBinding(c.Gateway, domain.NativeTaskKey{Device: c.Destination.Device, Root: c.Context.Root, Task: c.Task}, recovered)
	if err != nil || verified != c {
		t.Fatalf("inverse did not retain exact correlation: %+v, %v", verified, err)
	}
	c.RequestDigest = domain.Hash([]byte("changed commitment"))
	if _, err := OriginFromCorrelation(c); err == nil {
		t.Fatal("invalid compact correlation emitted an unbound or stale origin")
	}
}
