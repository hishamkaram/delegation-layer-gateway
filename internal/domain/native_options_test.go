package domain

import (
	"strings"
	"testing"
)

func TestNativeOptionsAreIntentNotGatewayPolicy(t *testing.T) {
	options := NativeOptions{Version: 1, Provider: "future:provider", Model: Selection{Kind: Explicit, Value: "unadvertised/model"}, Effort: Selection{Kind: NativeDefault}, Permission: "future-native-mode", Budget: "250000h", ReviewTarget: "base:topic", NativeTimeout: "1h", OutputSilenceTimeout: "0"}
	request := FrozenRequest{Native: options, Brief: "probe"}
	if err := request.Validate(); err != nil {
		t.Fatal("Gateway imposed Native execution semantics", err)
	}
	malformed := options
	malformed.Version = 0
	if (FrozenRequest{Native: malformed, Brief: "probe", Provider: "legacy:provider", Model: Selection{Kind: NativeDefault}, Effort: Selection{Kind: NativeDefault}, Permission: ReadOnly, BudgetSeconds: 60}).Validate() == nil {
		t.Fatal("nonempty version-zero Native options bypassed validation")
	}
	request.Provider = "legacy:provider"
	if request.Validate() == nil {
		t.Fatal("mixed legacy and new execution options accepted")
	}
}

func TestOperationRouteIsPartOfImmutableRequestAfterBodyDisposal(t *testing.T) {
	c := Correlation{Operation: "op", Task: "0123456789abcdef0123456789abcdef", Gateway: "gw", AdmissionGeneration: "generation", Owner: OperationOwner{Kind: Owned, Principal: "principal"}, Destination: Destination{Device: "device", Project: "op"}, Context: ContextBinding{Root: RootGuard("ctx1_" + strings.Repeat("1", 64)), Project: ProjectGuard("ctx1_" + strings.Repeat("2", 64))}, Route: OperationRoute{Version: 1, RequestID: RequestID(strings.Repeat("a", 32)), InputDigest: Hash([]byte("client intent")), ScopeID: "workspace", RelativePath: "project"}}
	r := FrozenRequest{Native: NativeOptions{Version: 1, Provider: "claude:print", Model: Selection{Kind: NativeDefault}, Effort: Selection{Kind: NativeDefault}}, Brief: "probe"}
	c.BriefDigest = Hash([]byte(r.Brief))
	original, err := RequestDigest(c, r)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := RequestBindingDigest(c, r.Options(), c.BriefDigest)
	if err != nil || recovered != original {
		t.Fatal("body disposal lost route commitment")
	}
	c.Route.RelativePath = "other"
	changed, err := RequestBindingDigest(c, r.Options(), c.BriefDigest)
	if err != nil {
		t.Fatal(err)
	}
	if changed == original {
		t.Fatal("route retargeted without changing canonical identity")
	}
}
