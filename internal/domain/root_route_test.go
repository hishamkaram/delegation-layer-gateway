package domain

import (
	"strings"
	"testing"
)

func TestRootInitializationHasExactlyOneTypedRoute(t *testing.T) {
	guard := RootGuard("ctx1_" + strings.Repeat("1", 64))
	root := RootRoute{Device: "device", Root: guard}
	project := Destination{Device: "device", Project: "project"}
	context := ContextBinding{Root: guard, Project: ProjectGuard("ctx1_" + strings.Repeat("2", 64))}
	for _, lookup := range []RootInitializationLookup{{RootRoute: &root}, {Route: project, ExpectedContext: context}} {
		actual, err := lookup.Namespace()
		if err != nil || actual != root {
			t.Fatal("valid route changed namespace identity", err)
		}
	}
	for _, lookup := range []RootInitializationLookup{
		{},
		{Route: project, RootRoute: &root, ExpectedContext: context},
		{RootRoute: &root, ExpectedContext: context},
		{Route: project},
		{RootRoute: &RootRoute{Device: "device"}},
	} {
		if lookup.Validate() == nil {
			t.Fatal("ambiguous/incomplete route accepted")
		}
	}
	binding := OwnedRootBinding{Route: root, Credential: CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}, Connection: ConnectionGeneration{BootEpoch: "boot", Counter: 1}}
	if binding.Validate() != nil {
		t.Fatal("current root binding rejected")
	}
	binding.Credential.Device = "other-device"
	if binding.Validate() == nil {
		t.Fatal("root borrowed another device credential")
	}
}
