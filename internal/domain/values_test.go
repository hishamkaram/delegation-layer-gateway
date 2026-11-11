package domain

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestRequestDigestBindsCanonicalRequest(t *testing.T) {
	c := Correlation{Operation: "op", Task: "0123456789abcdef0123456789abcdef", Gateway: "gw", AdmissionGeneration: "generation", Owner: OperationOwner{Kind: Owned, Principal: "principal"}, Destination: Destination{Device: "device", Project: "project"}, Context: ContextBinding{Root: RootGuard("ctx1_" + strings.Repeat("1", 64)), Project: ProjectGuard("ctx1_" + strings.Repeat("2", 64))}}
	r := FrozenRequest{Provider: "provider", Model: Selection{Kind: NativeDefault}, Effort: Selection{Kind: Explicit, Value: "high"}, Permission: ReadOnly, BudgetSeconds: 60, Brief: "hello"}
	c.BriefDigest = Hash([]byte(r.Brief))
	got, err := RequestDigest(c, r)
	if err != nil {
		t.Fatal(err)
	}
	// Independent fixed wire example protects both field membership and encoding.
	const canonical = `{"Version":2,"Operation":"op","Task":"0123456789abcdef0123456789abcdef","Gateway":"gw","Generation":"generation","Owner":{"Kind":"owned","Principal":"principal"},"Destination":{"Device":"device","Project":"project"},"Context":{"Root":"ctx1_1111111111111111111111111111111111111111111111111111111111111111","Project":"ctx1_2222222222222222222222222222222222222222222222222222222222222222"},"Options":{"Provider":"provider","Model":{"Kind":"native_default","Value":""},"Effort":{"Kind":"explicit","Value":"high"},"Permission":"read-only","BudgetSeconds":60},"BriefSHA256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}`
	want := sha256.Sum256([]byte(canonical))
	recovered, recoverErr := RequestBindingDigest(c, r.Options(), c.BriefDigest)
	if recoverErr != nil || recovered != want {
		t.Fatal("canonical identity cannot be recovered from options and brief digest alone")
	}
	if _, mismatchErr := RequestBindingDigest(c, r.Options(), Hash([]byte("different brief"))); mismatchErr == nil {
		t.Fatal("recovery accepted a mismatched brief digest")
	}
	if _, mismatchErr := RequestDigest(c, FrozenRequest{Provider: r.Provider, Model: r.Model, Effort: r.Effort, Permission: r.Permission, BudgetSeconds: r.BudgetSeconds, Brief: "different brief"}); mismatchErr == nil {
		t.Fatal("plaintext wrapper ignored the immutable brief digest")
	}
	if got != want {
		t.Fatalf("digest does not match canonical v2 example: %x != %x", got, want)
	}
	missingMapping := c
	missingMapping.Owner = OperationOwner{Kind: Ownerless}
	if _, err = RequestDigest(missingMapping, r); err == nil {
		t.Fatal("ownerless local visibility erased mandatory canonical origin principal")
	}
	mutations := []struct {
		name   string
		change func(*Correlation, *FrozenRequest)
	}{
		{"operation", func(c *Correlation, _ *FrozenRequest) { c.Operation = "other" }},
		{"task", func(c *Correlation, _ *FrozenRequest) { c.Task = "1123456789abcdef0123456789abcdef" }},
		{"gateway", func(c *Correlation, _ *FrozenRequest) { c.Gateway = "other" }},
		{"generation", func(c *Correlation, _ *FrozenRequest) { c.AdmissionGeneration = "other" }},
		{"principal", func(c *Correlation, _ *FrozenRequest) { c.Owner.Principal = "other" }},
		{"device", func(c *Correlation, _ *FrozenRequest) { c.Destination.Device = "other" }},
		{"alias", func(c *Correlation, _ *FrozenRequest) { c.Destination.Project = "other" }},
		{"root", func(c *Correlation, _ *FrozenRequest) { c.Context.Root = RootGuard("ctx1_" + strings.Repeat("3", 64)) }},
		{"project guard", func(c *Correlation, _ *FrozenRequest) {
			c.Context.Project = ProjectGuard("ctx1_" + strings.Repeat("4", 64))
		}},
		{"provider", func(_ *Correlation, r *FrozenRequest) { r.Provider = "other" }},
		{"model", func(_ *Correlation, r *FrozenRequest) { r.Model = Selection{Kind: Explicit, Value: "model"} }},
		{"effort", func(_ *Correlation, r *FrozenRequest) { r.Effort = Selection{Kind: NativeDefault} }},
		{"permission", func(_ *Correlation, r *FrozenRequest) { r.Permission = WorkspaceWrite }},
		{"budget", func(_ *Correlation, r *FrozenRequest) { r.BudgetSeconds++ }},
		{"brief", func(_ *Correlation, r *FrozenRequest) { r.Brief = "other" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changedC, changedR := c, r
			test.change(&changedC, &changedR)
			changedC.BriefDigest = Hash([]byte(changedR.Brief))
			digest, err := RequestDigest(changedC, changedR)
			if err != nil {
				t.Fatal(err)
			}
			if digest == got {
				t.Fatal("immutable field is not bound by digest")
			}
		})
	}
}

func TestBoundaryValuesRejectAmbiguity(t *testing.T) {
	for _, selection := range []Selection{{}, {Kind: NativeDefault, Value: "model"}, {Kind: Explicit}, {Kind: "unknown"}} {
		if selection.Validate() == nil {
			t.Fatalf("accepted ambiguous selection %+v", selection)
		}
	}
	for _, value := range []string{"", "a:b", "a/b", "a%20b", "a b", "é"} {
		if CredentialToken(value) == nil {
			t.Fatalf("accepted ambiguous URI component %q", value)
		}
	}
	if err := CredentialToken("device_1.-"); err != nil {
		t.Fatal(err)
	}
	if err := TaskID("0123456789ABCDEF0123456789abcdef").Validate(); err == nil {
		t.Fatal("uppercase task ID accepted")
	}
	if err := (ScopeSet{TaskRead, TaskRead}).Validate(); err == nil {
		t.Fatal("duplicate scope accepted")
	}
}

func TestRoutingAndGuardBoundsMatchWireContract(t *testing.T) {
	for _, value := range []string{"é", "device~", "has space", strings.Repeat("a", 129)} {
		if RoutingToken(value) == nil {
			t.Fatalf("unrouteable identifier accepted: %q", value)
		}
	}
	if err := RoutingToken(strings.Repeat("a", 128)); err != nil {
		t.Fatal(err)
	}
	if err := RoutingToken("provider:exec"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"device~", "epoch:1", strings.Repeat("a", 129)} {
		if CredentialToken(value) == nil {
			t.Fatalf("ambiguous credential component accepted: %q", value)
		}
	}
	if err := ContextToken("ctx1_" + strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"root", "base64-local-path", strings.Repeat("a", 4096), "ctx1_" + strings.Repeat("A", 64), "ctx1_" + strings.Repeat("a", 63)} {
		if ContextToken(value) == nil {
			t.Fatalf("local token or invalid wire commitment accepted: %q", value)
		}
	}
	if err := (Selection{Kind: Explicit, Value: "provider/model@revision"}).Validate(); err != nil {
		t.Fatal("routing alphabet incorrectly narrowed native model values")
	}
}
