package deviceclient

import "testing"

func TestProviderPolicyUsesWireSelectionValidation(t *testing.T) {
	provider := ProviderPolicy{Provider: "claude:print", Models: []string{"opus"}, Efforts: []string{"high"}, Permissions: []string{"read-only"}, MaxBudgetSeconds: 60}
	if !validProvider(provider) {
		t.Fatal("valid explicit provider policy rejected")
	}
	for _, model := range []string{"model with spaces", string([]byte{0xff})} {
		invalid := provider
		invalid.Models = []string{model}
		if validProvider(invalid) {
			t.Fatal("invalid wire model persisted in local approval")
		}
	}
	invalid := provider
	invalid.Permissions = []string{"read-only", "read-only"}
	if validProvider(invalid) {
		t.Fatal("duplicate permission ceiling persisted")
	}
}

func TestLocalProfilePathsCannotChangeDuringJSONEncoding(t *testing.T) {
	if localPath("/" + string([]byte{0xff})) {
		t.Fatal("invalid UTF-8 path could be replaced silently by JSON encoding")
	}
}
