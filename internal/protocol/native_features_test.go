package protocol

import (
	"slices"
	"testing"
)

func TestRecognizedNativeFeaturesPreservesOnlyActualEvidence(t *testing.T) {
	for _, test := range []struct {
		name        string
		input, want []string
	}{
		{"unknown", []string{"future-feature"}, nil},
		{"admission-only", []string{"namespace-admission-v1", "future-feature"}, []string{"namespace-admission-v1"}},
		{"lease-only", []string{"namespace-mutation-lease-v1"}, []string{"namespace-mutation-lease-v1"}},
		{"both-reordered-duplicates", []string{"namespace-mutation-lease-v1", "namespace-admission-v1", "namespace-mutation-lease-v1", "future-feature"}, []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := RecognizedNativeFeatures(test.input)
			if !slices.Equal(got, test.want) {
				t.Fatalf("recognized features = %v, want %v", got, test.want)
			}
			if len(got) > 0 {
				got[0] = "changed"
				if slices.Contains(test.input, "changed") {
					t.Error("projection aliases Native evidence")
				}
			}
		})
	}
}

func TestProjectCapabilityRequiresNamespaceMutationLeaseForReadiness(t *testing.T) {
	for _, test := range []struct {
		name     string
		features []string
		valid    bool
	}{
		{"admission-only", []string{"namespace-admission-v1"}, false},
		{"lease-only", []string{"namespace-mutation-lease-v1"}, false},
		{"both", []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			project := ProjectCapability{
				Alias: "project-one", Context: ContextBinding{Root: WireContextGuard("root"), Project: WireContextGuard("project")},
				ContractVersion: Version, Features: test.features,
				AdmissionGeneration: "generation-one", AdmissionOpen: true, Ready: true,
			}
			if err := project.Validate(); (err == nil) != test.valid {
				t.Errorf("ready project validation error = %v, want valid %t", err, test.valid)
			}
			project.Ready = false
			if err := project.Validate(); err != nil {
				t.Errorf("unready capability observation rejected: %v", err)
			}
		})
	}
}

func TestRootCapabilityRequiresNamespaceMutationLease(t *testing.T) {
	for _, test := range []struct {
		name     string
		features []string
		valid    bool
	}{
		{"admission-only", []string{"namespace-admission-v1"}, false},
		{"lease-only", []string{"namespace-mutation-lease-v1"}, false},
		{"both", []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := RootCapability{Root: WireContextGuard("root"), ContractVersion: Version, Features: test.features}
			if err := root.Validate(); (err == nil) != test.valid {
				t.Errorf("root validation error = %v, want valid %t", err, test.valid)
			}
		})
	}
}
