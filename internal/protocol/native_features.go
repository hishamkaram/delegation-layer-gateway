package protocol

import "slices"

const (
	FeatureNamespaceAdmission     = "namespace-admission-v1"
	FeatureNamespaceMutationLease = "namespace-mutation-lease-v1"
)

// NativeFeaturesCompatible is the minimum Native root contract for guarded work.
func NativeFeaturesCompatible(features []string) bool {
	return slices.Contains(features, FeatureNamespaceAdmission) && slices.Contains(features, FeatureNamespaceMutationLease)
}

// RecognizedNativeFeatures projects actual evidence in a stable wire order.
func RecognizedNativeFeatures(features []string) []string {
	var result []string
	for _, feature := range [...]string{FeatureNamespaceAdmission, FeatureNamespaceMutationLease} {
		if slices.Contains(features, feature) {
			result = append(result, feature)
		}
	}
	return result
}
