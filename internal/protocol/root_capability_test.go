package protocol

import "testing"

func TestRootCapabilityKeepsNamespaceAndProjectEvidenceDistinct(t *testing.T) {
	base := RootCapability{Root: WireContextGuard("private-root"), ContractVersion: Version, Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}}
	if base.Validate() != nil {
		t.Fatal("supported root without registered namespace rejected")
	}
	for _, variant := range []string{"missing-root", "feature", "version", "missing-origin", "unexpected-origin", "bad-origin"} {
		t.Run(variant, func(t *testing.T) {
			value := base
			switch variant {
			case "missing-root":
				value.Root = ""
			case "feature":
				value.Features = nil
			case "version":
				value.ContractVersion = 0
			case "missing-origin":
				value.OriginRegistered = true
			case "unexpected-origin":
				value.Origin = &OriginStateReport{GatewayID: "gateway", RecoveryID: "recovery", Generation: "generation"}
			case "bad-origin":
				value.OriginRegistered = true
				value.Origin = &OriginStateReport{}
			}
			if value.Validate() == nil {
				t.Fatal("dishonest or unsupported root proof accepted")
			}
		})
	}
	base.OriginRegistered = true
	base.Origin = &OriginStateReport{GatewayID: "gateway", RecoveryID: "recovery", Generation: "generation", AdmissionOpen: true}
	if base.Validate() != nil {
		t.Fatal("registered namespace rejected")
	}
}
