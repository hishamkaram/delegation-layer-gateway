package domain

import (
	"strings"
	"testing"
	"time"
)

func TestClosureMetadataEnforcesEvidenceAndPendingPartitions(t *testing.T) {
	now := time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)
	proof := &ClosureEvidence{Kind: ClosureRegisteredNative, Reference: Hash([]byte("canonical owner reference"))}
	cases := []struct {
		name        string
		observation DelegateObservation
		valid       bool
	}{
		{"dated pending", DelegateObservation{Kind: Existing, ClosurePending: ClosureOwnerBusy}, true},
		{"bare terminal", DelegateObservation{Kind: Terminal}, false},
		{"terminal stop", DelegateObservation{Kind: Terminal, ConfirmedStop: &StopConfirmation{Cancellation: CancellationID(strings.Repeat("a", 32))}}, true},
		{"proof and stop", DelegateObservation{Kind: Terminal, Closure: proof, ConfirmedStop: &StopConfirmation{Cancellation: CancellationID(strings.Repeat("a", 32))}}, true},
		{"empty stop", DelegateObservation{Kind: Terminal, ConfirmedStop: &StopConfirmation{}}, false},
		{"invalid stop", DelegateObservation{Kind: Terminal, ConfirmedStop: &StopConfirmation{Cancellation: "guessed"}}, false},
		{"stop on existing", DelegateObservation{Kind: Existing, ConfirmedStop: &StopConfirmation{Cancellation: CancellationID(strings.Repeat("a", 32))}}, false},
		{"stop and pending", DelegateObservation{Kind: Terminal, ConfirmedStop: &StopConfirmation{Cancellation: CancellationID(strings.Repeat("a", 32))}, ClosurePending: ClosureOwnerBusy}, false},
		{"terminal proof", DelegateObservation{Kind: Terminal, Closure: proof}, true},
		{"proof on existing", DelegateObservation{Kind: Existing, Closure: proof}, false},
		{"pending terminal", DelegateObservation{Kind: Terminal, ClosurePending: ClosureUnproven}, false},
		{"pending refusal", DelegateObservation{Kind: Refused, ClosurePending: ClosureMissingOwner}, false},
		{"proof and pending", DelegateObservation{Kind: Terminal, Closure: proof, ClosurePending: ClosurePartialEvidence}, false},
		{"unknown pending kind", DelegateObservation{Kind: Existing, ClosurePending: "guessed"}, false},
		{"unknown proof kind", DelegateObservation{Kind: Terminal, Closure: &ClosureEvidence{Kind: "guessed", Reference: proof.Reference}}, false},
		{"missing proof reference", DelegateObservation{Kind: Terminal, Closure: &ClosureEvidence{Kind: ClosureNeverStarted}}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observation := test.observation
			observation.ObservedAt = now
			observation.SpecDigest = Hash([]byte("spec"))
			err := observation.Validate(now)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, got %v", test.valid, err)
			}
		})
	}
}
