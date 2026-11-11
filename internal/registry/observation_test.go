package registry

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestRefusalRetainsKnownSpecWithoutOverwritingAcceptedEvidence(t *testing.T) {
	cases := []struct {
		name        string
		initial     domain.ObservationKind
		result      bool
		changedSpec bool
		accepted    bool
	}{
		{"partial preparation refused", domain.Existing, false, false, true},
		{"different spec", domain.Existing, false, true, false},
		{"accepted result", domain.Existing, true, false, false},
		{"canonical terminal", domain.Terminal, false, false, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.prepare(t, "refusal")
			_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
			requireOK(t, err)
			spec := domain.Hash([]byte("existing prepared spec"))
			observation := domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: test.initial, ObservedAt: f.now, SpecDigest: spec}}
			if test.initial == domain.Terminal {
				observation.Observation.Closure = canonicalClosureEvidence()
			}
			if test.result {
				observation.Observation.Result = &domain.ResultDescriptor{Digest: domain.Hash([]byte("accepted")), Bytes: 8}
			}
			requireOK(t, f.store.RecordObservation(t.Context(), observation))
			observation.Observation = domain.DelegateObservation{Kind: domain.Refused, ObservedAt: f.now}
			if test.changedSpec {
				observation.Observation.SpecDigest = domain.Hash([]byte("different"))
			}
			view, err := f.store.ApplyResolution(t.Context(), domain.ValidatedResolution{ValidatedObservation: observation})
			if !test.accepted {
				requireCode(t, err, domain.Conflict)
				return
			}
			got := must(t, view, err)
			if got.Reserved || got.Delivery != domain.Resolved || got.Observation.Kind != domain.Refused || got.Observation.SpecDigest != spec || got.Observation.Result != nil {
				t.Fatal("canonical refusal lost immutable identity or fabricated an accepted outcome")
			}
		})
	}
}

func TestClosurePendingRetainsQuotaAndCanonicalProofRemainsImmutable(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "closure")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireOK(t, err)
	observation := domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("spec")), ClosurePending: domain.ClosureOwnerBusy}}
	requireOK(t, f.store.RecordObservation(t.Context(), observation))
	view, err := f.store.GetOperation(t.Context(), f.actor, c.Operation)
	pending := must(t, view, err)
	if !pending.Reserved || pending.Observation.ClosurePending != domain.ClosureOwnerBusy {
		t.Fatal("pending closure released capacity or lost its dated reason")
	}
	observation.Observation.Kind = domain.Terminal
	if err = f.store.RecordObservation(t.Context(), observation); err == nil {
		t.Fatal("pending closure was accepted as terminal")
	}
	proof := &domain.ClosureEvidence{Kind: domain.ClosureRegisteredNative, Reference: domain.Hash([]byte("fsynced canonical owner closure"))}
	observation.Observation.ClosurePending = domain.NoClosurePending
	observation.Observation.Closure = proof
	requireOK(t, f.store.RecordObservation(t.Context(), observation))
	view, err = f.store.GetOperation(t.Context(), f.actor, c.Operation)
	terminal := must(t, view, err)
	if terminal.Reserved || terminal.Observation.Closure == nil || *terminal.Observation.Closure != *proof {
		t.Fatal("canonical closure proof did not settle the reservation")
	}
	observation.Observation.Closure = nil
	if observeErr := f.store.RecordObservation(t.Context(), observation); observeErr == nil {
		t.Fatal("new terminal observation inherited proof before current evidence validation")
	}
	view, err = f.store.GetOperation(t.Context(), f.actor, c.Operation)
	repeated := must(t, view, err)
	if repeated.Observation.Closure == nil || *repeated.Observation.Closure != *proof {
		t.Fatal("later observation erased immutable closure reference")
	}
	observation.Observation.Closure = proof
	requireOK(t, f.store.RecordObservation(t.Context(), observation))
	observation.Observation.Closure = &domain.ClosureEvidence{Kind: proof.Kind, Reference: domain.Hash([]byte("different owner reference"))}
	requireCode(t, f.store.RecordObservation(t.Context(), observation), domain.Conflict)
}
