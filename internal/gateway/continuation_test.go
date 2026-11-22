package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func selectedPreparationExample() (SelectedPreparation, protocol.SelectionObservation) {
	selection := protocol.FileSelection{ScopeID: "workspace", RelativePath: "repo"}
	input := SelectedPreparation{Device: "device", RequestID: domain.RequestID(strings.Repeat("a", 32)), Selection: selection, Request: domain.FrozenRequest{Native: domain.NativeOptions{Version: 1, Provider: "provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}}, Brief: "predecessor brief"}}
	observed := protocol.SelectionObservation{Selection: selection, Context: protocol.ContextBinding{Root: protocol.WireContextGuard("root"), Project: protocol.WireContextGuard("project")}, WorkspaceGuard: protocol.WireContextGuard("workspace"), AdmissionOpen: true, AdmissionGeneration: "generation", Features: []string{protocol.FeatureNativeOptions, protocol.FeatureProjectHashGuard, protocol.FeatureOriginBinding, protocol.FeatureGuardedContinuation}}
	return input, observed
}

func TestSelectedPreparationRequiresImmutableOriginCapability(t *testing.T) {
	input, observed := selectedPreparationExample()
	observed.ObservedAt = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	request := protocol.SelectionRequest{Selection: input.Selection}
	if err := validatePreparationSelection(observed, request); err != nil {
		t.Fatal(err)
	}
	observed.Features = []string{protocol.FeatureNativeOptions, protocol.FeatureProjectHashGuard}
	var failure *RemoteError
	if err := validatePreparationSelection(observed, request); !errors.As(err, &failure) || failure.Failure.Code != "delegate_upgrade_required" {
		t.Fatalf("missing immutable Origin support did not fail closed: %v", err)
	}
}

func selectedPredecessor(t *testing.T, f *dispatchFixture) (domain.RecoveryView, protocol.SelectionObservation) {
	t.Helper()
	input, observed := selectedPreparationExample()
	fingerprint, err := domain.DispatchInputDigestV1(input.Device, domain.RequestSelector{ScopeID: input.Selection.ScopeID, RelativePath: input.Selection.RelativePath}, input.Request.Options(), domain.Hash([]byte(input.Request.Brief)))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.service.newSelectedPreparation(f.actor, input, observed, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Correlation.RequestVersion != 4 || plan.Correlation.Kind != domain.RequestKindDispatch || !plan.Request.BriefPresent || !plan.Correlation.BriefPresent {
		t.Fatal("selected admission did not capture compact caller intent")
	}
	return domain.RecoveryView{Correlation: plan.Correlation, SpecDigest: domain.Hash([]byte("Native predecessor spec"))}, observed
}

func TestContinuationPreparationCommitsParentWithoutInventingInheritedOptions(t *testing.T) {
	f := newDispatchFixture(t)
	parent, observed := selectedPredecessor(t, f)
	input := ContinuationPreparation{RequestID: domain.RequestID(strings.Repeat("b", 32)), Device: "device", Predecessor: parent.Correlation.Operation, Overrides: domain.ContinuationOverrides{Version: 1}}
	request, selector, err := input.request()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := domain.ContinuationInputDigestV1(input.Device, input.Predecessor, selector, false, input.Overrides, false, domain.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.service.newContinuation(f.actor, input, request, parent, observed, fingerprint, domain.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	assertContinuationPreparation(t, plan, parent, request)
}

func assertContinuationPreparation(t *testing.T, plan domain.Preparation, parent domain.RecoveryView, request domain.FrozenRequest) {
	t.Helper()
	c := plan.Correlation
	if c.Kind != domain.RequestKindContinuation || c.RequestVersion != 4 || c.BriefPresent || c.BriefDigest != (domain.Digest{}) || c.Task == parent.Correlation.Task || c.Operation == parent.Correlation.Operation || request.Options() != (domain.ExecutionOptions{}) {
		t.Fatal("continuation invented defaults, a requested brief or reused identity")
	}
	origin, err := protocol.OriginFromCorrelation(c)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := domain.ParseOriginBinding(origin.Binding)
	if err != nil || restored != c {
		t.Fatal("successor commitment did not independently restore its correlation")
	}
	assertContinuationCommand(t, c, request, parent)
}

func assertContinuationCommand(t *testing.T, c domain.Correlation, request domain.FrozenRequest, parent domain.RecoveryView) {
	t.Helper()
	command, err := continuationCommand(c, request, parent)
	if err != nil {
		t.Fatal(err)
	}
	var body protocol.Continuation
	if protocol.DecodeStrict(command.Body, &body, protocol.MaxFrameBytes) != nil || body.Validate() != nil || command.Operation != protocol.Continue || body.BriefPresent || body.Brief != "" || body.Predecessor.TaskID != string(parent.Correlation.Task) || body.Predecessor.SpecSHA256 != parent.SpecDigest.Hex() || body.Overrides != (protocol.ContinuationOverrides{Version: 1}) {
		t.Fatal("wire continuation changed parent identity or Native inheritance")
	}
	parent.SpecDigest = domain.Hash([]byte("different Native spec"))
	if _, err = continuationCommand(c, request, parent); err == nil {
		t.Fatal("changed predecessor was admitted under an old successor commitment")
	}
	if _, err = admissionCommand(c, request); err == nil {
		t.Fatal("continuation fell back to ordinary dispatch")
	}
}

type continuationReplayStore struct {
	DispatchStore
	saved domain.PreparedOperation
	input domain.Digest
	reads int
}

func (s *continuationReplayStore) LookupPreparation(_ context.Context, _ domain.Actor, _ domain.DeviceID, _ domain.RequestID, digest domain.Digest) (domain.PreparedOperation, bool, error) {
	s.input = digest
	return s.saved, true, nil
}

func (s *continuationReplayStore) GetForContinuation(context.Context, domain.Actor, domain.OperationID) (domain.RecoveryView, error) {
	s.reads++
	return domain.RecoveryView{}, errors.New("predecessor is unavailable")
}

func TestContinuationReplayPrecedesMissingParentNetworkAndEntropy(t *testing.T) {
	f := newDispatchFixture(t)
	store := &continuationReplayStore{DispatchStore: f.store, saved: domain.PreparedOperation{Correlation: domain.Correlation{Operation: "original-successor", Task: domain.TaskID(strings.Repeat("c", 32))}}}
	f.service.store = store
	f.service.targeted = nil
	f.entropy.deny = true
	input := ContinuationPreparation{RequestID: domain.RequestID(strings.Repeat("b", 32)), Device: "device", Predecessor: "missing-predecessor", Overrides: domain.ContinuationOverrides{Version: 1}}
	got, err := f.service.PrepareContinuation(t.Context(), f.actor, input)
	if err != nil || got != store.saved || store.reads != 0 || f.entropy.reads != 0 || f.link.reserves != 0 || store.input == (domain.Digest{}) {
		t.Fatalf("replay consulted missing dependencies or allocated replacement work: %+v, %v", got, err)
	}
}
