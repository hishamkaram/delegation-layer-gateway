package gateway

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type protectedSelectionInspector struct {
	TargetedCapabilities
	observation protocol.SelectionObservation
}

func (p protectedSelectionInspector) PrepareSelection(_ context.Context, _ domain.Actor, _ domain.DeviceID, request protocol.SelectionRequest) (protocol.SelectionObservation, error) {
	observation := p.observation
	observation.Selection = request.Selection
	return observation, nil
}

func protectedFixture(t *testing.T) (*dispatchFixture, SelectedPreparation, protocol.SelectionObservation) {
	t.Helper()
	f := newDispatchFixture(t)
	dispatchOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, domain.OwnerPolicy{Enabled: true, Scopes: f.actor.Scopes, MaxDevices: 1}))
	// Seed the pre-existing device's immutable ownership in the real fixture DB.
	db, err := sql.Open("sqlite", f.path)
	dispatchOK(t, err)
	t.Cleanup(func() { dispatchOK(t, db.Close()) })
	_, err = db.ExecContext(t.Context(), "INSERT INTO device_owners(device,principal) VALUES(?,?)", f.destination.Device, f.actor.Principal)
	dispatchOK(t, err)
	input, observed := selectedPreparationExample()
	observed.ObservedAt = f.now
	observed.AdmissionGeneration = f.link.snapshot.Capabilities.Projects[0].AdmissionGeneration
	f.service.targeted = protectedSelectionInspector{observation: observed}
	f.link.snapshot.WireVersion = protocol.WireVersion2
	f.link.snapshot.CapabilitiesV2 = &protocol.CapabilityReportV2{ObservedAt: f.now, Root: &protocol.RootCapability{Root: observed.Context.Root, ContractVersion: 1, Features: append(observed.Features, protocol.WorkspaceFeature, protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease), OriginRegistered: true, Origin: &protocol.OriginStateReport{GatewayID: string(f.service.gateway), RecoveryID: "recovery", Generation: observed.AdmissionGeneration, AdmissionOpen: true}}}
	return f, input, observed
}

func protectedPath(character string, components int) string {
	parts := make([]string, components)
	for i := range parts {
		parts[i] = strings.Repeat(character, 255)
	}
	return strings.Join(parts, "/")
}

func TestProtectedPreflightPreparation(t *testing.T) {
	for _, kind := range []domain.RequestKind{domain.RequestKindDispatch, domain.RequestKindContinuation} {
		for _, quoted := range []bool{false, true} {
			name, path := "ordinary-4095-bytes", protectedPath("p", 16)
			if quoted {
				name, path = "quoted-3071-bytes", protectedPath(`"`, 12)
			}
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				checkProtectedPreparation(t, kind, quoted, path)
			})
		}
	}
}

func checkProtectedPreparation(t *testing.T, kind domain.RequestKind, quoted bool, path string) {
	t.Helper()
	f, input, _ := protectedFixture(t)
	var parent domain.PreparedOperation
	if kind == domain.RequestKindContinuation {
		parent = protectedParent(t, f, input)
	}
	input.Selection.RelativePath = path
	if input.validate() != nil {
		t.Fatal("counterexample is not a valid selector")
	}
	prepared, err := prepareProtected(t, f, input, parent)
	if quoted {
		if !errors.Is(err, protocol.ErrTooLarge) {
			t.Fatalf("uncontrollable preparation should fail permanently before persistence: %v", err)
		}
	} else {
		dispatchOK(t, err)
		_, err = f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
		if !errors.Is(err, f.link.awaitError) || f.link.writes != 1 {
			t.Fatalf("ordinary long selector did not reach its one dispatch: %v", err)
		}
	}
	assertProtectedPreparationCount(t, f, kind, quoted)
}

func prepareProtected(t *testing.T, f *dispatchFixture, input SelectedPreparation, parent domain.PreparedOperation) (domain.PreparedOperation, error) {
	t.Helper()
	if parent.Correlation.Operation == "" {
		return f.service.PrepareSelected(t.Context(), f.actor, input)
	}
	return f.service.PrepareContinuation(t.Context(), f.actor, ContinuationPreparation{Device: input.Device, RequestID: domain.RequestID(strings.Repeat("b", 32)), Predecessor: parent.Correlation.Operation, Selection: &input.Selection, Overrides: domain.ContinuationOverrides{Version: 1, Budget: "1h"}})
}

func protectedParent(t *testing.T, f *dispatchFixture, input SelectedPreparation) domain.PreparedOperation {
	t.Helper()
	parent, err := f.service.PrepareSelected(t.Context(), f.actor, input)
	dispatchOK(t, err)
	f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
		var admission protocol.Admission
		if decodeErr := protocol.DecodeStrict(command.Body, &admission, protocol.MaxFrameBytes); decodeErr != nil {
			return protocol.Reply{}, decodeErr
		}
		admission.Task.SpecSHA256 = domain.Hash([]byte("parent spec")).Hex()
		observation := protocol.TaskObservation{Task: admission.Task, BriefSHA256: domain.Hash([]byte(admission.Brief)).Hex(), Resolution: "existing", Admission: "admitted", Liveness: "running", Publication: "pending"}
		return protocol.Reply{Operation: command.Operation, Body: protectedPayload(t, observation)}, nil
	}
	_, err = f.service.Dispatch(t.Context(), f.actor, parent.Correlation.Operation)
	dispatchOK(t, err)
	f.link.respond = nil
	f.link.reserves, f.link.writes, f.link.awaits, f.link.releases = 0, 0, 0, 0
	return parent
}

func assertProtectedPreparationCount(t *testing.T, f *dispatchFixture, kind domain.RequestKind, rejected bool) {
	t.Helper()
	page, err := f.store.ListOperations(t.Context(), f.actor, domain.OperationPageRequest{})
	dispatchOK(t, err)
	want := 0
	if kind == domain.RequestKindContinuation {
		want++
	}
	if !rejected {
		want++
	}
	if len(page.Items) != want || rejected && (f.link.reserves != 0 || f.link.writes != 0) {
		t.Fatal("rejected preparation changed durable rows or touched transport")
	}
}

// A Store-seeded draft represents a valid record written before this preflight
// existed. The public preparation retry must still resolve its original key.
func TestProtectedPreflightOldDraftReplayCannotFirstSend(t *testing.T) {
	f, input, observed := protectedFixture(t)
	plan := protectedDraft(t, f, input, observed, protectedPath(`"`, 12))
	original, err := f.store.Prepare(t.Context(), f.actor, plan)
	dispatchOK(t, err)
	input.Selection.RelativePath = plan.Correlation.Route.RelativePath
	f.entropy.deny, f.service.targeted = true, nil
	replay, err := f.service.PrepareSelected(t.Context(), f.actor, input)
	if err != nil || replay != original {
		t.Fatalf("existing key lost replay precedence: %v", err)
	}
	_, err = f.service.Dispatch(t.Context(), f.actor, original.Correlation.Operation)
	if !errors.Is(err, protocol.ErrTooLarge) {
		t.Fatalf("older uncontrollable draft reached first send: %v", err)
	}
	assertUnsent(t, f, original.Correlation.Operation)
	if f.link.reserves != 0 {
		t.Fatal("old draft reserved transport before size rejection")
	}
	view, err := f.store.GetForDispatch(t.Context(), f.actor, original.Correlation.Operation, f.now)
	dispatchOK(t, err)
	if view.Request != plan.Request || view.Operation.Correlation != original.Correlation {
		t.Fatal("size rejection rewrote historical intent")
	}
}

func protectedDraft(t *testing.T, f *dispatchFixture, input SelectedPreparation, observed protocol.SelectionObservation, path string) domain.Preparation {
	t.Helper()
	// Build a short valid draft, then use domain APIs to represent the historical
	// long-path record without calling the new preparation preflight.
	fingerprint, err := domain.DispatchInputDigestV1(input.Device, domain.RequestSelector{ScopeID: input.Selection.ScopeID, RelativePath: input.Selection.RelativePath}, input.Request.Options(), domain.Hash([]byte(input.Request.Brief)))
	dispatchOK(t, err)
	plan, err := f.service.newSelectedPreparation(f.actor, input, observed, fingerprint)
	dispatchOK(t, err)
	plan.Correlation.Route.RelativePath = path
	plan.Correlation.Route.InputDigest, err = domain.DispatchInputDigestV1(input.Device, domain.RequestSelector{ScopeID: input.Selection.ScopeID, RelativePath: path}, input.Request.Options(), domain.Hash([]byte(input.Request.Brief)))
	dispatchOK(t, err)
	plan.Correlation.RequestDigest, err = domain.RequestDigest(plan.Correlation, plan.Request)
	dispatchOK(t, err)
	return plan
}

func TestProtectedPreflightIncludesCompletedReply(t *testing.T) {
	f, input, observed := protectedFixture(t)
	plan := protectedDraft(t, f, input, observed, protectedPath(`"`, 9))
	command, err := admissionCommand(plan.Correlation, plan.Request)
	dispatchOK(t, err)
	task, err := binding(plan.Correlation, domain.Hash([]byte("future spec")))
	dispatchOK(t, err)
	control := protocol.Command{Operation: protocol.Cancel, Project: command.Project, Body: protectedPayload(t, protocol.Cancellation{Task: task, CancellationID: strings.Repeat("c", 32)})}
	request := protocol.Frame{Version: 2, Type: protocol.Request, RequestID: "g:18446744073709551615", Generation: protocol.Generation{BootEpoch: strings.Repeat("b", 128), Counter: math.MaxUint64}, OperationID: string(plan.Correlation.Operation), TTLMillis: 30000, Payload: protectedPayload(t, control)}
	requestBytes, err := protocol.EncodeFrameVersion(request, 2)
	dispatchOK(t, err)
	observation := protocol.TaskObservation{Task: task, BriefSHA256: strings.Repeat("f", 64), Resolution: "existing", Admission: "not-admitted", Liveness: "undetermined", Publication: "committed", Verdict: "committed", Result: &protocol.Descriptor{SHA256: strings.Repeat("d", 64), Length: math.MaxInt64}, Stop: &protocol.StopObservation{RequestID: strings.Repeat("c", 32)}, ExecutionClosure: &protocol.ExecutionClosure{Kind: "unregistered-recovered", ReferenceSHA256: strings.Repeat("e", 64)}}
	dispatchOK(t, observation.Validate())
	reply := protocol.ControlResponse{Completion: protocol.ControlCompletion{ProcessBoot: strings.Repeat("a", 32), Call: protocol.ControlCall{Generation: request.Generation, RequestID: request.RequestID, OperationID: request.OperationID, Operation: protocol.Cancel, RequestSHA256: domain.Hash(request.Payload).Hex()}, Disposition: protocol.ControlPending}, Reply: protocol.Reply{Operation: protocol.Cancel, Body: protectedPayload(t, observation)}}
	dispatchOK(t, reply.Validate())
	request.Type, request.Payload = protocol.Response, protectedPayload(t, reply)
	replyBytes, err := protocol.EncodeFrameVersion(request, 2)
	dispatchOK(t, err)
	t.Logf("request=%d completed reply=%d", len(requestBytes), len(replyBytes))
	if len(requestBytes) > 16<<10 || len(replyBytes) <= 16<<10 {
		t.Fatal("counterexample must isolate a fitting request and overflowing completed reply")
	}
	if err = preflight(command, string(plan.Correlation.Operation)); !errors.Is(err, protocol.ErrTooLarge) {
		t.Fatalf("request-only check accepted an oversized completion receipt: %v", err)
	}
}

func protectedPayload[T any](t *testing.T, value T) []byte {
	t.Helper()
	data, err := protocol.Encode(value, protocol.MaxFrameBytes)
	dispatchOK(t, err)
	return data
}
