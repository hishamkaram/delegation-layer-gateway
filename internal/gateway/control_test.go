package gateway

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const fixtureResultSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func specFixture() domain.Digest             { return domain.Hash([]byte("canonical Delegate task request")) }
func hexFixture(digest domain.Digest) string { return hex.EncodeToString(digest[:]) }
func (f *dispatchFixture) possible(t *testing.T) domain.Correlation {
	t.Helper()
	operation := f.prepare(t)
	command, commandErr := admissionCommand(operation.Correlation, f.request)
	admit := dispatchMust(t, command, commandErr)
	setup := &controlledLink{snapshot: f.link.snapshot, store: f.store, now: f.link.now, nextRequest: 100000 + f.entropy.reads, respond: func(context.Context, protocol.Command) (protocol.Reply, error) {
		return protocol.Reply{Operation: protocol.Admit, Body: []byte(`{}`)}, nil
	}}
	reservation, reserveErr := setup.Reserve(t.Context(), f.destination.Device, operation.Correlation.Operation, admit)
	buffer := dispatchMust(t, reservation, reserveErr)
	transmission := buffer.Transmission()
	transmission.Now = f.now
	request, routeErr := buffer.Routing()
	route := dispatchMust(t, request, routeErr)
	route.Now = f.now
	_, err := f.store.MarkPossibleSendRouted(t.Context(), f.actor, transmission, route)
	dispatchOK(t, err)
	// An independent controlled peer completes setup admission. Application-link
	// counts below measure only the read/cancel/recovery operation under test.
	dispatchOK(t, buffer.ArmRouting(route))
	dispatchOK(t, buffer.Publish(t.Context(), func(context.Context) error { return nil }))
	_, awaitErr := buffer.Await(t.Context())
	dispatchOK(t, awaitErr)
	dispatchOK(t, buffer.Release(t.Context()))
	return operation.Correlation
}

func observationFixture(c domain.Correlation) protocol.TaskObservation {
	return protocol.TaskObservation{Task: protocol.TaskBinding{TaskID: string(c.Task), Context: protocol.ContextBinding{Root: string(c.Context.Root), Project: string(c.Context.Project)}, Origin: protocol.Origin{GatewayID: string(c.Gateway), AdmissionGeneration: string(c.AdmissionGeneration), OperationID: string(c.Operation), PrincipalRef: string(c.Owner.Principal), RequestSHA256: hexFixture(c.RequestDigest)}, SpecSHA256: hexFixture(specFixture())}, BriefSHA256: hexFixture(c.BriefDigest), Resolution: "existing", Admission: "admitted", Liveness: "running", Publication: "pending"}
}

func encodeReplyFixture[T any](operation protocol.Operation, value T) (protocol.Reply, error) {
	body, err := protocol.Encode(value, protocol.MaxFrameBytes)
	return protocol.Reply{Operation: operation, Body: body}, err
}

func (f *dispatchFixture) seedExisting(t *testing.T, c domain.Correlation, result bool) {
	t.Helper()
	observation := domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: specFixture()}
	if result {
		bytes, err := hex.DecodeString(fixtureResultSHA256)
		digest := dispatchMust(t, bytes, err)
		var resultHash domain.Digest
		copy(resultHash[:], digest)
		observation.Result = &domain.ResultDescriptor{Digest: resultHash, Bytes: 3}
	}
	_, err := f.store.ApplyResolution(t.Context(), domain.ValidatedResolution{ValidatedObservation: domain.ValidatedObservation{Correlation: c, Connection: f.link.snapshot.Connection, Credential: f.link.snapshot.Credential, Observation: observation, Now: f.now}, DurableRequest: true})
	dispatchOK(t, err)
}

func assertPublishedOperations(t *testing.T, link *controlledLink, want ...protocol.Operation) {
	t.Helper()
	got := make([]protocol.Operation, len(link.published))
	for i, command := range link.published {
		got[i] = command.Operation
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published operations %v, want %v", got, want)
	}
}

func TestReadOnlyControlsNeverAdmitResumeOrFence(t *testing.T) {
	cases := []struct {
		operation protocol.Operation
		call      func(*Service, context.Context, domain.Actor, domain.OperationID) (domain.OperationView, error)
	}{
		{protocol.Resolve, (*Service).Resolve}, {protocol.Status, (*Service).Status}, {protocol.Collect, (*Service).Collect},
	}
	for _, test := range cases {
		operation := test.operation
		t.Run(string(operation), func(t *testing.T) {
			f := newDispatchFixture(t)
			c := f.possible(t)
			reader := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskRead}}
			f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
				if command.Operation != operation {
					return protocol.Reply{}, errors.New("read-only control attempted another operation")
				}
				var request protocol.TaskControl
				if err := protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes); err != nil {
					return protocol.Reply{}, err
				}
				if request.Task.TaskID != string(c.Task) {
					return protocol.Reply{}, errors.New("read-only control changed task identity")
				}
				return encodeReplyFixture(operation, observationFixture(c))
			}
			view, err := test.call(f.service, t.Context(), reader, c.Operation)
			got := dispatchMust(t, view, err)
			if !got.Reserved || got.Correlation != c {
				t.Fatal("passive observation changed execution accounting or identity")
			}
			assertPublishedOperations(t, f.link, operation)
		})
	}
}

func TestUnsentCancelOnlyBindingSendsNothingAndCannotLaterDispatch(t *testing.T) {
	f := newDispatchFixture(t)
	prepared := f.prepare(t)
	canceller := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskCancel}}
	id := domain.CancellationID(strings.Repeat("a", 32))
	result, err := f.service.Cancel(t.Context(), canceller, prepared.Correlation.Operation, id)
	cancelled := dispatchMust(t, result, err)
	if !cancelled.DefinitelyUnsent || cancelled.ClosureConfirmed {
		t.Fatal("local unsent cancellation claimed Delegate execution closure")
	}
	result, err = f.service.Cancel(t.Context(), canceller, prepared.Correlation.Operation, id)
	if dispatchMust(t, result, err) != cancelled {
		t.Fatal("same cancellation ID changed local result")
	}
	if f.link.reserves != 0 || f.link.writes != 0 {
		t.Fatal("definitely-unsent cancellation contacted Delegate")
	}
	_, err = f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	dispatchCode(t, err, domain.Conflict)
	_, err = f.store.GetOperation(t.Context(), canceller, prepared.Correlation.Operation)
	dispatchCode(t, err, domain.Forbidden)
}

func TestCancelOnlyFencesBeforeCancelAndKeepsIdentityAcrossAckRetries(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	canceller := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskCancel}}
	id := domain.CancellationID(strings.Repeat("a", 32))
	terminated := false
	f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
		observation := observationFixture(c)
		if command.Operation == protocol.FenceAbsent {
			return encodeReplyFixture(command.Operation, observation)
		}
		if command.Operation != protocol.Cancel {
			return protocol.Reply{}, errors.New("cancel-only control attempted an admission")
		}
		var request protocol.Cancellation
		if err := protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes); err != nil {
			return protocol.Reply{}, err
		}
		if request.CancellationID != string(id) || request.Task.TaskID != string(c.Task) || request.Task.SpecSHA256 != hexFixture(specFixture()) {
			return protocol.Reply{}, errors.New("cancel changed immutable task/spec/cancellation identity")
		}
		observation.Stop = &protocol.StopObservation{RequestID: string(id), Requested: true, Terminated: terminated}
		observation.Liveness = "ended" // Ended/ACK alone is not canonical closure.
		return encodeReplyFixture(command.Operation, observation)
	}
	result, err := f.service.Cancel(t.Context(), canceller, c.Operation, id)
	if dispatchMust(t, result, err).ClosureConfirmed || !f.view(t, c.Operation).Reserved {
		t.Fatal("cancel acceptance or ended liveness proved execution closure")
	}
	terminated = true
	result, err = f.service.Cancel(t.Context(), canceller, c.Operation, id)
	if !dispatchMust(t, result, err).ClosureConfirmed || f.view(t, c.Operation).Reserved {
		t.Fatal("fresh matching stop termination did not settle closure")
	}
	assertPublishedOperations(t, f.link, protocol.FenceAbsent, protocol.Cancel, protocol.FenceAbsent, protocol.Cancel)
	_, err = f.store.GetOperation(t.Context(), canceller, c.Operation)
	dispatchCode(t, err, domain.Forbidden)
}

func TestRecoveryDispatchOnlyUsesCanonicalExistingSpecAndCurrentCeiling(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	f.seedExisting(t, c, false)
	dispatcher := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
		if command.Operation != protocol.ResumeExisting {
			return protocol.Reply{}, errors.New("recovery attempted a fresh admission")
		}
		var request protocol.TaskControl
		if err := protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes); err != nil {
			return protocol.Reply{}, err
		}
		if request.Task.TaskID != string(c.Task) || request.Task.SpecSHA256 != hexFixture(specFixture()) {
			return protocol.Reply{}, errors.New("recovery changed task/spec identity")
		}
		return encodeReplyFixture(command.Operation, observationFixture(c))
	}
	view, err := f.service.Recover(t.Context(), dispatcher, c.Operation)
	recovered := dispatchMust(t, view, err)
	if recovered.Correlation != c || recovered.Observation != nil || !recovered.Reserved {
		t.Fatal("dispatch-only recovery leaked status/results or changed identity/accounting")
	}
	assertPublishedOperations(t, f.link, protocol.ResumeExisting)
	_, err = f.service.Recover(t.Context(), domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskRead}}, c.Operation)
	dispatchCode(t, err, domain.Forbidden)
	_, err = f.store.GetOperation(t.Context(), dispatcher, c.Operation)
	dispatchCode(t, err, domain.Forbidden)
	f.link.beforeWrite = func(ctx context.Context) error {
		return f.store.PutGrant(ctx, domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination}, Scopes: f.actor.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 30}})
	}
	_, err = f.service.Recover(t.Context(), dispatcher, c.Operation)
	dispatchCode(t, err, domain.Forbidden)
	assertPublishedOperations(t, f.link, protocol.ResumeExisting)
	if !f.view(t, c.Operation).Reserved {
		t.Fatal("recovery ceiling refusal freed uncertain execution")
	}
}

func TestCancellationDoesNotAcceptAnotherRequestTermination(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	canceller := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskCancel}}
	f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
		observation := observationFixture(c)
		if command.Operation == protocol.Cancel {
			observation.Stop = &protocol.StopObservation{RequestID: strings.Repeat("b", 32), Requested: true, Terminated: true}
			observation.Liveness = "ended"
		}
		return encodeReplyFixture(command.Operation, observation)
	}
	result, err := f.service.Cancel(t.Context(), canceller, c.Operation, domain.CancellationID(strings.Repeat("a", 32)))
	if dispatchMust(t, result, err).ClosureConfirmed || !f.view(t, c.Operation).Reserved {
		t.Fatal("another cancellation's stop receipt proved this request's closure")
	}
	assertPublishedOperations(t, f.link, protocol.FenceAbsent, protocol.Cancel)
}

func TestCancelOnlyPermanentFenceRetainsKnownSpecAndSendsNoCancel(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	f.seedExisting(t, c, false)
	canceller := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskCancel}}
	f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
		if command.Operation != protocol.FenceAbsent {
			return protocol.Reply{}, errors.New("permanent absent fence was followed by another control")
		}
		observation := observationFixture(c)
		observation.Resolution = "permanently_refused"
		observation.Admission = "not-admitted"
		observation.Liveness = "undetermined"
		observation.Publication = "unknown"
		observation.Task.SpecSHA256 = ""
		observation.BriefSHA256 = ""
		return encodeReplyFixture(command.Operation, observation)
	}
	result, err := f.service.Cancel(t.Context(), canceller, c.Operation, domain.CancellationID(strings.Repeat("a", 32)))
	if !dispatchMust(t, result, err).ClosureConfirmed {
		t.Fatal("canonical permanent refusal did not settle uncertainty")
	}
	view := f.view(t, c.Operation)
	if view.Reserved || view.Observation.Kind != domain.Refused || view.Observation.SpecDigest != specFixture() {
		t.Fatal("refusal released the wrong identity or lost prior immutable spec")
	}
	assertPublishedOperations(t, f.link, protocol.FenceAbsent)
}

func TestResultReadRejectsConnectionGenerationSupersededDuringAwait(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	f.seedExisting(t, c, true)
	descriptor := protocol.Descriptor{SHA256: fixtureResultSHA256, Length: 3}
	f.link.respond = func(ctx context.Context, command protocol.Command) (protocol.Reply, error) {
		current, err := f.store.NextConnectionGeneration(ctx, f.link.snapshot.Credential, "replacement-after-scan", f.now)
		if err != nil {
			return protocol.Reply{}, err
		}
		if current.Counter != f.link.snapshot.Connection.Counter+1 {
			return protocol.Reply{}, errors.New("fixture did not supersede the persisted generation")
		}
		return encodeReplyFixture(command.Operation, protocol.ResultRange{Descriptor: descriptor, DataBase64: "YWJj", NextOffset: 3, EOF: true})
	}
	result, err := f.service.ReadResult(t.Context(), f.actor, c.Operation, descriptor, 0, 3)
	dispatchCode(t, err, domain.Conflict)
	if result.DataBase64 != "" {
		t.Fatal("superseded generation released accepted result bytes")
	}
}

func TestResultReadBindsAcceptedDescriptorAndValidatesBase64Cursor(t *testing.T) {
	cases := []struct {
		name   string
		change func(*protocol.ResultRange)
		valid  bool
	}{
		{"valid", func(*protocol.ResultRange) {}, true},
		{"descriptor", func(r *protocol.ResultRange) { r.Descriptor.SHA256 = strings.Repeat("f", 64) }, false},
		{"base64", func(r *protocol.ResultRange) { r.DataBase64 = "!!!!" }, false},
		{"offset", func(r *protocol.ResultRange) { r.Offset = 1 }, false},
		{"cursor", func(r *protocol.ResultRange) { r.NextOffset = 2 }, false},
		{"EOF", func(r *protocol.ResultRange) { r.EOF = false }, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newDispatchFixture(t)
			c := f.possible(t)
			f.seedExisting(t, c, true)
			descriptor := protocol.Descriptor{SHA256: fixtureResultSHA256, Length: 3}
			f.link.respond = func(_ context.Context, command protocol.Command) (protocol.Reply, error) {
				value := protocol.ResultRange{Descriptor: descriptor, Offset: 0, DataBase64: "YWJj", NextOffset: 3, EOF: true}
				test.change(&value)
				return encodeReplyFixture(command.Operation, value)
			}
			result, err := f.service.ReadResult(t.Context(), f.actor, c.Operation, descriptor, 0, 3)
			if test.valid {
				if dispatchMust(t, result, err).DataBase64 != "YWJj" {
					t.Fatal("verified range changed bytes")
				}
			} else {
				dispatchCode(t, err, domain.EvidenceInvalid)
				if result.DataBase64 != "" {
					t.Fatal("invalid range released bytes")
				}
			}
			assertPublishedOperations(t, f.link, protocol.ResultChunk)
		})
	}
}

func TestResultReadReauthorizesAfterScanAndRejectsUnacceptedDescriptor(t *testing.T) {
	f := newDispatchFixture(t)
	c := f.possible(t)
	f.seedExisting(t, c, true)
	descriptor := protocol.Descriptor{SHA256: fixtureResultSHA256, Length: 3}
	unaccepted := descriptor
	unaccepted.Length = 4
	if _, err := f.service.ReadResult(t.Context(), f.actor, c.Operation, unaccepted, 0, 3); err == nil {
		t.Fatal("unaccepted result descriptor launched a scan")
	}
	if f.link.reserves != 0 {
		t.Fatal("unaccepted descriptor reached the connector")
	}
	f.link.respond = func(ctx context.Context, command protocol.Command) (protocol.Reply, error) {
		if err := f.store.RevokeGrant(ctx, domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination}); err != nil {
			return protocol.Reply{}, err
		}
		return encodeReplyFixture(command.Operation, protocol.ResultRange{Descriptor: descriptor, DataBase64: "YWJj", NextOffset: 3, EOF: true})
	}
	result, err := f.service.ReadResult(t.Context(), f.actor, c.Operation, descriptor, 0, 3)
	dispatchCode(t, err, domain.NotFound)
	if result.DataBase64 != "" {
		t.Fatal("post-scan revocation released result bytes")
	}
}
