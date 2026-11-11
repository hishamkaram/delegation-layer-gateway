package recovery_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
)

func prepareDrainTask(t *testing.T, f *recoveryTLS) domain.NativeTaskKey {
	t.Helper()
	f.approved(t)
	p := f.advance(t, protocol.ContextInspect, protocol.OriginReopen, protocol.ContextInspect, protocol.ContextInspect)
	principal, err := f.store.ResolvePrincipal(f.ctx, domain.ExternalSubject{Issuer: "https://issuer.example", Subject: "operator"})
	recoveryOK(t, err)
	scopes := domain.ScopeSet{domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}
	recoveryOK(t, f.store.PutGrant(f.ctx, domain.Grant{Key: domain.GrantKey{Principal: principal.ID, Destination: f.lookup.Route}, Scopes: scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"fixture"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 30}}))
	request := domain.FrozenRequest{Provider: "fixture", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: domain.ReadOnly, BudgetSeconds: 30, Brief: "controlled task"}
	correlation := domain.Correlation{Operation: "drain-operation", Task: domain.TaskID(strings.Repeat("a", 32)), Gateway: f.id, AdmissionGeneration: p.Generation, Owner: domain.OperationOwner{Kind: domain.Owned, Principal: principal.ID}, Destination: f.lookup.Route, Context: f.lookup.ExpectedContext, BriefDigest: domain.Hash([]byte(request.Brief))}
	correlation.RequestDigest, err = domain.RequestDigest(correlation, request)
	recoveryOK(t, err)
	_, err = f.store.Prepare(f.ctx, domain.Actor{Principal: principal.ID, Scopes: scopes}, domain.Preparation{Correlation: correlation, Request: request, Now: f.now})
	recoveryOK(t, err)
	return domain.NativeTaskKey{Device: f.lookup.Route.Device, Root: f.lookup.ExpectedContext.Root, Task: correlation.Task}
}

func TestAdministrativeCancelLearnsSpecAndRetainsHoldUntilClosure(t *testing.T) {
	f := newRecoveryTLS(t)
	key := prepareDrainTask(t, f)
	drainer, err := recovery.NewDrainer(f.store, f.service, func() time.Time { return f.now })
	recoveryOK(t, err)
	view, err := f.store.GetAdministrativeTask(f.ctx, key)
	recoveryOK(t, err)
	if view.Binding.SpecDigest != (domain.Digest{}) {
		t.Fatal("fixture must begin without a learned native spec")
	}
	cancellation := domain.CancellationID(strings.Repeat("c", 32))
	peer := drainReply{original: view, cancellation: cancellation}
	f.taskResponse = peer.response
	input := recovery.DrainRequest{Key: key, Route: f.lookup.Route, Action: domain.AdministrativeCancel, Cancellation: cancellation}
	var observed domain.AdministrativeTaskView
	recoveryOK(t, runRecoveryCall(t, f, []protocol.Operation{protocol.FenceAbsent, protocol.Cancel}, func(ctx context.Context) error {
		var callErr error
		observed, callErr = drainer.Control(ctx, input)
		return callErr
	}, false))
	if !observed.Reserved || observed.Cancellation != cancellation || observed.Observation == nil || observed.Observation.Kind != domain.Existing || observed.Observation.ConfirmedStop != nil {
		t.Fatal("asynchronous cancellation released a hold or changed its intent")
	}
	peer.closed = true
	recoveryOK(t, runRecoveryCall(t, f, []protocol.Operation{protocol.FenceAbsent}, func(ctx context.Context) error {
		var callErr error
		observed, callErr = drainer.Control(ctx, input)
		return callErr
	}, false))
	if observed.Reserved || observed.Observation == nil || observed.Observation.Kind != domain.Terminal || observed.Cancellation != cancellation {
		t.Fatal("matching canonical closure did not release the original hold")
	}
}

type drainReply struct {
	original     domain.AdministrativeTaskView
	cancellation domain.CancellationID
	closed       bool
}

func (p *drainReply) response(t *testing.T, command protocol.Command) protocol.TaskObservation {
	t.Helper()
	var task protocol.TaskBinding
	if command.Operation == protocol.Cancel {
		var input protocol.Cancellation
		recoveryOK(t, protocol.DecodeStrict(command.Body, &input, protocol.MaxFrameBytes))
		if input.CancellationID != string(p.cancellation) || input.Task.SpecSHA256 != strings.Repeat("d", 64) {
			t.Fatal("cancel did not retain the original identity and learned spec")
		}
		task = input.Task
	} else {
		var input protocol.TaskControl
		recoveryOK(t, protocol.DecodeStrict(command.Body, &input, protocol.MaxFrameBytes))
		task = input.Task
	}
	task.SpecSHA256 = strings.Repeat("d", 64)
	observation := protocol.TaskObservation{Task: task, BriefSHA256: hex.EncodeToString(p.original.Correlation.BriefDigest[:]), Resolution: "existing", Admission: "admitted", Liveness: "running", Publication: "pending"}
	if command.Operation == protocol.Cancel {
		observation.Stop = &protocol.StopObservation{RequestID: string(p.cancellation), Requested: true}
	}
	if p.closed {
		observation.Liveness = "ended"
		observation.ExecutionClosure = &protocol.ExecutionClosure{Kind: "registered-native", ReferenceSHA256: strings.Repeat("e", 64)}
	}
	return observation
}

func TestAdministrativeDrainRejectsForeignOriginOverMutualTLS(t *testing.T) {
	f := newRecoveryTLS(t)
	key := prepareDrainTask(t, f)
	drainer, err := recovery.NewDrainer(f.store, f.service, func() time.Time { return f.now })
	recoveryOK(t, err)
	f.taskResponse = func(t *testing.T, command protocol.Command) protocol.TaskObservation {
		var input protocol.TaskControl
		recoveryOK(t, protocol.DecodeStrict(command.Body, &input, protocol.MaxFrameBytes))
		input.Task.Origin.OperationID = "foreign-operation"
		return protocol.TaskObservation{Task: input.Task, Resolution: "absent", Admission: "unknown", Liveness: "undetermined", Publication: "unknown"}
	}
	err = runRecoveryCall(t, f, []protocol.Operation{protocol.Resolve}, func(ctx context.Context) error {
		_, callErr := drainer.Control(ctx, recovery.DrainRequest{Key: key, Route: f.lookup.Route, Action: domain.AdministrativeResolve})
		return callErr
	}, false)
	var rejected *domain.Error
	if !errors.As(err, &rejected) || rejected.Code != domain.EvidenceInvalid {
		t.Fatalf("foreign observation accepted: %v", err)
	}
	view, err := f.store.GetAdministrativeTask(f.ctx, key)
	recoveryOK(t, err)
	if view.Observation != nil {
		t.Fatal("foreign reply changed the stored observation")
	}
}

func prepareAcceptedTerminalDrain(t *testing.T, f *recoveryTLS) (domain.NativeTaskKey, domain.AdministrativeTaskView, domain.ResultDescriptor) {
	t.Helper()
	key := prepareDrainTask(t, f)
	view, err := f.store.GetAdministrativeTask(f.ctx, key)
	recoveryOK(t, err)
	var spec, closure domain.Digest
	for i := range spec {
		spec[i], closure[i] = 0xdd, 0xee
	}
	result := domain.ResultDescriptor{Digest: domain.Hash([]byte("private supervisor acceptance passed")), Bytes: 36}
	view, err = f.store.RecordAdministrativeObservation(f.ctx, domain.AdministrativeObservation{
		Check:       domain.AdministrativeDrainCheck{Key: key, Destination: f.lookup.Route, Action: domain.AdministrativeResolve, Credential: f.ref, Connection: f.peer.Generation(), Now: f.now},
		Binding:     view.Binding,
		Observation: domain.DelegateObservation{Kind: domain.Terminal, ObservedAt: f.now, SpecDigest: spec, Result: &result, Closure: &domain.ClosureEvidence{Kind: domain.ClosureRegisteredNative, Reference: closure}},
	})
	recoveryOK(t, err)
	if view.Reserved || view.Delivery != domain.Resolved || view.Observation == nil || view.Observation.Kind != domain.Terminal {
		t.Fatal("fixture did not establish an accepted terminal observation")
	}
	return key, view, result
}

func TestAdministrativeResolveAcceptedTerminalWithAdvancingClock(t *testing.T) {
	f := newRecoveryTLS(t)
	key, view, result := prepareAcceptedTerminalDrain(t, f)
	original := view.Binding
	peer := drainReply{original: view, closed: true}
	f.taskResponse = func(t *testing.T, command protocol.Command) protocol.TaskObservation {
		observation := peer.response(t, command)
		observation.Publication, observation.Verdict = "committed", "committed"
		observation.Result = &protocol.Descriptor{SHA256: hex.EncodeToString(result.Digest[:]), Length: result.Bytes}
		return observation
	}
	var ticks atomic.Int64
	drainer, err := recovery.NewDrainer(f.store, f.service, func() time.Time {
		return f.now.Add(time.Duration(ticks.Add(1)) * time.Nanosecond)
	})
	recoveryOK(t, err)
	var observed domain.AdministrativeTaskView
	err = runRecoveryCall(t, f, []protocol.Operation{protocol.Resolve}, func(ctx context.Context) error {
		var callErr error
		observed, callErr = drainer.Control(ctx, recovery.DrainRequest{Key: key, Route: f.lookup.Route, Action: domain.AdministrativeResolve})
		return callErr
	}, false)
	if err != nil {
		t.Fatalf("accepted terminal resolve failed with advancing clock: %v", err)
	}
	if observed.Binding != original || observed.Correlation == nil || observed.Correlation.Operation != original.Origin.Operation || observed.Reserved || observed.Observation == nil || observed.Observation.Kind != domain.Terminal {
		t.Fatal("terminal resolve changed the frozen identity or closure")
	}
	if !observed.Observation.ObservedAt.After(f.now) || observed.Observation.Result == nil || *observed.Observation.Result != result {
		t.Fatal("terminal resolve lost the advancing observation time or accepted result")
	}
	stored, err := f.store.GetAdministrativeTask(f.ctx, key)
	recoveryOK(t, err)
	if stored.Binding != original || stored.Observation == nil || !stored.Observation.ObservedAt.Equal(observed.Observation.ObservedAt) {
		t.Fatal("returned terminal observation did not match the durable Registry row")
	}
}
