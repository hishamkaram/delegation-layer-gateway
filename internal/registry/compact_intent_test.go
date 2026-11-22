package registry

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func compactAdmissionRoute(t *testing.T, f *fixture, input domain.Preparation) routing.Request {
	t.Helper()
	route, err := f.admissionRoute(t.Context(), f.transmission(input.Correlation))
	value := must(t, route, err)
	admission := fixtureAdmission(input.Correlation, input.Request)
	origin, err := protocol.OriginFromCorrelation(input.Correlation)
	admission.Task.Origin = must(t, origin, err)
	return commandRoute(t, value, protocol.Admit, input.Correlation.Destination.Project, admission)
}

func commandRoute[T any](t *testing.T, route routing.Request, op protocol.Operation, project domain.ProjectAlias, body T) routing.Request {
	t.Helper()
	data, err := encode(body)
	command := protocol.Command{Operation: op, Project: string(project), Body: must(t, data, err)}
	payload, err := encode(command)
	route.Payload = must(t, payload, err)
	route.Call.Operation, route.Call.RequestSHA256 = op, domain.Hash(route.Payload).Hex()
	return route
}

func sendCompact(t *testing.T, f *fixture, input domain.Preparation) {
	t.Helper()
	_, err := f.store.Prepare(t.Context(), f.actor, input)
	requireOK(t, err)
	route := compactAdmissionRoute(t, f, input)
	decision, err := f.store.MarkPossibleSendRouted(t.Context(), f.actor, f.transmission(input.Correlation), route)
	if must(t, decision, err).Kind != domain.SendOnce {
		t.Fatal("compact task did not make exactly one original admission")
	}
	requireOK(t, f.store.CompleteRouting(t.Context(), f.credential, f.connection, protocol.ControlCompletion{ProcessBoot: route.ProcessBoot, Call: route.Call, Disposition: protocol.ControlSettled}, f.now))
}

func observeCompact(t *testing.T, f *fixture, c domain.Correlation, kind domain.ObservationKind, spec domain.Digest) {
	t.Helper()
	observation := domain.DelegateObservation{Kind: kind, ObservedAt: f.now, SpecDigest: spec}
	if kind == domain.Terminal {
		observation.Closure = canonicalClosureEvidence()
	}
	_, err := f.store.ApplyResolution(t.Context(), domain.ValidatedResolution{ValidatedObservation: domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: observation}, DurableRequest: true})
	requireOK(t, err)
}

func TestCompactRetainedBodyIsOnlyFreshAdmissionIntent(t *testing.T) {
	for _, mode := range []string{"changed body", "missing body", "empty body", "mirrored options", "changed task index"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			removeOwnedFixtureProjects(t, f)
			input := compactPreparation(t, f, "compact-body-integrity", domain.RequestKindDispatch)
			_, err := f.store.Prepare(t.Context(), f.actor, input)
			requireOK(t, err)
			route := compactAdmissionRoute(t, f, input)
			corruptCompactIntent(t, f, input, mode)
			_, err = f.store.GetForDispatch(t.Context(), f.actor, input.Correlation.Operation, f.now)
			requireCode(t, err, domain.EvidenceInvalid)
			_, _, err = f.store.LookupPreparation(t.Context(), f.actor, "device", input.Correlation.Route.RequestID, input.Correlation.Route.InputDigest)
			requireCode(t, err, domain.EvidenceInvalid)
			_, err = f.store.MarkPossibleSendRouted(t.Context(), f.actor, f.transmission(input.Correlation), route)
			requireCode(t, err, domain.EvidenceInvalid)
			assertUnsentCompact(t, f, input.Correlation.Operation)
		})
	}
}

func corruptCompactIntent(t *testing.T, f *fixture, input domain.Preparation, mode string) {
	t.Helper()
	var err error
	switch mode {
	case "changed body":
		input.Request.Native.Budget = "different-Native-intent"
		data, encodeErr := encode(input.Request)
		requireOK(t, encodeErr)
		_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET request=? WHERE id=?", data, input.Correlation.Operation)
	case "missing body":
		_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET request=NULL WHERE id=?", input.Correlation.Operation)
	case "empty body":
		_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET request=? WHERE id=?", []byte{}, input.Correlation.Operation)
	case "mirrored options":
		data, encodeErr := encode(input.Request.Options())
		requireOK(t, encodeErr)
		digest := domain.Hash(data)
		_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET execution_options=?,options_sha256=? WHERE id=?", data, digest[:], input.Correlation.Operation)
	case "changed task index":
		_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET task='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=?", input.Correlation.Operation)
	}
	requireOK(t, err)
}

func assertUnsentCompact(t *testing.T, f *fixture, id domain.OperationID) {
	t.Helper()
	var state domain.DeliveryState
	var reserved bool
	var permits int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT state,reserved FROM operations WHERE id=?", id).Scan(&state, &reserved))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM routing_permits WHERE state='active'").Scan(&permits))
	if state != domain.Prepared || reserved || permits != 0 {
		t.Fatalf("rejected admission changed operation or permit: state=%s reserved=%t permits=%d", state, reserved, permits)
	}
}

func TestCompactQueuedAdmissionCannotReconstructDisposedBody(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	input := compactPreparation(t, f, "compact-queued-body", domain.RequestKindDispatch)
	sendCompact(t, f, input)
	requireOK(t, f.store.CheckQueuedAdmission(t.Context(), f.actor, f.transmission(input.Correlation)))
	_, err := f.store.db.ExecContext(t.Context(), "UPDATE operations SET request=NULL WHERE id=?", input.Correlation.Operation)
	requireOK(t, err)
	requireCode(t, f.store.CheckQueuedAdmission(t.Context(), f.actor, f.transmission(input.Correlation)), domain.EvidenceInvalid)
	decision, err := f.store.MarkPossibleSend(t.Context(), f.actor, f.transmission(input.Correlation))
	got := must(t, decision, err)
	if got.Kind != domain.ObserveExisting || got.Request != (domain.FrozenRequest{}) || !got.Operation.Reserved {
		t.Fatal("bodyless possible-send replay invented a fresh request or released uncertainty")
	}
}
