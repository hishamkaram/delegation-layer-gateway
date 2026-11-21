package registry

import (
	"errors"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func TestContinuationIdentityRequiresCurrentDispatchAndKnownSpec(t *testing.T) {
	for _, mode := range []string{"terminal", "missing spec", "refused", "unowned", "recovery blocked", "legacy route"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			makeOwnedFixture(t, f)
			c, spec := continuationIdentityParent(t, f, mode == "legacy route", mode != "missing spec" && mode != "refused")
			if mode == "refused" {
				observeCompact(t, f, c, domain.Refused, domain.Digest{})
			}
			actor := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
			if mode == "unowned" {
				actor.Principal = "another-principal"
			}
			if mode == "recovery blocked" {
				_, err := f.store.db.ExecContext(t.Context(), "UPDATE settings SET blocked=1")
				requireOK(t, err)
			}
			view, err := f.store.GetForContinuation(t.Context(), actor, c.Operation)
			codes := map[string]domain.ErrorCode{"missing spec": domain.Pending, "refused": domain.Conflict, "unowned": domain.NotFound, "recovery blocked": domain.Pending, "legacy route": domain.Conflict}
			if code, denied := codes[mode]; denied {
				requireCode(t, err, code)
				return
			}
			if got := must(t, view, err); got.Correlation != c || got.SpecDigest != spec {
				t.Fatal("terminal predecessor identity changed or required task-read scope")
			}
		})
	}
}

func continuationIdentityParent(t *testing.T, f *fixture, legacy, knownSpec bool) (domain.Correlation, domain.Digest) {
	t.Helper()
	input := compactPreparation(t, f, "continuation-parent", domain.RequestKindDispatch)
	c := input.Correlation
	if legacy {
		c = f.prepare(t, "legacy-continuation-parent")
		_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
		requireOK(t, err)
	} else {
		sendCompact(t, f, input)
	}
	spec := domain.Hash([]byte("actual Native predecessor spec"))
	if knownSpec {
		observeCompact(t, f, c, domain.Terminal, spec)
	}
	return c, spec
}

func continuationPreparation(t *testing.T, f *fixture, parent domain.Correlation, spec domain.Digest, explicit bool) domain.Preparation {
	t.Helper()
	input := compactPreparation(t, f, "fresh-continuation-child", domain.RequestKindContinuation)
	c := &input.Correlation
	c.Predecessor = domain.ContinuationPredecessor{Operation: parent.Operation, Task: parent.Task, SpecDigest: spec, RequestDigest: parent.RequestDigest}
	input.Request.Continuation = domain.ContinuationOverrides{Version: 1, Budget: "30s", Model: "actual Native model", Effort: "high", OutputSilenceTimeout: "0"}
	input.Request.SelectionExplicit = explicit
	var selector domain.RequestSelector
	if explicit {
		selector = domain.RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}
	}
	digest, err := domain.ContinuationInputDigestV1(c.Destination.Device, parent.Operation, selector, explicit, input.Request.Continuation, false, domain.Digest{})
	c.Route.InputDigest = must(t, digest, err)
	digest, err = domain.RequestDigest(*c, input.Request)
	c.RequestDigest = must(t, digest, err)
	return input
}

func continuationRoute(t *testing.T, f *fixture, input domain.Preparation, parent domain.Correlation, spec domain.Digest) (routing.Request, protocol.Continuation) {
	t.Helper()
	route, err := f.admissionRoute(t.Context(), f.transmission(input.Correlation))
	value := must(t, route, err)
	task := fixtureAdmission(input.Correlation, input.Request).Task
	origin, err := protocol.OriginFromCorrelation(input.Correlation)
	task.Origin = must(t, origin, err)
	predecessor := fixtureAdmission(parent, domain.FrozenRequest{}).Task
	origin, err = protocol.OriginFromCorrelation(parent)
	predecessor.Origin, predecessor.SpecSHA256 = must(t, origin, err), spec.Hex()
	o := input.Request.Continuation
	body := protocol.Continuation{Task: task, Predecessor: predecessor, Overrides: protocol.ContinuationOverrides{Version: o.Version, Budget: o.Budget, Model: o.Model, Effort: o.Effort, OutputSilenceTimeout: o.OutputSilenceTimeout}, SelectionExplicit: input.Request.SelectionExplicit, BriefPresent: input.Request.BriefPresent, Brief: input.Request.Brief}
	requireOK(t, body.Validate())
	return commandRoute(t, value, protocol.Continue, input.Correlation.Destination.Project, body), body
}

func freshContinuation(t *testing.T, explicit bool) (*fixture, domain.Preparation, routing.Request, protocol.Continuation) {
	t.Helper()
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	parent := compactPreparation(t, f, "fresh-continuation-parent", domain.RequestKindDispatch)
	sendCompact(t, f, parent)
	spec := domain.Hash([]byte("Native parent spec"))
	observeCompact(t, f, parent.Correlation, domain.Terminal, spec)
	input := continuationPreparation(t, f, parent.Correlation, spec, explicit)
	_, err := f.store.Prepare(t.Context(), f.actor, input)
	requireOK(t, err)
	route, body := continuationRoute(t, f, input, parent.Correlation, spec)
	return f, input, route, body
}

func TestContinuationRoutingUsesAtomicAdmissionOwner(t *testing.T) {
	f, input, route, _ := freshContinuation(t, true)
	if err := f.store.AcquireRouting(t.Context(), route); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("generic routing bypassed continuation admission transaction: %v", err)
	}
	assertUnsentCompact(t, f, input.Correlation.Operation)
	actor := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	decision, err := f.store.MarkPossibleSendRouted(t.Context(), actor, f.transmission(input.Correlation), route)
	if got := must(t, decision, err); got.Kind != domain.SendOnce || got.Request != input.Request {
		t.Fatal("atomic continuation changed retained intent or sent a replacement")
	}
	requireOK(t, f.store.CheckQueuedAdmission(t.Context(), actor, f.transmission(input.Correlation)))
	_, err = f.store.db.ExecContext(t.Context(), "DELETE FROM operations WHERE id=?", input.Correlation.Predecessor.Operation)
	requireOK(t, err)
	requireCode(t, f.store.CheckQueuedAdmission(t.Context(), actor, f.transmission(input.Correlation)), domain.NotFound)
	var reserved bool
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT reserved FROM operations WHERE id=?", input.Correlation.Operation).Scan(&reserved))
	if !reserved {
		t.Fatal("queued predecessor loss released possibly-sent child evidence")
	}
}

func TestContinuationRoutingRejectsChangedTupleAndCurrentAuthority(t *testing.T) {
	for _, mode := range []string{"parent spec", "parent origin", "parent route", "overrides", "selection explicit", "brief presence", "missing parent", "current scope"} {
		t.Run(mode, func(t *testing.T) {
			f, input, route, body := freshContinuation(t, false)
			code := domain.EvidenceInvalid
			switch mode {
			case "parent spec":
				body.Predecessor.SpecSHA256 = domain.Hash([]byte("changed parent spec")).Hex()
			case "parent origin":
				body.Predecessor.Origin.Binding += " "
			case "parent route":
				body.Predecessor.Route.Selection.RelativePath = "other-parent-path"
			case "overrides":
				body.Overrides.Budget = "unrequested-budget"
			case "selection explicit":
				body.SelectionExplicit = true
			case "brief presence":
				body.BriefPresent, body.Brief = true, "unrequested brief"
			case "missing parent":
				_, err := f.store.db.ExecContext(t.Context(), "DELETE FROM operations WHERE id=?", input.Correlation.Predecessor.Operation)
				requireOK(t, err)
				code = domain.NotFound
			case "current scope":
				policy := testOwnerPolicy()
				policy.Scopes = domain.ScopeSet{domain.TaskRead}
				requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
				code = domain.NotFound
			}
			route = commandRoute(t, route, protocol.Continue, input.Correlation.Destination.Project, body)
			_, err := f.store.MarkPossibleSendRouted(t.Context(), f.actor, f.transmission(input.Correlation), route)
			requireCode(t, err, code)
			assertUnsentCompact(t, f, input.Correlation.Operation)
		})
	}
}
