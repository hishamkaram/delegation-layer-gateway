package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type targetedFixture struct {
	value  TargetedProjectObservation
	calls  int
	scope  domain.Scope
	before func()
}

func (f *targetedFixture) InspectProject(_ context.Context, _ domain.Actor, _ domain.Destination, scope domain.Scope) (TargetedProjectObservation, error) {
	f.calls++
	f.scope = scope
	if f.before != nil {
		f.before()
	}
	return f.value, nil
}

func targetedDispatchFixture(t *testing.T) (*dispatchFixture, *targetedFixture) {
	t.Helper()
	f := newDispatchFixture(t)
	capability := f.link.snapshot.Capabilities.Projects[0]
	f.destination.Project = domain.ProjectAlias(strings.Repeat("7", 32))
	dispatchOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: f.destination, Context: domain.ContextBinding{Root: domain.RootGuard(capability.Context.Root), Project: domain.ProjectGuard(capability.Context.Project)}}))
	f.grant(t)
	capability.Alias = string(f.destination.Project)
	capability.Features = append(capability.Features, protocol.WorkspaceFeature)
	target := &targetedFixture{value: TargetedProjectObservation{Capability: protocol.ProjectCapabilityV2{Project: protocol.ResolvedProject{Handle: capability.Alias, Workspace: protocol.WorkspaceBinding{ID: "work", Guard: protocol.WireContextGuard("workspace")}, Context: capability.Context}, CurrentPolicyRevision: 1, Capability: capability}, Credential: f.link.snapshot.Credential, Connection: f.link.snapshot.Connection, ObservedAt: f.now}}
	f.link.snapshot.WireVersion = protocol.WireVersion2
	// A conflicting legacy cache must never decide v2 authority.
	f.link.snapshot.Capabilities.Projects[0].Ready = false
	f.service.targeted = target
	return f, target
}

func TestTargetedPrepareUsesDispatchScopeAndFreshPeerEvidence(t *testing.T) {
	f, target := targetedDispatchFixture(t)
	actor := f.actor
	actor.Scopes = domain.ScopeSet{domain.TaskDispatch}
	prepared, err := f.service.Prepare(t.Context(), actor, f.destination, f.request)
	dispatchOK(t, err)
	if target.calls != 1 || target.scope != domain.TaskDispatch || prepared.Correlation.Destination != f.destination {
		t.Fatal("v2 prepare required inventory rights or used stale project cache")
	}
}

func TestTargetedPrepareRejectsUnavailableOrWrongPeerBeforeCreatingOperation(t *testing.T) {
	for _, fault := range []string{"missing-service", "wrong-generation", "wrong-context", "not-ready"} {
		t.Run(fault, func(t *testing.T) {
			f, target := targetedDispatchFixture(t)
			switch fault {
			case "missing-service":
				f.service.targeted = nil
			case "wrong-generation":
				target.value.Connection.Counter++
			case "wrong-context":
				target.value.Capability.Project.Context.Project = protocol.WireContextGuard("other")
			case "not-ready":
				target.value.Capability.Capability.Ready = false
			}
			if _, err := f.service.Prepare(t.Context(), f.actor, f.destination, f.request); err == nil {
				t.Fatal("invalid v2 evidence created preparation")
			}
			if f.entropy.reads != 0 || f.link.reserves != 0 || f.link.writes != 0 {
				t.Fatal("refused preflight allocated operation or task transmission")
			}
		})
	}
}

func TestTargetedDispatchBindsObservationToReservedConnection(t *testing.T) {
	f, target := targetedDispatchFixture(t)
	prepared, err := f.service.Prepare(t.Context(), f.actor, f.destination, f.request)
	dispatchOK(t, err)
	target.before = func() { f.link.snapshot.Connection.Counter++ }
	_, err = f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	dispatchCode(t, err, domain.Conflict)
	view, err := f.store.GetOperation(t.Context(), f.actor, prepared.Correlation.Operation)
	dispatchOK(t, err)
	if view.Delivery != domain.Prepared || f.link.writes != 0 || f.link.releases != 1 {
		t.Fatal("new connection inherited targeted evidence or leaked unsent reservation")
	}
}
