package registry

import (
	"encoding/hex"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func workspaceMetadataRequest(t *testing.T, f *fixture, operation protocol.Operation) routing.Request {
	t.Helper()
	request := protocol.FilesystemRequest{}
	if operation != protocol.FilesystemScopes {
		request.Selection = protocol.FileSelection{ScopeID: "workspace", RelativePath: "."}
	}
	body, err := encode(request)
	requireOK(t, err)
	payload, err := encode(protocol.Command{Operation: operation, Root: string(binding().Root), Body: body})
	requireOK(t, err)
	route := routingRequest(t, f, operation, 999)
	route.WireVersion, route.Payload = protocol.WireVersion2, payload
	digest := domain.Hash(payload)
	route.Call.RequestSHA256 = hex.EncodeToString(digest[:])
	return route
}

func TestWorkspaceMetadataRequiresAllScopesAndCreatesNoSelectionState(t *testing.T) {
	for _, operation := range []protocol.Operation{protocol.FilesystemScopes, protocol.ListDirectory, protocol.ReadFile, protocol.InspectFile, protocol.InspectGit} {
		t.Run(string(operation), func(t *testing.T) {
			f := newFixture(t)
			removeOwnedFixtureProjects(t, f)
			input := workspaceMetadataRequest(t, f, operation)
			scopes := domain.ScopeSet{domain.TaskDispatch, domain.TaskRead}
			requireOK(t, f.store.AcquireWorkspaceMetadata(t.Context(), f.actor, scopes, input))
			completeRouting(t, f, input, protocol.ControlSettled)
			binding := domain.OwnedRootBinding{Route: domain.RootRoute{Device: "device", Root: binding().Root}, Credential: f.credential, Connection: f.connection}
			requireOK(t, f.store.CheckWorkspaceMetadata(t.Context(), f.actor, scopes, binding, f.now))
			var operations, resolutions, projects int
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT (SELECT count(*) FROM operations),(SELECT count(*) FROM project_resolutions),(SELECT count(*) FROM projects)").Scan(&operations, &resolutions, &projects))
			if operations != 0 || resolutions != 0 || projects != 0 {
				t.Fatal("filesystem metadata created a task, selection or project record")
			}
			for _, weaker := range []domain.ScopeSet{{domain.TaskDispatch}, {domain.TaskRead}, {domain.TaskCancel}} {
				if err := f.store.AcquireWorkspaceMetadata(t.Context(), f.actor, weaker, input); err == nil {
					t.Fatal("caller weakened mandatory filesystem scopes")
				}
			}
			policy := testOwnerPolicy()
			policy.Scopes = domain.ScopeSet{domain.TaskDispatch}
			requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
			requireCode(t, f.store.CheckWorkspaceMetadata(t.Context(), f.actor, scopes, binding, f.now), domain.NotFound)
			requireCode(t, f.store.AcquireWorkspaceMetadata(t.Context(), f.actor, scopes, input), domain.NotFound)
		})
	}
}

func TestWorkspaceMetadataRechecksGenerationRootAndCredential(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	input := workspaceMetadataRequest(t, f, protocol.ReadFile)
	scopes := domain.ScopeSet{domain.TaskDispatch, domain.TaskRead}
	bound := domain.OwnedRootBinding{Route: domain.RootRoute{Device: "device", Root: binding().Root}, Credential: f.credential, Connection: f.connection}
	requireOK(t, f.store.AcquireWorkspaceMetadata(t.Context(), f.actor, scopes, input))
	_, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "replacement-workspace", f.now)
	requireOK(t, err)
	requireCode(t, f.store.CheckWorkspaceMetadata(t.Context(), f.actor, scopes, bound, f.now), domain.Conflict)
	requireCode(t, f.store.AcquireWorkspaceMetadata(t.Context(), f.actor, scopes, input), domain.Conflict)
}

func TestRoutedAdmissionChecksExactNativeOptionsAndSelector(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	input := routedPreparation(t, f, "native-routing", "cccccccccccccccccccccccccccccccc")
	_, err := f.store.Prepare(t.Context(), f.actor, input)
	requireOK(t, err)
	transmission := f.transmission(input.Correlation)
	route, err := f.admissionRoute(t.Context(), transmission)
	original := must(t, route, err)
	requireOK(t, validateRoutingAdmission(t.Context(), nil, f.actor, original, input.Correlation, input.Request))
	for _, change := range []func(*protocol.Admission){
		func(a *protocol.Admission) { a.Native.Permission = "different-native-permission" },
		func(a *protocol.Admission) { a.Task.Route.Selection.RelativePath = "another-project" },
		func(a *protocol.Admission) { a.Task.Route.WorkspaceGuard = fixtureGuard("other-workspace") },
	} {
		admission := fixtureAdmission(input.Correlation, input.Request)
		change(&admission)
		body, encodeErr := encode(admission)
		requireOK(t, encodeErr)
		payload, encodeErr := encode(protocol.Command{Operation: protocol.Admit, Project: string(input.Correlation.Destination.Project), Body: body})
		requireOK(t, encodeErr)
		changed := original
		changed.Payload = payload
		digest := domain.Hash(payload)
		changed.Call.RequestSHA256 = hex.EncodeToString(digest[:])
		requireCode(t, validateRoutingAdmission(t.Context(), nil, f.actor, changed, input.Correlation, input.Request), domain.EvidenceInvalid)
	}
	decision, err := f.store.MarkPossibleSendRouted(t.Context(), f.actor, transmission, original)
	if got := must(t, decision, err); got.Kind != domain.SendOnce || got.Request.Native != input.Request.Native {
		t.Fatal("Native route failed to reserve its exact execution intent")
	}
}

func TestProjectSelectionMetadataNeedsDispatchWithoutCreatingPin(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	input := workspaceMetadataRequest(t, f, protocol.SelectProject)
	requireOK(t, f.store.AcquireWorkspaceMetadata(t.Context(), f.actor, domain.ScopeSet{domain.TaskDispatch}, input))
	var pins int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM project_resolutions").Scan(&pins))
	if pins != 0 {
		t.Fatal("read-only project selection created a pin")
	}
}

func TestWorkspaceMetadataDoesNotRequireTaskAdmissionInitialization(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	_, err := f.store.db.ExecContext(t.Context(), "DELETE FROM root_admissions")
	requireOK(t, err)
	input := workspaceMetadataRequest(t, f, protocol.ReadFile)
	scopes := domain.ScopeSet{domain.TaskDispatch, domain.TaskRead}
	requireOK(t, f.store.AcquireWorkspaceMetadata(t.Context(), f.actor, scopes, input))
	bound := domain.OwnedRootBinding{Route: domain.RootRoute{Device: "device", Root: binding().Root}, Credential: f.credential, Connection: f.connection}
	requireOK(t, f.store.CheckWorkspaceMetadata(t.Context(), f.actor, scopes, bound, f.now))
}
