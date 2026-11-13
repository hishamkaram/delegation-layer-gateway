package registry

import (
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func resolutionStart(f *fixture, port *OwnedRootPort) domain.ProjectResolutionStart {
	return domain.ProjectResolutionStart{Request: domain.ResolutionID(strings.Repeat("e", 32)), Binding: port.Binding(), Workspace: domain.WorkspaceBinding{ID: "code", Guard: fixtureGuard("owned-workspace")}, SelectorDigest: domain.Hash([]byte("private selector")), Now: f.now}
}

func resolutionPin(input domain.ProjectResolutionStart) domain.ProjectResolutionPin {
	return domain.ProjectResolutionPin{Request: input.Request, Binding: input.Binding, Now: input.Now, Pin: domain.ProjectPin{Handle: domain.ProjectAlias(input.Request), Workspace: input.Workspace, Context: domain.ContextBinding{Root: input.Binding.Route.Root, Project: domain.ProjectGuard(fixtureGuard("resolved-project"))}}}
}

func TestProjectResolutionFirstPinSurvivesRestartAndConflictingRoute(t *testing.T) {
	f, port := ownedRootFixture(t)
	input := resolutionStart(f, port)
	first, err := f.store.BeginProjectResolution(t.Context(), f.actor, input)
	initial := must(t, first, err)
	pin := resolutionPin(input)
	_, err = f.store.RecordProjectResolutionPin(t.Context(), f.actor, pin)
	requireOK(t, err)
	destination := domain.Destination{Device: input.Binding.Route.Device, Project: pin.Pin.Handle}
	_, err = f.store.GetResolvedProject(t.Context(), f.actor, destination, domain.InventoryRead)
	requireCode(t, err, domain.NotFound)
	f.restart(t)
	saved, found, err := f.store.LookupProjectResolution(t.Context(), f.actor, destination.Device, input.Request)
	requireOK(t, err)
	if !found || saved.Pin == nil || *saved.Pin != pin.Pin || saved.Registered || saved.CreatedAt != initial.CreatedAt {
		t.Fatal("restart lost the first pin before route registration")
	}
	// Even equal guards do not authorize adoption of a preexisting legacy alias.
	requireOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: destination, Context: pin.Pin.Context}))
	_, err = f.store.RegisterResolvedProject(t.Context(), f.actor, domain.ProjectResolutionCheck{Request: input.Request, Binding: input.Binding, Now: f.now})
	requireCode(t, err, domain.Conflict)
	changed := pin
	changed.Pin.Context.Project = domain.ProjectGuard(fixtureGuard("different-project"))
	_, err = f.store.RecordProjectResolutionPin(t.Context(), f.actor, changed)
	requireCode(t, err, domain.Conflict)
	retained, _, err := f.store.LookupProjectResolution(t.Context(), f.actor, destination.Device, input.Request)
	requireOK(t, err)
	if retained.Pin == nil || *retained.Pin != pin.Pin || retained.Registered {
		t.Fatal("route failure or changed reply replaced the authoritative pin")
	}
}

func TestProjectResolutionReplayAndEveryMutationRecheckCurrentAuthority(t *testing.T) {
	for _, boundary := range []string{"record", "register"} {
		for _, revocation := range []string{"policy", "principal", "device", "connection"} {
			t.Run(boundary+"/"+revocation, func(t *testing.T) {
				checkResolutionMutationFence(t, boundary, revocation)
			})
		}
	}
}

func checkResolutionMutationFence(t *testing.T, boundary, revocation string) {
	t.Helper()
	f, port := ownedRootFixture(t)
	input := resolutionStart(f, port)
	initial, err := f.store.BeginProjectResolution(t.Context(), f.actor, input)
	requireOK(t, err)
	replay, err := f.store.BeginProjectResolution(t.Context(), f.actor, input)
	requireOK(t, err)
	if !reflect.DeepEqual(initial, replay) {
		t.Fatal("identical request changed correlation")
	}
	changed := input
	changed.SelectorDigest = domain.Hash([]byte("different selector"))
	_, err = f.store.BeginProjectResolution(t.Context(), f.actor, changed)
	requireCode(t, err, domain.Conflict)
	pin := resolutionPin(input)
	if boundary == "register" {
		_, err = f.store.RecordProjectResolutionPin(t.Context(), f.actor, pin)
		requireOK(t, err)
	}
	revokeResolutionAuthority(t, f, port, revocation)
	if boundary == "record" {
		_, err = f.store.RecordProjectResolutionPin(t.Context(), f.actor, pin)
	} else {
		_, err = f.store.RegisterResolvedProject(t.Context(), f.actor, domain.ProjectResolutionCheck{Request: input.Request, Binding: input.Binding, Now: f.now})
	}
	if err == nil {
		t.Fatal("stale authority mutated resolution")
	}
	var routes int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM owned_projects WHERE request=?", input.Request).Scan(&routes))
	if routes != 0 {
		t.Fatal("denied mutation registered a project")
	}
}

func revokeResolutionAuthority(t *testing.T, f *fixture, port *OwnedRootPort, kind string) {
	t.Helper()
	switch kind {
	case "policy":
		policy := testOwnerPolicy()
		policy.Enabled = false
		requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	case "principal":
		requireOK(t, f.store.SetPrincipalRevoked(t.Context(), f.actor.Principal, true))
	case "device":
		requireOK(t, f.store.SetDeviceRevoked(t.Context(), port.binding.Route.Device, true))
	case "connection":
		_, err := f.store.NextConnectionGeneration(t.Context(), port.binding.Credential, "replacement-boot", f.now)
		requireOK(t, err)
	}
}

func TestProjectResolutionLifetimeQuotaIncludesPendingAndAllowsExistingReplay(t *testing.T) {
	f, port := ownedRootFixture(t)
	input := resolutionStart(f, port)
	_, err := f.store.BeginProjectResolution(t.Context(), f.actor, input)
	requireOK(t, err)
	// Seed valid independent pending intents in one real transaction. The subject
	// under test performs the final admission/replay; no 1024 slow fixture opens.
	_, err = transaction(t.Context(), f.store, func(tx *sql.Tx) (struct{}, error) {
		for i := 1; i < protocol.MaxProjectPins; i++ {
			id := fmt.Sprintf("%032x", i)
			if _, insertErr := tx.ExecContext(t.Context(), "INSERT INTO project_resolutions(request,principal,device,root_guard,workspace_id,workspace_guard,selector_sha256,created) VALUES(?,?,?,?,?,?,?,?)", id, f.actor.Principal, input.Binding.Route.Device, input.Binding.Route.Root, input.Workspace.ID, input.Workspace.Guard, input.SelectorDigest[:], f.now.Format(timestampLayout)); insertErr != nil {
				return struct{}{}, insertErr
			}
		}
		return struct{}{}, nil
	})
	requireOK(t, err)
	_, err = f.store.BeginProjectResolution(t.Context(), f.actor, input)
	requireOK(t, err)
	input.Request = domain.ResolutionID(strings.Repeat("f", 32))
	_, err = f.store.BeginProjectResolution(t.Context(), f.actor, input)
	requireCode(t, err, domain.ResourceLimit)
}
