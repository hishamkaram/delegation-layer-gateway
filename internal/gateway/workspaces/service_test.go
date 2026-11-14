package workspaces_test

import (
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
)

func TestResolutionInitializesZeroProjectRootAndRetainsFirstPinAfterRegistrationFailure(t *testing.T) {
	f := newFixture(t)
	ctx := bounded(t)
	inventory, err := f.backend.ListWorkspaces(ctx, f.actor, f.device)
	require(t, err)
	assertWorkspaceInventory(t, f, inventory)
	input := f.input()
	dispatch := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	f.registerFailures.Store(1)
	_, err = f.backend.ResolveProject(ctx, dispatch, input)
	requireCode(t, err, domain.Pending)
	saved, found, err := f.store.LookupProjectResolution(ctx, f.actor, f.device, domain.ResolutionID(input.Request.RequestID))
	require(t, err)
	if !found || saved.Pin == nil || saved.Registered || saved.Pin.Handle != domain.ProjectAlias(input.Request.RequestID) || f.resolveCalls.Load() != 1 || f.barrierCalls.Load() != 1 {
		t.Fatalf("first pin was not durable before route registration: %+v", saved)
	}
	result, err := f.backend.ResolveProject(ctx, dispatch, input)
	require(t, err)
	if result.Project != *saved.Pin || f.resolveCalls.Load() != 1 || f.barrierCalls.Load() != 1 {
		t.Fatal("same-request retry replaced the pin or repeated namespace initialization")
	}
	// A path change cannot turn an existing request into a second resolve.
	input.Request.RelativePath = "another-repository"
	_, err = f.backend.ResolveProject(ctx, f.actor, input)
	requireCode(t, err, domain.Conflict)
	if f.resolveCalls.Load() != 1 {
		t.Fatal("changed request reached Native")
	}
	input.Request.RelativePath = "private-canary-repository"
	require(t, f.hub.DisconnectContext(ctx, f.device))
	offline, err := f.backend.ResolveProject(ctx, dispatch, input)
	require(t, err)
	if offline != result || f.resolveCalls.Load() != 1 {
		t.Fatal("offline replay changed its registered immutable pin")
	}
}

func assertWorkspaceInventory(t *testing.T, f *fixture, inventory workspaces.Inventory) {
	t.Helper()
	if !inventory.Online || !inventory.DelegateReady || inventory.ObservedAt.IsZero() || len(inventory.Workspaces) != 1 || inventory.Workspaces[0].WorkspaceBinding != f.workspace {
		t.Fatalf("missing dated zero-project workspace inventory: %+v", inventory)
	}
}

func TestTargetedCapabilityUsesIndependentScopesAndNeverImplicitlyResolves(t *testing.T) {
	f := newFixture(t)
	ctx := bounded(t)
	result, err := f.backend.ResolveProject(ctx, f.actor, f.input())
	require(t, err)
	destination := domain.Destination{Device: f.device, Project: result.Project.Handle}
	f.policyRevision.Store(2)
	for _, scope := range []domain.Scope{domain.InventoryRead, domain.TaskDispatch} {
		actor := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{scope}}
		observed, inspectErr := f.backend.InspectProject(ctx, actor, destination, scope)
		require(t, inspectErr)
		if observed.Capability.CurrentPolicyRevision != 2 || observed.Capability.Project.Handle != string(result.Project.Handle) || observed.Capability.Project.Workspace != f.workspace || observed.ObservedAt.IsZero() {
			t.Fatal("targeted metadata altered the immutable pin or lost its fresh observation")
		}
	}
	unknown := destination
	unknown.Project = domain.ProjectAlias(strings.Repeat("f", 32))
	_, err = f.backend.InspectProject(ctx, f.actor, unknown, domain.InventoryRead)
	requireCode(t, err, domain.NotFound)
	if f.resolveCalls.Load() != 1 || f.inspectCalls.Load() != 2 {
		t.Fatal("unknown handle caused an implicit wire resolve or inspection")
	}
	policy := ownerPolicy()
	policy.Enabled = false
	require(t, f.store.PutOwnerPolicy(ctx, f.actor.Principal, policy))
	_, err = f.backend.InspectProject(ctx, f.actor, destination, domain.TaskDispatch)
	requireCode(t, err, domain.Forbidden)
	if f.inspectCalls.Load() != 2 {
		t.Fatal("revoked owner policy reached Native")
	}
}

func TestResolutionDoesNotSavePinWhenDispatchAuthorityIsLostBeforeReply(t *testing.T) {
	f := newFixture(t)
	ctx := bounded(t)
	input := f.input()
	f.removeDispatchBeforeReply.Store(true)
	_, err := f.backend.ResolveProject(ctx, f.actor, input)
	requireCode(t, err, domain.NotFound)
	require(t, f.store.PutOwnerPolicy(ctx, f.actor.Principal, ownerPolicy()))
	saved, found, err := f.store.LookupProjectResolution(ctx, f.actor, f.device, domain.ResolutionID(input.Request.RequestID))
	require(t, err)
	if !found || saved.Pin != nil || saved.Registered {
		t.Fatal("reply committed after owner dispatch authority was removed")
	}
	result, err := f.backend.ResolveProject(ctx, f.actor, input)
	require(t, err)
	if result.Request != saved.Request || result.Project.Handle != domain.ProjectAlias(saved.Request) || f.barrierCalls.Load() != 1 || f.resolveCalls.Load() != 2 {
		t.Fatal("authorized retry did not recover the original explicit request")
	}
}

func TestResolutionConflictingNamespaceInventoryCannotCreateProject(t *testing.T) {
	f := newFixture(t)
	ctx := bounded(t)
	f.conflictingHistory.Store(true)
	input := f.input()
	_, err := f.backend.ResolveProject(ctx, f.actor, input)
	requireCode(t, err, domain.Conflict)
	saved, found, err := f.store.LookupProjectResolution(ctx, f.actor, f.device, domain.ResolutionID(input.Request.RequestID))
	require(t, err)
	if !found || saved.Pin != nil || saved.Registered || f.resolveCalls.Load() != 0 {
		t.Fatal("conflicting namespace inventory allowed project pinning")
	}
}
