package mcpadapter

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestCapabilityCleanupRightsIntersectCurrentActorAndTargetGrant(t *testing.T) {
	for _, test := range []struct {
		name                       string
		actorMissing, grantMissing domain.Scope
		offline, missingReport     bool
		read, cancel               bool
	}{
		{name: "both", read: true, cancel: true},
		{name: "token-read-missing", actorMissing: domain.TaskRead, cancel: true},
		{name: "token-cancel-missing", actorMissing: domain.TaskCancel, read: true},
		{name: "grant-read-missing", grantMissing: domain.TaskRead, cancel: true},
		{name: "grant-cancel-missing", grantMissing: domain.TaskCancel, read: true},
		{name: "offline", offline: true, read: true, cancel: true},
		{name: "no-provider-report", missingReport: true, read: true, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, 1)
			actor := domain.Actor{Principal: f.alice.Principal, Scopes: cleanupScopesExcept(test.actorMissing)}
			setCleanupGrant(t, f, cleanupScopesExcept(test.grantMissing))
			if test.offline {
				f.link.err = &gateway.RemoteError{Failure: protocol.Failure{Code: "device_offline", Retryable: true}}
			}
			if test.missingReport {
				f.link.snapshot.Capabilities.Projects = nil
			}
			got, err := f.adapter.capabilities(t.Context(), actor, CapabilitiesInput{DeviceID: string(deviceID(0)), ProjectAlias: "public"})
			check(t, err)
			if got.TaskReadAllowed != test.read || got.TaskCancelAllowed != test.cancel {
				t.Fatalf("current authorization conflated with token, grant or presence: %+v", got)
			}
		})
	}
}

func TestCapabilityCleanupRightsReflectGrantChangesThroughPublicSDK(t *testing.T) {
	f := newFixture(t, 1)
	session := f.session(t, "alice")
	input := args(t, CapabilitiesInput{DeviceID: string(deviceID(0)), ProjectAlias: "public"})
	before := decodeResult[Capabilities](t, f.call(t, session, "get_capabilities", input))
	if before.Error != nil || before.Data == nil || !before.Data.TaskReadAllowed || !before.Data.TaskCancelAllowed {
		t.Fatal("authorized cleanup rights absent from public capability response")
	}
	setCleanupGrant(t, f, cleanupScopesExcept(domain.TaskCancel))
	after := decodeResult[Capabilities](t, f.call(t, session, "get_capabilities", input))
	if after.Error != nil || after.Data == nil || !after.Data.TaskReadAllowed || after.Data.TaskCancelAllowed {
		t.Fatal("public capability response reused stale cancellation authority")
	}
	assertPublic(t, f.call(t, session, "get_capabilities", input))
}

func cleanupScopesExcept(missing domain.Scope) domain.ScopeSet {
	var scopes domain.ScopeSet
	for _, scope := range []domain.Scope{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel} {
		if scope != missing {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

func setCleanupGrant(t *testing.T, f *fixture, scopes domain.ScopeSet) {
	t.Helper()
	check(t, f.store.PutGrant(t.Context(), domain.Grant{
		Key:     domain.GrantKey{Principal: f.alice.Principal, Destination: domain.Destination{Device: deviceID(0), Project: "public"}},
		Scopes:  scopes,
		Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 120},
	}))
}
