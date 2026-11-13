package registry

import (
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestOwnedDeviceAuthorizationNeedsOwnerAndCurrentTaskScope(t *testing.T) {
	f := newFixture(t)
	request := domain.OwnedDeviceRequest{Actor: f.actor, Device: "device", Scope: domain.InventoryRead}
	_, err := f.store.AuthorizeOwnedDevice(t.Context(), request)
	requireCode(t, err, domain.NotFound) // Legacy project grants never become device ownership.
	makeOwnedFixture(t, f)
	_, err = f.store.db.ExecContext(t.Context(), "DELETE FROM projects WHERE device='device'")
	requireOK(t, err)
	value, err := f.store.AuthorizeOwnedDevice(t.Context(), request)
	authorized := must(t, value, err)
	if authorized.Principal != f.actor.Principal || authorized.Device.ID != "device" || authorized.Policy.Ceiling.MaxBudgetSeconds != 60 {
		t.Fatal("zero-project authorization lost its current owner policy")
	}
	authorized.Policy.Ceiling.Providers[0] = "changed-copy"
	value, err = f.store.AuthorizeOwnedDevice(t.Context(), request)
	if got := must(t, value, err); got.Policy.Ceiling.Providers[0] != "provider" {
		t.Fatal("caller mutated Registry's policy authority")
	}
	other, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "other"})
	requireOK(t, err)
	request.Actor.Principal = other.ID
	_, err = f.store.AuthorizeOwnedDevice(t.Context(), request)
	requireCode(t, err, domain.NotFound)
	request.Actor = domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.DeviceEnroll, domain.DeviceManage}}
	_, err = f.store.AuthorizeOwnedDevice(t.Context(), request)
	requireCode(t, err, domain.NotFound)
	request.Actor = f.actor
	requireOK(t, f.store.DisableOwnerPolicy(t.Context(), f.actor.Principal))
	_, err = f.store.AuthorizeOwnedDevice(t.Context(), request)
	requireCode(t, err, domain.Forbidden)
}
