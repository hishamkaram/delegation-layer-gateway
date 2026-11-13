package deviceclient

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestRevokeDeviceUsesFreshManageOnlyFlowAndRetainsLocalState(t *testing.T) {
	f := newGatewayFixture(t)
	store, actor, _ := realSelfService(t, f)
	status, err := Connect(t.Context(), f.options)
	if err != nil {
		t.Fatal(err)
	}
	beforeProfile, err := os.ReadFile(filepath.Join(f.options.ProfileDirectory, profileName))
	if err != nil {
		t.Fatal(err)
	}
	beforeIdentity, err := os.ReadFile(filepath.Join(f.options.ProfileDirectory, "identity", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(t.Context(), f.options.ProfileDirectory)
	if err != nil {
		t.Fatal(err)
	}
	busyErr := RevokeDevice(t.Context(), f.options.ProfileDirectory, f.options.PresentChallenge)
	closeErr := runtime.Close()
	if !errors.Is(busyErr, ErrBusy) || closeErr != nil {
		t.Fatal("active runtime was replaced during revoke", busyErr, closeErr)
	}
	if err = RevokeDevice(t.Context(), f.options.ProfileDirectory, f.options.PresentChallenge); err != nil {
		t.Fatal(err)
	}
	devices, err := store.ListDevices(t.Context(), actor, domain.DevicePageRequest{Limit: 10})
	if err != nil || len(devices.Items) != 0 {
		t.Fatal("Gateway authorization was not revoked", err)
	}
	assertRevokeLocalState(t, f.options.ProfileDirectory, beforeProfile, beforeIdentity)
	local, err := Status(t.Context(), f.options.ProfileDirectory)
	if err != nil || local.DeviceID != status.DeviceID {
		t.Fatal("revocation deleted local history", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) != 2 || f.scopes[1] != "device:manage" {
		t.Fatal("revocation reused authorization or requested extra scopes")
	}
}

func TestUncertainRevokePreservesProfileAndDoesNotRetry(t *testing.T) {
	f := newGatewayFixture(t)
	store, actor, _ := realSelfService(t, f)
	if _, err := Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	beforeProfile, err := os.ReadFile(filepath.Join(f.options.ProfileDirectory, profileName))
	if err != nil {
		t.Fatal(err)
	}
	beforeIdentity, err := os.ReadFile(filepath.Join(f.options.ProfileDirectory, "identity", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failNext = true
	f.mu.Unlock()
	if err = RevokeDevice(t.Context(), f.options.ProfileDirectory, f.options.PresentChallenge); !errors.Is(err, ErrTransport) {
		t.Fatal("lost revocation acknowledgment not explicit", err)
	}
	devices, err := store.ListDevices(t.Context(), actor, domain.DevicePageRequest{Limit: 10})
	if err != nil || len(devices.Items) != 0 {
		t.Fatal("fixture did not actually commit revocation", err)
	}
	assertRevokeLocalState(t, f.options.ProfileDirectory, beforeProfile, beforeIdentity)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) != 2 {
		t.Fatal("uncertain revoke retried authorization automatically")
	}
}

func assertRevokeLocalState(t *testing.T, directory string, profile, identity []byte) {
	t.Helper()
	afterProfile, err := os.ReadFile(filepath.Join(directory, profileName))
	if err != nil {
		t.Fatal(err)
	}
	afterIdentity, err := os.ReadFile(filepath.Join(directory, "identity", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(profile, afterProfile) || !bytes.Equal(identity, afterIdentity) {
		t.Fatal("revoke modified or deleted local source/credential history")
	}
}

func TestFreshRevokeLoginCannotTargetAnotherOwnersDevice(t *testing.T) {
	f := newGatewayFixture(t)
	store, original, auth := realSelfService(t, f)
	if _, err := Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	other, err := store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: f.descriptor.Issuer, Subject: "different-account"})
	if err != nil {
		t.Fatal(err)
	}
	policy := domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 2}
	if err = store.PutOwnerPolicy(t.Context(), other.ID, policy); err != nil {
		t.Fatal(err)
	}
	auth.mu.Lock()
	auth.actor = domain.Actor{Principal: other.ID, Scopes: domain.ScopeSet{domain.DeviceManage}}
	auth.mu.Unlock()
	if err = RevokeDevice(t.Context(), f.options.ProfileDirectory, f.options.PresentChallenge); !errors.Is(err, ErrDenied) {
		t.Fatal("different fresh login revoked stored device", err)
	}
	devices, err := store.ListDevices(t.Context(), original, domain.DevicePageRequest{Limit: 10})
	if err != nil || len(devices.Items) != 1 {
		t.Fatal("denied revoke changed owner authorization", err)
	}
}
