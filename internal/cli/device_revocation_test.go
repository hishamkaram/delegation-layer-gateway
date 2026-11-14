package cli

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestTypedDeviceRevocationUsesExistingPrivateMutationAndRetainsIdentity(t *testing.T) {
	f := newOwnedCLIAdmin(t)
	output := filepath.Join(f.parent, "token.json")
	code, _, diagnostic := command(t, f.args(output)...)
	if code != 0 {
		t.Fatal("token setup failed", diagnostic)
	}
	devices := f.devices(t)
	if len(devices) != 1 {
		t.Fatal("expected one owned device")
	}
	id := devices[0].ID
	code, out, diagnostic := command(t, "devices", "revoke", "--socket", f.socket, "--device", string(id))
	if code != 0 || diagnostic != "" {
		t.Fatal("typed revocation failed", code, diagnostic)
	}
	var result adminapi.Mutation
	require(t, json.Unmarshal([]byte(out), &result))
	if !result.Committed {
		t.Fatal("revocation was not committed")
	}
	_, err := f.store.AuthorizeOwnedDevice(t.Context(), domain.OwnedDeviceRequest{Actor: domain.Actor{Principal: f.owner, Scopes: domain.ScopeSet{domain.InventoryRead}}, Device: id, Scope: domain.InventoryRead})
	var denied *domain.Error
	if !errors.As(err, &denied) || denied.Code != domain.NotFound {
		t.Fatal("revoked device retained routing authorization")
	}
	after := f.devices(t)
	if len(after) != 0 {
		t.Fatal("revoked device remained in authorized inventory")
	}
	assertRevokedDeviceRetained(t, f, id, devices[0].Name)
}

func assertRevokedDeviceRetained(t *testing.T, f *ownedCLIAdmin, id domain.DeviceID, expectedName string) {
	t.Helper()
	// Inventory deliberately conceals revoked identities. A read-only query
	// checks retention without re-registering (which could conceal deletion).
	db, err := sql.Open("sqlite", "file:"+filepath.Join(f.parent, "registry.sqlite")+"?mode=ro")
	require(t, err)
	t.Cleanup(func() { require(t, db.Close()) })
	var name string
	var revoked bool
	require(t, db.QueryRowContext(t.Context(), "SELECT name,revoked FROM devices WHERE id=?", id).Scan(&name, &revoked))
	if name != expectedName || !revoked {
		t.Fatal("revocation deleted or rebound device history")
	}
}
