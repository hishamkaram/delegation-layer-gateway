package registry

import (
	"database/sql"
	"reflect"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func testOwnerPolicy() domain.OwnerPolicy {
	return domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 10}
}

func makeOwnedFixture(t *testing.T, f *fixture) {
	t.Helper()
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, testOwnerPolicy()))
	// Simulates a newly created owned device without adding an adoption API.
	_, err := f.store.db.ExecContext(t.Context(), "DELETE FROM grants WHERE device='device'")
	requireOK(t, err)
	_, err = f.store.db.ExecContext(t.Context(), "INSERT INTO device_owners(device,principal) VALUES('device',?)", f.actor.Principal)
	requireOK(t, err)
}

func TestOwnedAuthorityUsesLivePolicyAndNeverLegacyGrantFallback(t *testing.T) {
	f := newFixture(t)
	makeOwnedFixture(t, f)
	request := domain.AuthorizationRequest{Actor: f.actor, Destination: destination(), Scope: domain.TaskDispatch}
	authorized, err := f.store.Authorize(t.Context(), request)
	if got := must(t, authorized, err); got.Grant.Ceiling.MaxBudgetSeconds != 60 {
		t.Fatal("owner ceiling was not derived from current policy")
	}
	c := f.prepare(t, "owned-operation")
	operations, err := f.store.ListOperations(t.Context(), f.actor, domain.OperationPageRequest{})
	if got := must(t, operations, err); len(got.Items) != 1 || got.Items[0].Correlation.Operation != c.Operation {
		t.Fatal("owned operation invisible without generated grants")
	}
	f.restart(t)
	policy := testOwnerPolicy()
	policy.Ceiling.MaxBudgetSeconds = 30
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	authorized, err = f.store.Authorize(t.Context(), request)
	if got := must(t, authorized, err); got.Grant.Ceiling.MaxBudgetSeconds != 30 {
		t.Fatal("policy change did not narrow effective authority")
	}
	bob, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "bob"})
	other := must(t, bob, err)
	request.Actor.Principal = other.ID
	_, err = f.store.Authorize(t.Context(), request)
	requireCode(t, err, domain.NotFound)
	grant := domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: destination()}, Scopes: f.actor.Scopes, Ceiling: policy.Ceiling}
	requireCode(t, f.store.PutGrant(t.Context(), grant), domain.Conflict)
	grant.Key.Principal = other.ID
	requireCode(t, f.store.PutGrant(t.Context(), grant), domain.Conflict)
	policy.Enabled = false
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	_, err = f.store.CheckCredential(t.Context(), f.credential, f.now)
	requireCode(t, err, domain.Forbidden)
	_, err = f.store.GetOperation(t.Context(), f.actor, c.Operation)
	requireCode(t, err, domain.Forbidden)
	devices, err := f.store.ListDevices(t.Context(), f.actor, domain.DevicePageRequest{})
	if got := must(t, devices, err); len(got.Items) != 0 {
		t.Fatal("disabled owner still visible through inventory")
	}
}

func TestOwnedDeviceVisibleWithoutProjectsAndScopeIsolation(t *testing.T) {
	f := newFixture(t)
	makeOwnedFixture(t, f)
	_, err := f.store.db.ExecContext(t.Context(), "DELETE FROM projects WHERE device='device'")
	requireOK(t, err)
	devices, err := f.store.ListDevices(t.Context(), f.actor, domain.DevicePageRequest{})
	if got := must(t, devices, err); len(got.Items) != 1 || got.Items[0].ID != "device" {
		t.Fatal("zero-project owner device disappeared")
	}
	projects, err := f.store.ListProjects(t.Context(), f.actor, "device", domain.ProjectPageRequest{})
	if got := must(t, projects, err); len(got.Items) != 0 {
		t.Fatal("zero-project device manufactured a bootstrap project")
	}
	f.actor.Scopes = domain.ScopeSet{domain.DeviceEnroll, domain.DeviceManage}
	_, err = f.store.ListDevices(t.Context(), f.actor, domain.DevicePageRequest{})
	requireCode(t, err, domain.Forbidden)
}

func TestOwnershipPolicyRequiresPrivateAdministration(t *testing.T) {
	f := newFixture(t)
	f.store.admin = nil
	requireCode(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, testOwnerPolicy()), domain.Forbidden)
	var count int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM owner_policies").Scan(&count))
	if count != 0 {
		t.Fatal("unprivileged policy write mutated registry")
	}
}

func TestRestoreNeverResurrectsOwnerAuthorizationFromSnapshot(t *testing.T) {
	f := newFixture(t)
	makeOwnedFixture(t, f)
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "owner-restore", Epoch: "new-owner-epoch", Now: f.now})
	requireOK(t, err)
	_, err = f.store.Authorize(t.Context(), domain.AuthorizationRequest{Actor: f.actor, Destination: destination(), Scope: domain.InventoryRead})
	requireCode(t, err, domain.Forbidden)
	var owners, policies int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM device_owners").Scan(&owners))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM owner_policies").Scan(&policies))
	if owners != 1 || policies != 0 {
		t.Fatal("restore erased ownership or retained snapshot authorization")
	}
}

func TestOwnerRevokeRequiresManagementAndCannotTargetLegacyDevice(t *testing.T) {
	f := newFixture(t)
	actor, input := selfEnrollmentFixture(t, f)
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, testOwnerPolicy()))
	reserved, err := f.store.BeginSelfEnrollment(t.Context(), actor, input)
	intent := must(t, reserved, err)
	_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: signFixture(t, intent, f.key), Now: f.now})
	requireOK(t, err)
	_, err = f.store.NextConnectionGeneration(t.Context(), intent.Credential, "owner-boot", f.now)
	requireOK(t, err)
	readOnly := actor
	readOnly.Scopes = domain.ScopeSet{domain.DeviceEnroll}
	requireCode(t, f.store.RevokeOwnedDevice(t.Context(), readOnly, intent.Credential.Device), domain.Forbidden)
	requireCode(t, f.store.RevokeOwnedDevice(t.Context(), actor, "device"), domain.NotFound)
	requireOK(t, f.store.RevokeOwnedDevice(t.Context(), actor, intent.Credential.Device))
	requireOK(t, f.store.RevokeOwnedDevice(t.Context(), actor, intent.Credential.Device))
	_, err = f.store.CheckCredential(t.Context(), intent.Credential, f.now)
	requireCode(t, err, domain.Forbidden)
	device, err := transaction(t.Context(), f.store, func(tx *sql.Tx) (domain.Device, error) { return readDevice(t.Context(), tx, intent.Credential.Device) })
	if got := must(t, device, err); !got.Revoked || got.CredentialGeneration != intent.Credential.Generation+1 {
		t.Fatal("retry changed generation or revocation was not committed")
	}
}

func TestSchemaSevenMigrationPreservesAuthorityWithoutAdoption(t *testing.T) {
	f := newFixture(t)
	before := migrationSnapshot(t, f.store.db)
	_, err := f.store.db.ExecContext(t.Context(), "DROP TABLE self_enrollments; DROP TABLE device_owners; DROP TABLE owner_policies; PRAGMA user_version=7;")
	requireOK(t, err)
	requireOK(t, f.store.Close())
	_, err = Open(t.Context(), f.path, options(f.gateway))
	requireCode(t, err, domain.Conflict)
	result, err := Migrate(t.Context(), f.path)
	if got := must(t, result, err); got.FromVersion != 7 || got.ToVersion != 9 || got.Gateway != f.gateway {
		t.Fatal("migration changed authority")
	}
	s, err := Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, s, err)
	if !reflect.DeepEqual(before, migrationSnapshot(t, f.store.db)) {
		t.Fatal("migration changed existing rows")
	}
	var owners int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM device_owners").Scan(&owners))
	if owners != 0 {
		t.Fatal("migration adopted legacy devices")
	}
	_, err = transaction(t.Context(), f.store, func(tx *sql.Tx) (domain.Authorization, error) {
		return authorize(t.Context(), tx, domain.AuthorizationRequest{Actor: f.actor, Destination: destination(), Scope: domain.TaskDispatch})
	})
	requireOK(t, err)
}
