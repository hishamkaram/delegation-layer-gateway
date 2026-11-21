package registry

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestSchemaNinePolicyMigrationPreservesAuthorityAndFrozenOperations(t *testing.T) {
	f := newFixture(t)
	f.prepare(t, "legacy-policy-prepared")
	sent := f.prepare(t, "legacy-policy-possible-send")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(sent))
	requireOK(t, err)
	policy := testOwnerPolicy()
	policy.Enabled = false
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	_, err = f.store.db.ExecContext(t.Context(), `UPDATE operations SET expires=?;
UPDATE grants SET value=CAST(json_set(value,'$.Ceiling',json('{"Providers":["old-provider"],"Permissions":["read-only"],"MaxBudgetSeconds":1}')) AS BLOB);
UPDATE owner_policies SET value=CAST(json_set(value,'$.Ceiling',json('{"Providers":["old-provider"],"Permissions":["read-only"],"MaxBudgetSeconds":1}')) AS BLOB);
DROP INDEX operations_retained_bodies; DROP INDEX operations_preparations; DROP INDEX operations_preparation_key; ALTER TABLE operations DROP COLUMN preparation_key; ALTER TABLE operations DROP COLUMN preparation_expires_ns;
PRAGMA user_version=9;`, f.now.Add(domain.DraftTTL).Format(time.RFC3339Nano))
	requireOK(t, err)
	preview, err := PreviewMigration(t.Context(), f.path)
	if got := must(t, preview, err); got != (MigrationPreview{MigrationResult: MigrationResult{Gateway: f.gateway, FromVersion: 9, ToVersion: 10}, GrantCount: 1, OwnerPolicyCount: 1, ObsoleteExecutionPolicyCount: 2}) {
		t.Fatalf("preview lost policy counts or changed identity: %+v", got)
	}
	before := migrationSnapshot(t, f.store.db)
	requireOK(t, f.store.Close())
	opened, err := Open(t.Context(), f.path, options(f.gateway))
	if err == nil {
		requireOK(t, opened.Close())
		t.Fatal("Open accepted obsolete execution policies without explicit migration")
	}
	result, err := Migrate(t.Context(), f.path)
	if got := must(t, result, err); got != (MigrationResult{Gateway: f.gateway, FromVersion: 9, ToVersion: 10}) {
		t.Fatalf("wrong policy migration identity or versions: %+v", got)
	}
	opened, err = Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, opened, err)
	var expiryNS int64
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT preparation_expires_ns FROM operations WHERE state='prepared'").Scan(&expiryNS))
	if expiryNS != f.now.Add(domain.DraftTTL).UnixNano() {
		t.Fatal("migration did not derive the exact legacy expiration instant")
	}
	after := migrationSnapshot(t, f.store.db)
	for _, table := range []string{"grants", "owner_policies"} {
		delete(before, table)
		delete(after, table)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("policy migration changed identity, authorization state or frozen operation evidence")
	}
	for _, table := range []string{"grants", "owner_policies"} {
		var value string
		// The table comes only from the fixed authority list above.
		requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT value FROM "+table).Scan(&value))
		if strings.Contains(value, "Ceiling") || strings.Contains(value, "old-provider") {
			t.Fatal("obsolete execution policy survived schema migration")
		}
	}
	migrated, err := f.store.ReadOwnerPolicy(t.Context(), f.actor.Principal)
	if got := must(t, migrated, err); got.Enabled || got.MaxDevices != policy.MaxDevices || !reflect.DeepEqual(got.Scopes, policy.Scopes) {
		t.Fatal("migration changed disabled owner authority")
	}
	_, err = f.store.Authorize(t.Context(), domain.AuthorizationRequest{Actor: f.actor, Destination: destination(), Scope: domain.TaskDispatch})
	requireOK(t, err) // This legacy device retains its explicit project grant.
}

func TestPolicyMigrationRollsBackOnInvalidRetainedAuthorization(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.db.ExecContext(t.Context(), `UPDATE grants SET value=CAST(json_set(value,'$.Ceiling',json('{"Providers":["old-provider"]}'),'$.Scopes',json('["device:manage"]')) AS BLOB);
DROP INDEX operations_retained_bodies; DROP INDEX operations_preparations; DROP INDEX operations_preparation_key; ALTER TABLE operations DROP COLUMN preparation_key; ALTER TABLE operations DROP COLUMN preparation_expires_ns;
PRAGMA user_version=9;`)
	requireOK(t, err)
	before := migrationSnapshot(t, f.store.db)
	requireOK(t, f.store.Close())
	_, err = Migrate(t.Context(), f.path)
	requireCode(t, err, domain.EvidenceInvalid)
	opened, err := connect(t.Context(), f.path, fixtureAdmin{}, false)
	f.store = must(t, opened, err)
	var version int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&version))
	if version != 9 || !reflect.DeepEqual(before, migrationSnapshot(t, f.store.db)) {
		t.Fatal("invalid access policy migration changed rows or schema version")
	}
}
