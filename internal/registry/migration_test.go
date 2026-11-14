package registry

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// This is the pre-migration schema-6 declaration, independently frozen here.
const legacyRoutingPermits = `CREATE TABLE routing_permits(device TEXT NOT NULL, connection_boot TEXT NOT NULL, connection_counter INTEGER NOT NULL, request TEXT NOT NULL, process_boot TEXT NOT NULL, credential BLOB NOT NULL, call BLOB NOT NULL, protected INTEGER NOT NULL, scan INTEGER NOT NULL, state TEXT NOT NULL, PRIMARY KEY(device,connection_boot,connection_counter,request))`

func legacyMigrationFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	correlation := f.prepare(t, "migration-reserved")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(correlation))
	requireOK(t, err)
	for number, state := range []string{"active", "unpublished", "reconciled", "admin_drained", "settled", "not_claimed"} {
		request := routingRequest(t, f, protocol.ContextInspect, 100+number)
		requireOK(t, f.store.AcquireRouting(t.Context(), request))
		_, err = f.store.db.ExecContext(t.Context(), "UPDATE routing_permits SET state=? WHERE request=?", state, request.Call.RequestID)
		requireOK(t, err)
	}
	_, err = f.store.db.ExecContext(t.Context(), `ALTER TABLE routing_permits RENAME TO routing_permits_current;
`+legacyRoutingPermits+`;
INSERT INTO routing_permits SELECT * FROM routing_permits_current;
DROP TABLE routing_permits_current;
PRAGMA user_version=6;`)
	requireOK(t, err)
	return f
}

func migrationSnapshot(t *testing.T, db *sql.DB) map[string][][]any {
	t.Helper()
	result := make(map[string][][]any)
	for _, table := range []string{"settings", "principals", "devices", "projects", "grants", "enrollment", "issuance", "credentials", "operations", "administrative_routes", "recoveries", "root_admissions", "credential_epochs", "recovery_destinations", "inventory_pages", "routing_peers", "routing_permits", "routing_rosters", "routing_roster_devices", "owner_policies", "device_owners", "self_enrollments"} {
		result[table] = migrationTableRows(t, db, table)
	}
	return result
}

func migrationTableRows(t *testing.T, db *sql.DB, table string) (result [][]any) {
	t.Helper()
	// Names come only from the fixed authority table list above.
	rows, err := db.QueryContext(t.Context(), "SELECT * FROM "+table+" ORDER BY rowid")
	requireOK(t, err)
	t.Cleanup(func() { requireOK(t, rows.Close()) })
	columns, err := rows.Columns()
	requireOK(t, err)
	for rows.Next() {
		values := make([]any, len(columns))
		targets := make([]any, len(columns))
		for i := range values {
			targets[i] = &values[i]
		}
		requireOK(t, rows.Scan(targets...))
		for i, value := range values {
			if data, ok := value.([]byte); ok {
				values[i] = append([]byte(nil), data...)
			}
		}
		result = append(result, values)
	}
	requireOK(t, rows.Err())
	requireOK(t, rows.Close())
	return result
}

func TestMigrationPreservesSchemaSixAuthorityAndEveryPermit(t *testing.T) {
	f := legacyMigrationFixture(t)
	before := migrationSnapshot(t, f.store.db)
	requireOK(t, f.store.Close())
	opened, err := Open(t.Context(), f.path, options(f.gateway))
	if err == nil {
		requireOK(t, opened.Close())
		t.Fatal("Open accepted schema 6 without explicit migration")
	}
	result, err := Migrate(t.Context(), f.path)
	if got := must(t, result, err); got != (MigrationResult{Gateway: f.gateway, FromVersion: 6, ToVersion: 9}) {
		t.Fatalf("migration identity or version changed: %+v", got)
	}
	store, err := Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, store, err)
	if after := migrationSnapshot(t, f.store.db); !reflect.DeepEqual(before, after) {
		t.Fatal("migration changed authority, grants, task evidence or routing rows")
	}
	var version int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&version))
	// The previous binary's first schema gate requires exactly version 6.
	if version == 6 {
		t.Fatal("old schema-6 validator would still accept the migrated database")
	}
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE routing_permits SET state='unknown'")
	if err == nil {
		t.Fatal("schema 7 accepted an unknown routing state")
	}
	requireOK(t, f.store.Close())
	result, err = Migrate(t.Context(), f.path)
	if got := must(t, result, err); got.FromVersion != 9 || got.ToVersion != 9 || got.Gateway != f.gateway {
		t.Fatal("idempotent migration changed identity or versions")
	}
	store, err = Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, store, err)
	assertActiveRoutingIndex(t, f.store.db)
}

func assertActiveRoutingIndex(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN SELECT COALESCE(SUM(protected=0),0),COALESCE(SUM(scan=1),0) FROM routing_permits WHERE state='active'")
	requireOK(t, err)
	defer func() { requireOK(t, rows.Close()) }()
	var indexed bool
	for rows.Next() {
		var id, parent, unused int
		var detail string
		requireOK(t, rows.Scan(&id, &parent, &unused, &detail))
		indexed = indexed || strings.Contains(detail, "routing_permits_active")
	}
	requireOK(t, rows.Err())
	if !indexed {
		t.Fatal("active quota query did not use the partial index")
	}
}

func TestMigrationUnknownStateRollsBackVersionAndAllRows(t *testing.T) {
	f := legacyMigrationFixture(t)
	_, err := f.store.db.ExecContext(t.Context(), "UPDATE routing_permits SET state='unknown' WHERE request='g:105'")
	requireOK(t, err)
	before := migrationSnapshot(t, f.store.db)
	requireOK(t, f.store.Close())
	_, err = Migrate(t.Context(), f.path)
	if err == nil {
		t.Fatal("migration accepted an unknown old routing state")
	}
	store, err := connect(t.Context(), f.path, fixtureAdmin{}, false)
	f.store = must(t, store, err)
	var version, temporary int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&version))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_schema WHERE name='routing_permits_v7'").Scan(&temporary))
	if version != 6 || temporary != 0 || !reflect.DeepEqual(before, migrationSnapshot(t, f.store.db)) {
		t.Fatal("failed migration changed version, rows or left a replacement table")
	}
}

func TestMigrationRequiresExistingSupportedOwnedDatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sqlite")
	_, err := Migrate(t.Context(), missing)
	if err == nil {
		t.Fatal("missing database migration succeeded")
	}
	if _, statErr := os.Lstat(missing); !os.IsNotExist(statErr) {
		t.Fatalf("migration created a missing database: %v", statErr)
	}
	f := legacyMigrationFixture(t)
	for _, version := range []int{5, 10} {
		_, err = f.store.db.ExecContext(t.Context(), fmt.Sprintf("PRAGMA user_version=%d", version))
		requireOK(t, err)
		_, err = Migrate(t.Context(), f.path)
		requireCode(t, err, domain.Conflict)
	}
}

func TestSchemaEightMigrationPreservesExistingOwnersWithoutAdoptingLegacyDevices(t *testing.T) {
	f, _ := ownedRootFixture(t)
	_, err := f.store.db.ExecContext(t.Context(), "DROP TABLE owned_projects; DROP TABLE project_resolutions; PRAGMA user_version=8;")
	requireOK(t, err)
	before := migrationSnapshot(t, f.store.db)
	requireOK(t, f.store.Close())
	opened, err := Open(t.Context(), f.path, options(f.gateway))
	if err == nil {
		requireOK(t, opened.Close())
		t.Fatal("Open migrated schema8 implicitly")
	}
	result, err := Migrate(t.Context(), f.path)
	if got := must(t, result, err); got.Gateway != f.gateway || got.FromVersion != 8 || got.ToVersion != 9 {
		t.Fatal("schema8 migration changed identity")
	}
	opened, err = Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, opened, err)
	if !reflect.DeepEqual(before, migrationSnapshot(t, f.store.db)) {
		t.Fatal("schema8 migration changed existing owners, grants or task evidence")
	}
	var owned, legacy int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM device_owners").Scan(&owned))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM device_owners WHERE device='device'").Scan(&legacy))
	if owned != 1 || legacy != 0 {
		t.Fatal("migration lost an owner or adopted a legacy device")
	}
}
