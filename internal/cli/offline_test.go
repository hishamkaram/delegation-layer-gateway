package cli

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func TestOfflineBeginRecoveryFencesBeforeServeAndRetriesSameIntent(t *testing.T) {
	path := initializedOfflineDatabase(t)
	prior := readOfflineRecoveryState(t, path)
	args := []string{"begin-recovery", "--database", path, "--recovery-id", "restore-one"}
	code, output, diagnostic := command(t, args...)
	if code != 0 || output == "" || diagnostic != "" {
		t.Fatalf("offline recovery failed: code=%d diagnostic=%s", code, diagnostic)
	}
	current := readOfflineRecoveryState(t, path)
	if !current.blocked || current.recovery != "restore-one" || current.epoch == prior.epoch {
		t.Fatal("offline recovery returned before durable credential fencing")
	}
	code, _, diagnostic = command(t, args...)
	if code != 0 || diagnostic != "" || readOfflineRecoveryState(t, path) != current {
		t.Fatal("retry changed the same restore intent")
	}
}

func TestOfflineMigrateReportsIdentityAndCurrentVersion(t *testing.T) {
	path := initializedOfflineDatabase(t)
	_, identity, _ := command(t, "identity", "--database", path)
	code, output, diagnostic := command(t, "migrate", "--database", path)
	if code != 0 || diagnostic != "" {
		t.Fatalf("offline migration failed: code=%d diagnostic=%s", code, diagnostic)
	}
	var result struct {
		Gateway string `json:"gateway_id"`
		From    int    `json:"from_version"`
		To      int    `json:"to_version"`
	}
	require(t, json.Unmarshal([]byte(output), &result))
	if result.Gateway == "" || result.From != 10 || result.To != 10 {
		t.Fatal("current database migration did not report stable schema10")
	}
	var original struct {
		Gateway string `json:"gateway_id"`
	}
	require(t, json.Unmarshal([]byte(identity), &original))
	if result.Gateway != original.Gateway {
		t.Fatal("migration replaced database authority")
	}
}

func TestOfflineCommandsRequireExistingDatabaseAndExclusiveLease(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	path := filepath.Join(parent, "private-canary.sqlite")
	for _, args := range [][]string{{"migrate", "--database", path}, {"begin-recovery", "--database", path, "--recovery-id", "restore-one"}} {
		code, out, diagnostic := command(t, args...)
		if code != 1 || out != "" || strings.Contains(diagnostic, path) {
			t.Fatal("missing database was initialized or diagnostics exposed its path")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("maintenance created a missing database")
		}
	}
	path = initializedOfflineDatabase(t)
	lease, err := instance.Acquire(filepath.Join(filepath.Dir(path), "gateway.lock"))
	require(t, err)
	defer func() { require(t, lease.Close()) }()
	for _, args := range [][]string{{"migrate", "--database", path}, {"begin-recovery", "--database", path, "--recovery-id", "restore-one"}} {
		code, out, diagnostic := command(t, args...)
		if code != 1 || out != "" || !strings.Contains(diagnostic, "database_unavailable") {
			t.Fatal("offline maintenance bypassed runtime ownership")
		}
	}
}

func initializedOfflineDatabase(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	path := filepath.Join(parent, "registry.sqlite")
	code, _, diagnostic := command(t, "init", "--database", path)
	if code != 0 || diagnostic != "" {
		t.Fatalf("fixture database initialization failed: code=%d diagnostic=%s", code, diagnostic)
	}
	return path
}

type offlineRecoveryState struct {
	epoch, recovery string
	blocked         bool
}

func readOfflineRecoveryState(t *testing.T, path string) offlineRecoveryState {
	t.Helper()
	endpoint := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", endpoint.String())
	require(t, err)
	defer func() { require(t, db.Close()) }()
	var result offlineRecoveryState
	require(t, db.QueryRow("SELECT epoch,recovery,blocked FROM settings WHERE id=1").Scan(&result.epoch, &result.recovery, &result.blocked))
	return result
}

func obsoletePolicyMigrationDatabase(t *testing.T) string {
	t.Helper()
	path := initializedOfflineDatabase(t)
	db, err := sql.Open("sqlite", path)
	require(t, err)
	defer func() { require(t, db.Close()) }()
	_, err = db.ExecContext(t.Context(), `INSERT INTO principals(id,issuer,subject) VALUES('disabled-owner','https://issuer.example/','alice');
INSERT INTO owner_policies(principal,value) VALUES('disabled-owner','{"Enabled":false,"Scopes":["task:dispatch"],"Ceiling":{"Providers":["old-provider"],"Permissions":["read-only"],"MaxBudgetSeconds":60},"MaxDevices":2}');
DROP INDEX operations_retained_bodies; DROP INDEX operations_preparations; DROP INDEX operations_preparation_key; ALTER TABLE operations DROP COLUMN preparation_key; ALTER TABLE operations DROP COLUMN preparation_expires_ns;
PRAGMA user_version=9;`)
	require(t, err)
	return path
}

type policyMigrationState struct {
	version int
	value   string
}

func readPolicyMigrationState(t *testing.T, path string) policyMigrationState {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require(t, err)
	defer func() { require(t, db.Close()) }()
	var state policyMigrationState
	require(t, db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&state.version))
	require(t, db.QueryRowContext(t.Context(), "SELECT value FROM owner_policies WHERE principal='disabled-owner'").Scan(&state.value))
	return state
}

func TestOfflinePolicyMigrationPreviewsWithoutChangesAndRequiresExplicitAcceptance(t *testing.T) {
	path := obsoletePolicyMigrationDatabase(t)
	before := readPolicyMigrationState(t, path)
	code, output, diagnostic := command(t, "migrate", "--database", path, "--preview", "--accept-execution-policy-removal")
	if code != 0 || diagnostic != "" || readPolicyMigrationState(t, path) != before {
		t.Fatal("migration preview changed schema or saved access policy")
	}
	var preview registry.MigrationPreview
	require(t, json.Unmarshal([]byte(output), &preview))
	if preview.FromVersion != 9 || preview.ToVersion != 10 || preview.GrantCount != 0 || preview.OwnerPolicyCount != 1 || preview.ObsoleteExecutionPolicyCount != 1 {
		t.Fatalf("preview returned wrong schema or policy counts: %+v", preview)
	}
	code, refused, diagnostic := command(t, "migrate", "--database", path)
	if code != 2 || refused != output || !strings.Contains(diagnostic, "execution_policy_removal_requires_acceptance") || readPolicyMigrationState(t, path) != before {
		t.Fatal("migration did not preserve policy and return preview until explicit acceptance")
	}
}

func TestOfflinePolicyMigrationAppliesAcceptedRemovalWithoutEnablingOwner(t *testing.T) {
	path := obsoletePolicyMigrationDatabase(t)
	before := readOfflineRecoveryState(t, path)
	code, _, diagnostic := command(t, "migrate", "--database", path, "--accept-execution-policy-removal")
	if code != 0 || diagnostic != "" {
		t.Fatalf("accepted migration failed: %s", diagnostic)
	}
	state := readPolicyMigrationState(t, path)
	if state.version != 10 || strings.Contains(state.value, "Ceiling") || readOfflineRecoveryState(t, path) != before {
		t.Fatal("accepted migration changed identity or left obsolete policy")
	}
	var policy domain.OwnerPolicy
	require(t, json.Unmarshal([]byte(state.value), &policy))
	if policy.Enabled || policy.MaxDevices != 2 || len(policy.Scopes) != 1 || policy.Scopes[0] != domain.TaskDispatch {
		t.Fatal("accepted migration changed disabled access authority")
	}
}
