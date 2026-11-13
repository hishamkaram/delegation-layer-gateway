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

	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
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
	if result.Gateway == "" || result.From != 9 || result.To != 9 {
		t.Fatal("current database migration did not report stable schema9")
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
