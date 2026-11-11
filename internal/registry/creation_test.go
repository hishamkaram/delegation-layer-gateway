package registry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestOpenExistingOnlyNeverInitializesMissingOrEmptyDatabase(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "empty"}[exists], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.sqlite")
			if exists {
				requireOK(t, os.WriteFile(path, nil, 0o600))
			}
			store, err := Open(t.Context(), path, Options{Gateway: "expected-pin"})
			if err == nil {
				requireOK(t, store.Close())
				t.Fatal("Open initialized uncreated authority")
			}
			assertUninitializedRegistryFile(t, path, exists)
			for _, suffix := range []string{"-wal", "-shm"} {
				if _, sidecarErr := os.Stat(path + suffix); !errors.Is(sidecarErr, os.ErrNotExist) {
					t.Fatal("invalid Open created SQLite sidecar")
				}
			}
		})
	}
}

func TestCreateIdentityAndEpochAreDurableExclusiveAndIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := Create(t.Context(), path, CreateOptions{})
	requireOK(t, err)
	id := fixtureIdentity(t, store)
	epoch := fixtureEpoch(t, store)
	if len(id) != 64 || len(epoch) != 64 || string(id) == string(epoch) {
		t.Fatal("authority entropy was not independently allocated")
	}
	info, err := os.Stat(path)
	requireOK(t, err)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("created registry is not private")
	}
	_, deniedErr := store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "device", Name: "Device"})
	requireCode(t, deniedErr, domain.Forbidden)
	requireOK(t, store.Close())
	for range 2 {
		reopened, openErr := Open(t.Context(), path, Options{Gateway: id})
		requireOK(t, openErr)
		if fixtureIdentity(t, reopened) != id || fixtureEpoch(t, reopened) != epoch {
			t.Fatal("reopening rotated durable authority")
		}
		requireOK(t, reopened.Close())
	}
	inspected, inspectErr := ReadIdentity(t.Context(), path)
	requireOK(t, inspectErr)
	if inspected != id {
		t.Fatal("identity inspection returned configuration data")
	}
	if duplicate, createErr := Create(t.Context(), path, CreateOptions{}); createErr == nil {
		requireOK(t, duplicate.Close())
		t.Fatal("Create overwrote existing authority")
	}
	if wrong, wrongErr := Open(t.Context(), path, Options{Gateway: "wrong-pin"}); wrongErr == nil {
		requireOK(t, wrong.Close())
		t.Fatal("incorrect expected pin accepted")
	}
	after, afterErr := ReadIdentity(t.Context(), path)
	requireOK(t, afterErr)
	if after != id {
		t.Fatal("failed expected-pin check changed authority")
	}
}

func TestCreateRefusesAnyExistingEntryAndLeavesFailedInitializationClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	requireOK(t, os.WriteFile(path, []byte("owned empty-or-foreign canary"), 0o600))
	_, err := Create(t.Context(), path, CreateOptions{})
	if !errors.Is(err, os.ErrExist) {
		t.Fatal("existing file was not exclusively refused")
	}
	data, err := os.ReadFile(path)
	requireOK(t, err)
	if string(data) != "owned empty-or-foreign canary" {
		t.Fatal("exclusive failure changed existing bytes")
	}
	for _, reader := range []io.Reader{bytes.NewReader(nil), bytes.NewReader(make([]byte, 63))} {
		incomplete := filepath.Join(t.TempDir(), "incomplete.sqlite")
		if store, createErr := Create(t.Context(), incomplete, CreateOptions{Random: reader}); createErr == nil {
			requireOK(t, store.Close())
			t.Fatal("short entropy created authority")
		}
		if _, statErr := os.Stat(incomplete); statErr != nil {
			t.Fatal("failed initialization file was silently removed")
		}
		if store, openErr := Open(t.Context(), incomplete, Options{Gateway: "expected-pin"}); openErr == nil {
			requireOK(t, store.Close())
			t.Fatal("Open repaired incomplete initialization")
		}
	}
}

func TestOpenRejectsOldAndPartialSchemasWithoutRepair(t *testing.T) {
	for _, version := range []int{4, 5} {
		path := filepath.Join(t.TempDir(), "registry.sqlite")
		requireOK(t, os.WriteFile(path, nil, 0o600))
		db, err := sql.Open("sqlite", path)
		requireOK(t, err)
		query := "PRAGMA user_version=4; CREATE TABLE settings(id INTEGER PRIMARY KEY,gateway TEXT,epoch TEXT); INSERT INTO settings VALUES(1,'old-gateway','old-epoch')"
		if version == 5 {
			query = "PRAGMA user_version=5; CREATE TABLE settings(id INTEGER PRIMARY KEY,gateway TEXT,epoch TEXT); INSERT INTO settings VALUES(1,'partial-gateway','partial-epoch')"
		}
		_, err = db.ExecContext(t.Context(), query)
		requireOK(t, err)
		requireOK(t, db.Close())
		expected := domain.GatewayID("old-gateway")
		if version == 5 {
			expected = "partial-gateway"
		}
		if store, openErr := Open(t.Context(), path, Options{Gateway: expected}); openErr == nil {
			requireOK(t, store.Close())
			t.Fatal("old or partial schema was silently repaired")
		}
		inspect, inspectErr := sql.Open("sqlite", path)
		requireOK(t, inspectErr)
		var tables int
		requireOK(t, inspect.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables))
		requireOK(t, inspect.Close())
		if tables != 1 {
			t.Fatal("Open installed missing schema")
		}
	}
}

func TestCreateCancellationAndIndependentAuthorities(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	_, err := Create(ctx, path, CreateOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("canceled creation did not stop before file mutation")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("canceled creation left database")
	}
	first, err := Create(t.Context(), path, CreateOptions{})
	requireOK(t, err)
	defer func() { requireOK(t, first.Close()) }()
	second, err := Create(t.Context(), filepath.Join(t.TempDir(), "other.sqlite"), CreateOptions{})
	requireOK(t, err)
	defer func() { requireOK(t, second.Close()) }()
	if fixtureIdentity(t, first) == fixtureIdentity(t, second) || fixtureEpoch(t, first) == fixtureEpoch(t, second) {
		t.Fatal("independent creation reused authority")
	}
}

func TestOpenRequiresExpectedPinAndIdentityInspectionIsQueryOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	created, err := Create(t.Context(), path, CreateOptions{})
	requireOK(t, err)
	id := fixtureIdentity(t, created)
	requireOK(t, created.Close())
	if inspected, openErr := Open(t.Context(), path, Options{Admin: fixtureAdmin{}}); !errors.Is(openErr, domain.ErrInvalid) {
		if inspected != nil {
			requireOK(t, inspected.Close())
		}
		t.Fatal("public Open accepted an absent expected identity pin")
	}
	inspected, inspectErr := ReadIdentity(t.Context(), path)
	requireOK(t, inspectErr)
	if inspected != id {
		t.Fatal("inspection changed database identity")
	}
	// ReadIdentity uses this private, non-exposed connection mode. Even direct
	// SQL cannot mutate through it; the public inspection API returns only an ID.
	connection, err := connect(t.Context(), path, fixtureAdmin{}, true)
	requireOK(t, err)
	if _, writeErr := connection.db.ExecContext(t.Context(), "INSERT INTO devices(id,name) VALUES('device','Device')"); writeErr == nil {
		t.Fatal("inspection connection allowed SQL mutation")
	}
	requireOK(t, connection.Close())
	writable, err := Open(t.Context(), path, Options{Gateway: id, Admin: fixtureAdmin{}})
	requireOK(t, err)
	defer func() { requireOK(t, writable.Close()) }()
	_, err = writable.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "device", Name: "Device"})
	requireOK(t, err)
}

func TestCreateRefusesExistingEmptyFileDirectoryAndSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "canary")
	requireOK(t, os.WriteFile(target, []byte("existing authority canary"), 0o600))
	empty := filepath.Join(parent, "empty")
	requireOK(t, os.WriteFile(empty, nil, 0o600))
	directory := filepath.Join(parent, "directory")
	requireOK(t, os.Mkdir(directory, 0o700))
	link := filepath.Join(parent, "symlink")
	requireOK(t, os.Symlink(target, link))
	for _, path := range []string{empty, directory, link} {
		if store, createErr := Create(t.Context(), path, CreateOptions{}); !errors.Is(createErr, os.ErrExist) {
			if store != nil {
				requireOK(t, store.Close())
			}
			t.Fatal("existing entry was not exclusively rejected")
		}
	}
	info, err := os.Stat(empty)
	requireOK(t, err)
	if info.Size() != 0 {
		t.Fatal("Create modified preexisting empty file")
	}
	data, err := os.ReadFile(target)
	requireOK(t, err)
	if string(data) != "existing authority canary" {
		t.Fatal("Create followed symlink")
	}
}

type crashBeforeIdentity struct{}

func (crashBeforeIdentity) Read([]byte) (int, error) { os.Exit(94); return 0, io.ErrUnexpectedEOF }

func TestCreateCrashBeforeIdentityCommitRemainsUnopenable(t *testing.T) {
	if path := os.Getenv("GATEWAY_CREATION_CRASH_FILE"); path != "" {
		_, err := Create(t.Context(), path, CreateOptions{Random: crashBeforeIdentity{}})
		requireOK(t, err)
		t.Fatal("crash reader was not reached inside creation transaction")
	}
	path := filepath.Join(t.TempDir(), "crashed.sqlite")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCreateCrashBeforeIdentityCommitRemainsUnopenable$")
	child.Env = append(os.Environ(), "GATEWAY_CREATION_CRASH_FILE="+path)
	_, err := child.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 94 {
		t.Fatal("creation subprocess did not stop at in-transaction entropy boundary")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatal("crashed initialization file disappeared")
	}
	if store, openErr := Open(t.Context(), path, Options{Gateway: "expected-pin"}); openErr == nil {
		requireOK(t, store.Close())
		t.Fatal("Open repaired crashed initialization")
	}
	if store, createErr := Create(t.Context(), path, CreateOptions{}); !errors.Is(createErr, os.ErrExist) {
		if store != nil {
			requireOK(t, store.Close())
		}
		t.Fatal("Create overwrote crashed initialization")
	}
}

func TestIdentityInspectionDoesNotChangeJournalMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	created, err := Create(t.Context(), path, CreateOptions{})
	requireOK(t, err)
	id := fixtureIdentity(t, created)
	requireOK(t, created.Close())
	database, err := sql.Open("sqlite", path)
	requireOK(t, err)
	var mode string
	requireOK(t, database.QueryRowContext(t.Context(), "PRAGMA journal_mode=DELETE").Scan(&mode))
	requireOK(t, database.Close())
	inspected, err := ReadIdentity(t.Context(), path)
	requireOK(t, err)
	if inspected != id {
		t.Fatal("inspection changed authority")
	}
	reopened, err := sql.Open("sqlite", path)
	requireOK(t, err)
	requireOK(t, reopened.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&mode))
	requireOK(t, reopened.Close())
	if mode != "delete" {
		t.Fatal("identity inspection mutated persistent journal policy")
	}
}

func assertUninitializedRegistryFile(t *testing.T, path string, exists bool) {
	t.Helper()
	info, statErr := os.Stat(path)
	if exists {
		requireOK(t, statErr)
		if info.Size() != 0 {
			t.Fatal("Open altered empty file")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("Open created missing database")
	}
}
