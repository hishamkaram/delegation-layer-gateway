package deviceidentity

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if path := os.Getenv("GATEWAY_DEVICE_LEASE_TEST"); path != "" {
		store, openErr := Open(path)
		if store != nil {
			if closeErr := store.Close(); closeErr != nil {
				os.Exit(12)
			}
		}
		if errors.Is(openErr, ErrBusy) {
			os.Exit(0)
		}
		os.Exit(11)
	}
	os.Exit(m.Run())
}

func TestInstanceLeaseExcludesAnotherProcessAndPersistsPrivateFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	store := openOwned(t, path)
	if _, keyErr := store.EnsureKey(rand.Reader); keyErr != nil {
		t.Fatal(keyErr)
	}
	executable, exeErr := os.Executable()
	if exeErr != nil {
		t.Fatal(exeErr)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable)
	command.Env = append(os.Environ(), "GATEWAY_DEVICE_LEASE_TEST="+path, "GORACE=atexit_sleep_ms=0")
	if runErr := command.Run(); runErr != nil {
		t.Fatal("another process acquired the identity lease")
	}
	for _, name := range []string{"", stateName, "instance.lock"} {
		info, statErr := os.Lstat(filepath.Join(path, name))
		if statErr != nil {
			t.Fatal(statErr)
		}
		expected := os.FileMode(0o600)
		if name == "" {
			expected = 0o700
		}
		if info.Mode().Perm() != expected {
			t.Fatal("identity material was not private")
		}
	}
	if closeErr := store.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	second := openOwned(t, path)
	if _, keyErr := second.EnsureKey(nil); keyErr != nil {
		t.Fatal("persisted key was lost across lease transfer")
	}
}

func TestRejectsUnsafeDirectoryAndStateFiles(t *testing.T) {
	for _, kind := range []string{"public_directory", "directory_symlink", "state_symlink", "state_public", "state_hardlink", "state_corrupt"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "identity")
			if mkdirErr := os.Mkdir(path, 0o700); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
			path = unsafeIdentity(t, parent, path, kind)
			candidate, openErr := Open(path)
			if candidate != nil {
				if closeErr := candidate.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if !errors.Is(openErr, ErrInvalid) {
				t.Fatal("unsafe private identity boundary accepted")
			}
		})
	}
}

func unsafeIdentity(t *testing.T, parent, path, kind string) string {
	t.Helper()
	switch kind {
	case "public_directory":
		if chmodErr := os.Chmod(path, 0o755); chmodErr != nil {
			t.Fatal(chmodErr)
		}
	case "directory_symlink":
		link := filepath.Join(parent, "link")
		if linkErr := os.Symlink(path, link); linkErr != nil {
			t.Fatal(linkErr)
		}
		return link
	default:
		foreign := filepath.Join(parent, "foreign")
		if writeErr := os.WriteFile(foreign, []byte("{}"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		unsafeStateFile(t, filepath.Join(path, stateName), foreign, kind)
	}
	return path
}

func unsafeStateFile(t *testing.T, target, foreign, kind string) {
	t.Helper()
	switch kind {
	case "state_symlink":
		if linkErr := os.Symlink(foreign, target); linkErr != nil {
			t.Fatal(linkErr)
		}
	case "state_hardlink":
		if linkErr := os.Link(foreign, target); linkErr != nil {
			t.Fatal(linkErr)
		}
	case "state_public":
		if writeErr := os.WriteFile(target, []byte("{}"), 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
	case "state_corrupt":
		if writeErr := os.WriteFile(target, []byte("{\"version\":1"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
}

func TestPreRenameFailureRetainsPreviousAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	store := openOwned(t, path)
	if mkdirErr := os.Mkdir(filepath.Join(path, stateName), 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	if _, keyErr := store.EnsureKey(rand.Reader); !errors.Is(keyErr, ErrInvalid) {
		t.Fatal("conflicting destination did not reject commit")
	}
	entries, readErr := os.ReadDir(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if entry.Name() != stateName && entry.Name() != "instance.lock" {
			t.Fatal("failed precommit left owned secret temporary file")
		}
	}
	if removeErr := os.Remove(filepath.Join(path, stateName)); removeErr != nil {
		t.Fatal(removeErr)
	}
	if _, keyErr := store.EnsureKey(rand.Reader); keyErr != nil {
		t.Fatal("failed precommit changed in-memory authority")
	}
}

func TestDirectorySyncFailureRequiresReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	store, openErr := Open(path)
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() {
		closeErr := store.Close()
		if closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			t.Error(closeErr)
		}
	})
	if closeErr := store.directory.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if csr, keyErr := store.EnsureKey(rand.Reader); !errors.Is(keyErr, ErrUncertain) || csr != nil {
		t.Fatal("unsynced rename returned a usable key receipt")
	}
	if _, keyErr := store.EnsureKey(nil); !errors.Is(keyErr, ErrUncertain) {
		t.Fatal("uncertain owner silently continued")
	}
	if closeErr := store.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
		t.Fatal(closeErr)
	}
	restarted := openOwned(t, path)
	if _, keyErr := restarted.EnsureKey(nil); keyErr != nil {
		t.Fatal("atomic renamed key could not be recovered")
	}
}
