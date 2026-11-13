package testsupport_test

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/testsupport"
)

func TestPrivateSocketDirectoryBindsDespiteLongAmbientTemporaryPath(t *testing.T) {
	ambient := filepath.Join(t.TempDir(), strings.Repeat("long", 32))
	if err := os.Mkdir(ambient, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", ambient)
	oversized := filepath.Join(ambient, "admin.sock")
	if listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: oversized, Net: "unix"}); err == nil {
		if closeErr := listener.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("counterexample path unexpectedly fits a Unix socket")
	}
	var directory string
	if !t.Run("private socket fixture", func(t *testing.T) {
		directory = testsupport.PrivateSocketDirectory(t)
		physical, err := filepath.EvalSymlinks(directory)
		if err != nil || physical != directory {
			t.Fatalf("noncanonical socket directory: %q, %v", directory, err)
		}
		info, err := os.Stat(directory)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("socket directory is not private: %v", err)
		}
		socket := filepath.Join(directory, "admin.sock")
		// Darwin's sockaddr_un has 104 bytes including its final NUL.
		if len(socket) >= 104 {
			t.Fatalf("socket path exceeds the supported platform bound: %d", len(socket))
		}
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}) {
		t.Fatal("socket fixture failed; its evidence was retained")
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("successful socket fixture was not removed: %v", err)
	}
}

func TestPrivateSocketDirectoryRetainsFailedFixture(t *testing.T) {
	const markerVariable = "GATEWAY_SOCKET_FIXTURE_MARKER"
	if marker := os.Getenv(markerVariable); marker != "" {
		directory := testsupport.PrivateSocketDirectory(t)
		if err := os.WriteFile(filepath.Join(directory, "evidence"), []byte("fixture evidence"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(marker, []byte(directory), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Fatal("intentional fixture failure; no listener or descendant started")
	}
	marker := filepath.Join(testsupport.PrivateSocketDirectory(t), "retained-path")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPrivateSocketDirectoryRetainsFailedFixture$")
	command.Env = append(os.Environ(), markerVariable+"="+marker)
	output, err := command.CombinedOutput() // Owns the exact child Wait.
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || ctx.Err() != nil {
		t.Fatalf("intentional failure fixture did not complete: %v, %s", err, output)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	directory := string(data)
	parent, err := filepath.EvalSymlinks("/tmp")
	if err != nil || filepath.Dir(directory) != parent || !strings.HasPrefix(filepath.Base(directory), "gw-sock-") {
		t.Fatalf("child returned an invalid fixture locator: %q, %v", directory, err)
	}
	// The joined child created only ordinary files; no actor needs this scope.
	t.Cleanup(func() {
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			t.Errorf("remove joined sentinel fixture: %v", removeErr)
		}
	})
	evidence, err := os.ReadFile(filepath.Join(directory, "evidence"))
	if err != nil || string(evidence) != "fixture evidence" {
		t.Fatalf("failed fixture evidence was removed: %v", err)
	}
	if !strings.Contains(string(output), directory) {
		t.Fatal("failed fixture did not report its retained directory")
	}
}
