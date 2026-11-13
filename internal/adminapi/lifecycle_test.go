package adminapi_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestShutdownJoinsInFlightMutationAndAllowsRestart(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	f := newFixture(t, func(ctx context.Context, _ domain.DeviceID) error {
		close(entered)
		defer close(exited)
		<-ctx.Done()
		return ctx.Err()
	})
	f.device(t)
	leasePath := filepath.Join(filepath.Dir(f.socket), ".admin.lock")
	before, err := os.Stat(leasePath)
	check(t, err)
	requestDone := make(chan error, 1)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://unix/v1/devices/revocation", strings.NewReader(`{"device_id":"device","revoked":true}`))
	check(t, err)
	request.Header.Set("Content-Type", "application/json")
	go func() {
		response, callErr := f.client.Do(request)
		if callErr == nil {
			_, readErr := io.Copy(io.Discard, response.Body)
			callErr = errors.Join(readErr, response.Body.Close())
		}
		requestDone <- callErr
	}()
	// A test failure still cancels and joins both the HTTP server and its client.
	t.Cleanup(func() { f.cancel(); f.stop(); <-requestDone })
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("disconnect callback not reached")
	}
	f.cancel()
	f.stop()
	select {
	case <-exited:
	default:
		t.Fatal("server returned before mutation handler joined")
	}
	if _, err = os.Lstat(f.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket retained: %v", err)
	}
	after, err := os.Stat(leasePath)
	check(t, err)
	if !os.SameFile(before, after) {
		t.Fatal("stable lease inode replaced")
	}
	f.start(t)
	if !f.device(t).Revoked {
		t.Fatal("durable revocation lost on listener restart")
	}
}

func TestListenerRefusesExistingPathsAndInsecureParents(t *testing.T) {
	f := newFixture(t, nil)
	if other, err := adminapi.Listen(f.socket, f.handler); err == nil {
		check(t, other.Close())
		t.Fatal("duplicate owner admitted")
	}
	f.device(t) // Duplicate attempt must not disturb the current socket.
	f.stop()
	t.Run("stale-socket", func(t *testing.T) {
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: f.socket, Net: "unix"})
		check(t, err)
		listener.SetUnlinkOnClose(false)
		check(t, listener.Close())
		before, err := os.Lstat(f.socket)
		check(t, err)
		if server, listenErr := adminapi.Listen(f.socket, f.handler); listenErr == nil {
			check(t, server.Close())
			t.Fatal("stale socket silently removed")
		}
		after, err := os.Lstat(f.socket)
		check(t, err)
		if !os.SameFile(before, after) {
			t.Fatal("stale socket replaced")
		}
		check(t, os.Remove(f.socket))
	})
	t.Run("regular-file", func(t *testing.T) {
		check(t, os.WriteFile(f.socket, []byte("owner-canary"), 0o600))
		if server, err := adminapi.Listen(f.socket, f.handler); err == nil {
			check(t, server.Close())
			t.Fatal("foreign file replaced")
		}
		data, err := os.ReadFile(f.socket)
		check(t, err)
		if string(data) != "owner-canary" {
			t.Fatal("foreign file changed")
		}
		check(t, os.Remove(f.socket))
	})
	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(filepath.Dir(f.socket), "target")
		check(t, os.WriteFile(target, []byte("owner"), 0o600))
		check(t, os.Symlink(target, f.socket))
		if server, err := adminapi.Listen(f.socket, f.handler); err == nil {
			check(t, server.Close())
			t.Fatal("foreign symlink followed")
		}
		targetAfter, err := os.Readlink(f.socket)
		check(t, err)
		if targetAfter != target {
			t.Fatal("foreign symlink replaced")
		}
		check(t, os.Remove(f.socket))
	})
	t.Run("insecure-parent", func(t *testing.T) {
		parent := t.TempDir()
		check(t, os.Chmod(parent, 0o755))
		if server, err := adminapi.Listen(filepath.Join(parent, "admin.sock"), f.handler); err == nil {
			check(t, server.Close())
			t.Fatal("insecure parent accepted")
		}
	})
}

func TestCloseNeverRemovesReplacedSocketPath(t *testing.T) {
	f := newFixture(t, nil)
	f.stop()
	server, err := adminapi.Listen(f.socket, f.handler)
	check(t, err)
	check(t, os.Remove(f.socket))
	check(t, os.WriteFile(f.socket, []byte("replacement"), 0o600))
	if err = server.Close(); err == nil {
		t.Fatal("ownership change not surfaced")
	}
	data, err := os.ReadFile(f.socket)
	check(t, err)
	if string(data) != "replacement" {
		t.Fatal("cleanup removed replacement owned by another actor")
	}
}
