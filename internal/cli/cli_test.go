package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/testsupport"
)

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func writePrivate[T any](t *testing.T, path string, value T) string {
	t.Helper()
	data, err := json.Marshal(value)
	require(t, err)
	require(t, os.WriteFile(path, data, 0o600))
	return path
}

func command(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(t.Context(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestHelpVersionAndErrorsNeverEchoArgumentsOrEnvironment(t *testing.T) {
	t.Setenv("AUTH0_CLIENT_SECRET", "private-canary-secret")
	for _, args := range [][]string{{"--help"}, {"serve", "--help"}, {"connector", "enroll", "--help"}, {"version"}} {
		code, out, err := command(t, args...)
		if code != 0 || out == "" || err != "" || strings.Contains(out, "private-canary") {
			t.Fatalf("command %v: %d %s %s", args, code, out, err)
		}
	}
	for _, args := range [][]string{{"unknown-private-canary"}, {"serve", "--secret=private-canary"}, {"connector", "enroll", "--token", "private-canary"}, {"version", "private-canary"}} {
		code, out, err := command(t, args...)
		if code != 2 || out != "" || strings.Contains(err, "private-canary") {
			t.Fatalf("unsafe argument diagnostics: %d %s %s", code, out, err)
		}
	}
}

func TestPrivateInputsRejectAliasesModesOversizeAndShellText(t *testing.T) {
	parent := t.TempDir()
	valid := filepath.Join(parent, "input.json")
	require(t, os.WriteFile(valid, []byte(`{}`), 0o600))
	public := filepath.Join(parent, "public.json")
	require(t, os.WriteFile(public, []byte(`{}`), 0o644))
	alias := filepath.Join(parent, "alias.json")
	require(t, os.Symlink(valid, alias))
	hardlink := filepath.Join(parent, "hardlink.json")
	require(t, os.Link(valid, hardlink))
	for _, path := range []string{public, alias, hardlink, parent, "relative-private-canary"} {
		if _, err := privateRead(path, 64); err == nil {
			t.Fatalf("unsafe input accepted: %s", path)
		}
	}
	oversized := filepath.Join(parent, "oversized")
	require(t, os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, 65), 0o600))
	if _, err := privateRead(oversized, 64); err == nil {
		t.Fatal("oversized input accepted")
	}
	script := filepath.Join(parent, "config.json")
	marker := filepath.Join(parent, "executed")
	require(t, os.WriteFile(script, []byte("$(touch "+marker+") private-canary"), 0o600))
	code, out, err := command(t, "serve", "--config", script)
	if code != 2 || out != "" || strings.Contains(err, "private-canary") {
		t.Fatal("configuration was executed or echoed")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("shell configuration executed")
	}
}

type disconnectFixture struct{}

func (disconnectFixture) Disconnect(context.Context, domain.DeviceID) error { return nil }

type adminFixture struct {
	socket, parent string
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	parent := testsupport.PrivateSocketDirectory(t)
	require(t, os.Chmod(parent, 0o700))
	authority := adminapi.NewAuthorizer()
	store, err := registry.Create(t.Context(), filepath.Join(parent, "registry.sqlite"), registry.CreateOptions{Admin: authority})
	require(t, err)
	t.Cleanup(func() { require(t, store.Close()) })
	handler, err := adminapi.NewHandler(adminapi.Options{Store: store, Authority: authority, Disconnector: disconnectFixture{}, Random: rand.Reader, Now: time.Now})
	require(t, err)
	socket := filepath.Join(parent, "admin.sock")
	server, err := adminapi.Listen(socket, handler)
	require(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require(t, server.Close())
		serveErr := <-done
		if serveErr != nil {
			t.Error(serveErr)
		}
	})
	// Actual HTTP request ensures Serve owns the accept loop before cleanup.
	input := writePrivate(t, filepath.Join(parent, "register.json"), adminapi.RegisterDeviceInput{DeviceID: "device", Name: "Workstation"})
	code, out, diagnostic := command(t, "admin", "--socket", socket, "--action", "register-device", "--input-file", input)
	if code != 0 || !strings.Contains(out, `"device_id":"device"`) || diagnostic != "" {
		t.Fatalf("real admin setup: %d %s %s", code, out, diagnostic)
	}
	return &adminFixture{socket: socket, parent: parent}
}

func TestAdminTokenRequiresExclusivePrivateOutputAndNeverPrintsCredential(t *testing.T) {
	f := newAdminFixture(t)
	input := writePrivate(t, filepath.Join(f.parent, "enrollment.json"), adminapi.EnrollmentInput{DeviceID: "device", Mode: domain.Regular, Generation: 1})
	code, out, diagnostic := command(t, "admin", "--socket", f.socket, "--action", "issue-enrollment-token", "--input-file", input)
	if code != 2 || out != "" || !strings.Contains(diagnostic, "credential_output_required") {
		t.Fatal("one-time token allowed terminal output")
	}
	output := filepath.Join(f.parent, "token.json")
	t.Setenv("HTTP_PROXY", "http://private-canary.invalid")
	code, out, diagnostic = command(t, "admin", "--socket", f.socket, "--action", "issue-enrollment-token", "--input-file", input, "--output-file", output)
	if code != 0 || out != "" || diagnostic != "" {
		t.Fatalf("private token delivery: %d %s %s", code, out, diagnostic)
	}
	data, err := os.ReadFile(output)
	require(t, err)
	var token adminapi.Enrollment
	require(t, json.Unmarshal(data, &token))
	if token.Token == "" {
		t.Fatal("token not delivered")
	}
	info, err := os.Stat(output)
	require(t, err)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("token output not private")
	}
	code, out, diagnostic = command(t, "admin", "--socket", f.socket, "--action", "issue-enrollment-token", "--input-file", input, "--output-file", output)
	if code != 2 || out != "" || strings.Contains(diagnostic, token.Token) {
		t.Fatal("existing credential overwritten or printed")
	}
	after, err := os.ReadFile(output)
	require(t, err)
	if !bytes.Equal(data, after) {
		t.Fatal("existing output changed")
	}
	bound, err := readToken(output, "device")
	require(t, err)
	if bound != token.Token {
		t.Fatal("connector token-file format incompatible with admin output")
	}
}

func TestReplacementRequiresValidInputsAndCancelledCommandsHaveNoSideEffects(t *testing.T) {
	parent := t.TempDir()
	missing := filepath.Join(parent, "private-canary-missing")
	code, out, err := command(t, "connector", "enroll", "--config", missing, "--token-file", missing, "--replace-existing")
	if code != 2 || out != "" || !strings.Contains(err, "private_input_invalid") || strings.Contains(err, missing) {
		t.Fatal("replacement accepted malformed private inputs")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var stdout, stderr bytes.Buffer
	if code = Run(ctx, []string{"admin", "--socket", missing, "--action", "issue-enrollment-token", "--input-file", missing, "--output-file", filepath.Join(parent, "token")}, &stdout, &stderr); code != 0 {
		t.Fatal("already-cancelled context not handled")
	}
	if _, err := os.Lstat(filepath.Join(parent, "token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled command created credential output")
	}
}

func TestCredentialOutputPreparedBeforeMutationAndForeignNamespacePreserved(t *testing.T) {
	parent := testsupport.PrivateSocketDirectory(t)
	require(t, os.Chmod(parent, 0o700))
	socket := filepath.Join(parent, "fixture.sock")
	output := filepath.Join(parent, "token.json")
	listener, err := net.Listen("unix", socket)
	require(t, err)
	calls := 0
	var mu sync.Mutex
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		info, statErr := os.Stat(output)
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Error("mutation preceded private output ownership")
			http.Error(w, "unavailable", 500)
			return
		}
		require(t, os.Remove(output))
		require(t, os.WriteFile(output, []byte("foreign-private-canary"), 0o600))
		w.Header().Set("Content-Type", "application/json")
		require(t, json.NewEncoder(w).Encode(adminapi.Enrollment{Token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DeviceID: "device", ExpiresAt: time.Now().Add(time.Minute)}))
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		require(t, server.Close())
		serveErr := <-done
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Error(serveErr)
		}
	})
	input := writePrivate(t, filepath.Join(parent, "input.json"), adminapi.EnrollmentInput{DeviceID: "device", Mode: domain.Regular, Generation: 1})
	code, out, diagnostic := command(t, "admin", "--socket", socket, "--action", "issue-enrollment-token", "--input-file", input, "--output-file", output)
	if code != 3 || out != "" || strings.Contains(diagnostic, "private-canary") || !strings.Contains(diagnostic, "credential_output_unconfirmed") {
		t.Fatalf("namespace uncertainty hidden: %d %s %s", code, out, diagnostic)
	}
	data, err := os.ReadFile(output)
	require(t, err)
	if string(data) != "foreign-private-canary" {
		t.Fatal("foreign replacement overwritten")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatal("unexpected request replay")
	}
}
