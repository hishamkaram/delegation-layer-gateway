package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
)

func TestInitAndIdentityAreExplicitPrivateAndStable(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	path := filepath.Join(parent, "authority.sqlite")
	code, out, diagnostic := command(t, "identity", "--database", path)
	if code == 0 || out != "" || diagnostic == "" {
		t.Fatal("identity silently initialized missing database")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection created authority")
	}
	code, out, diagnostic = command(t, "init", "--database", path)
	if code != 0 || diagnostic != "" {
		t.Fatal("explicit database creation failed")
	}
	var created struct {
		Gateway string `json:"gateway_id"`
	}
	require(t, json.Unmarshal([]byte(out), &created))
	if len(created.Gateway) != 64 {
		t.Fatal("init did not return generated database identity")
	}
	info, err := os.Stat(path)
	require(t, err)
	if !privateFile(info) {
		t.Fatal("init left an unsafe database")
	}
	code, identity, diagnostic := command(t, "identity", "--database", path)
	assertIdentityResponse(t, code, identity, diagnostic, out)
	code, repeated, diagnostic := command(t, "init", "--database", path)
	if code != 1 || repeated != "" || !strings.Contains(diagnostic, "database_creation_failed") || strings.Contains(diagnostic, path) {
		t.Fatal("repeated init overwrote database or exposed native data")
	}
	code, identity, diagnostic = command(t, "identity", "--database", path)
	assertIdentityResponse(t, code, identity, diagnostic, out)
}

func TestDatabaseCommandsRejectUnsafeInputsBeforeCreation(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	privatePath := filepath.Join(parent, "private-canary.sqlite")
	cases := [][]string{{"init"}, {"init", "--database", "relative.sqlite"}, {"init", "--database", privatePath, "--gateway-id", "caller-id"}, {"identity", "--database", privatePath, "--unknown", "private-canary"}}
	for _, args := range cases {
		code, out, diagnostic := command(t, args...)
		if code != 2 || out != "" || strings.Contains(diagnostic, "private-canary") {
			t.Fatal("invalid arguments accepted or echoed")
		}
	}
	require(t, os.Chmod(parent, 0o755))
	code, out, _ := command(t, "init", "--database", privatePath)
	if code != 2 || out != "" {
		t.Fatal("public database parent accepted")
	}
	if _, err := os.Stat(privatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsafe input created database")
	}
}

func TestDatabaseIdentityHonorsRuntimeLeaseAndRejectsSymlink(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	path := filepath.Join(parent, "registry.sqlite")
	code, _, _ := command(t, "init", "--database", path)
	if code != 0 {
		t.Fatal("init failed")
	}
	lease, err := instance.Acquire(filepath.Join(parent, "gateway.lock"))
	require(t, err)
	code, out, diagnostic := command(t, "identity", "--database", path)
	require(t, lease.Close())
	if code != 1 || out != "" || !strings.Contains(diagnostic, "database_unavailable") {
		t.Fatal("inspection bypassed runtime lease")
	}
	alias := filepath.Join(parent, "alias.sqlite")
	require(t, os.Symlink(path, alias))
	code, out, _ = command(t, "identity", "--database", alias)
	if code != 1 || out != "" {
		t.Fatal("identity followed a symlink")
	}
}

func TestDatabaseCommandProcess(t *testing.T) {
	path := os.Getenv("GATEWAY_CLI_DATABASE_FIXTURE")
	if path != "" {
		os.Exit(Run(t.Context(), []string{os.Getenv("GATEWAY_CLI_DATABASE_ACTION"), "--database", path}, os.Stdout, os.Stderr))
	}
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	path = filepath.Join(parent, "process.sqlite")
	invoke := func(action string) []byte {
		child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestDatabaseCommandProcess$")
		child.Env = append(os.Environ(), "GATEWAY_CLI_DATABASE_FIXTURE="+path, "GATEWAY_CLI_DATABASE_ACTION="+action)
		var diagnostic bytes.Buffer
		child.Stderr = &diagnostic
		output, err := child.Output()
		require(t, err)
		if diagnostic.Len() != 0 {
			t.Fatal("successful child wrote diagnostics")
		}
		return output
	}
	created := invoke("init")
	inspected := invoke("identity")
	if !bytes.Equal(created, inspected) || !bytes.Contains(created, []byte(`"gateway_id"`)) {
		t.Fatal("real process restart changed identity")
	}
}

func assertIdentityResponse(t *testing.T, code int, identity, diagnostic, expected string) {
	t.Helper()
	if code != 0 || identity != expected || diagnostic != "" {
		t.Fatal("inspection changed authority or returned diagnostics")
	}
}
