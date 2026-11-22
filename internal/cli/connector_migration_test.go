package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectorMigrationPreviewAcceptanceAndReplay(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	path := filepath.Join(parent, "connector.json")
	// Unknown old provider policy contents are discarded, never echoed or
	// reinterpreted. Identity and immutable project guards remain byte values.
	input := map[string]any{
		"schema_version": 1, "gateway_id": "gateway", "expected_device_id": "device",
		"enrollment_url": "https://example.invalid/v1/enroll", "wss_url": "wss://example.invalid:8443/device",
		"trust_ca_file": filepath.Join(parent, "ca.pem"), "identity_directory": filepath.Join(parent, "identity"),
		"delegate_executable": filepath.Join(parent, "delegate"), "temporary_directory": parent,
		"projects": []map[string]any{{
			"alias": "project", "root": parent, "directory": parent,
			"root_token": strings.Repeat("a", 64), "project_token": "private-pin-canary",
			"providers": []map[string]any{{"provider": "private-provider-canary", "max_budget_seconds": 1}},
		}},
	}
	writePrivate(t, path, input)
	before, err := os.ReadFile(path)
	require(t, err)
	for _, preview := range []bool{true, false} {
		args := []string{"connector", "migrate", "--config", path}
		if preview {
			args = append(args, "--preview")
		}
		code, out, diagnostic := command(t, args...)
		wantCode := exitUsage
		if preview {
			wantCode = exitSuccess
		}
		if code != wantCode || !strings.Contains(out, `"execution_policies":1`) || strings.Contains(out+diagnostic, "canary") || strings.Contains(out, parent) {
			t.Fatalf("preview/refusal: %d %s %s", code, out, diagnostic)
		}
		after, readErr := os.ReadFile(path)
		require(t, readErr)
		if !bytes.Equal(before, after) {
			t.Fatal("preview/refusal changed the configuration")
		}
	}
	for range 2 {
		code, out, diagnostic := command(t, "connector", "migrate", "--config", path, "--accept-execution-policy-removal")
		if code != exitSuccess || diagnostic != "" || !strings.Contains(out, `"to_version":2`) || strings.Contains(out, "canary") {
			t.Fatalf("migration/replay: %d %s %s", code, out, diagnostic)
		}
	}
	assertMigratedConnectorConfiguration(t, path, parent)
}

func assertMigratedConnectorConfiguration(t *testing.T, path, parent string) {
	t.Helper()
	after, err := os.ReadFile(path)
	require(t, err)
	var actual map[string]json.RawMessage
	require(t, json.Unmarshal(after, &actual))
	if string(actual["schema_version"]) != "2" || bytes.Contains(after, []byte("providers")) || !bytes.Contains(after, []byte("private-pin-canary")) || !bytes.Contains(after, []byte(filepath.Join(parent, "identity"))) {
		t.Fatal("migration lost source identity or retained execution policy")
	}
}

func TestConnectorLoadExplainsRequiredMigrationWithoutChangingInput(t *testing.T) {
	path := writePrivate(t, filepath.Join(t.TempDir(), "connector.json"), map[string]any{"schema_version": 1})
	code, out, diagnostic := command(t, "connector", "run", "--config", path)
	if code != exitUsage || out != "" || !strings.Contains(diagnostic, "connector_configuration_migration_required") {
		t.Fatalf("migration error was hidden: %d %s %s", code, out, diagnostic)
	}
}
