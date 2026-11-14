package deviceclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This owned test executable implements only Native root inspection. It never
// launches a provider or reads a real Delegate installation/state directory.
func TestMain(m *testing.M) {
	if os.Getenv("GATEWAY_SDK_NATIVE_FIXTURE") == "1" {
		os.Exit(runtimeNativeFixture(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runtimeNativeFixture(args []string) int {
	if len(args) < 2 || args[0] != "context" || args[1] != "inspect" {
		return 80
	}
	root := ""
	for i, arg := range args {
		if arg == "--root" && i+1 < len(args) {
			root = args[i+1]
		}
	}
	if !filepath.IsAbs(root) {
		return 81
	}
	if err := os.WriteFile(filepath.Join(root, "sdk-native-started"), []byte("started"), 0o600); err != nil {
		return 82
	}
	if _, err := os.Stat(filepath.Join(root, "sdk-native-block")); err == nil {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err = os.Stat(filepath.Join(root, "sdk-native-release")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return 83
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	response := map[string]any{"schema_version": 1, "command": "context", "admission": "unknown", "liveness": "undetermined", "publication": "unknown", "connector": map[string]any{"contract_version": 1, "features": []string{"namespace-admission-v1", "namespace-mutation-lease-v1", "workspace-constrained-connector-v1"}, "root_token": strings.Repeat("a", 64), "origin_registered": false}}
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		return 84
	}
	return 0
}
