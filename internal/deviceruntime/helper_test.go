package deviceruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This test executable is an owned public-CLI fixture. It accepts only context
// inspect, never launches a provider, and keeps its temporary evidence local.
func TestMain(m *testing.M) {
	if os.Getenv("GATEWAY_RUNTIME_CLI_FIXTURE") == "1" {
		os.Exit(runtimeCLI(os.Args[1:]))
	}
	os.Exit(m.Run())
}

type (
	helperBarrier struct {
		Gateway    string `json:"gateway_id"`
		Recovery   string `json:"recovery_id"`
		Generation string `json:"generation"`
		Open       bool   `json:"admission_open"`
	}
	helperConnector struct {
		Version    int           `json:"contract_version"`
		Features   []string      `json:"features"`
		Root       string        `json:"root_token"`
		Project    string        `json:"project_token"`
		Registered bool          `json:"origin_registered"`
		Barrier    helperBarrier `json:"origin_barrier"`
	}
	helperResponse struct {
		Version     int             `json:"schema_version"`
		Command     string          `json:"command"`
		Admission   string          `json:"admission"`
		Liveness    string          `json:"liveness"`
		Publication string          `json:"publication"`
		Connector   helperConnector `json:"connector"`
	}
)

func runtimeCLI(args []string) int {
	if len(args) < 2 || args[0] != "context" || args[1] != "inspect" {
		return 90
	}
	root, gatewayID := runtimeContextArgs(args)
	if !filepath.IsAbs(root) || gatewayID == "" {
		return 91
	}
	file, err := os.OpenFile(filepath.Join(root, "native-calls"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 92
	}
	_, writeErr := file.WriteString("context\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return 93
	}
	if _, err = os.Stat(filepath.Join(root, "block-native")); err == nil {
		if err = os.WriteFile(filepath.Join(root, "native-started"), []byte("started"), 0o600); err != nil {
			return 94
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err = os.Stat(filepath.Join(root, "release-native")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return 95
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	response := helperResponse{Version: 1, Command: "context", Admission: "unknown", Liveness: "undetermined", Publication: "unknown", Connector: helperConnector{Version: 1, Features: []string{"namespace-admission-v1"}, Root: strings.Repeat("a", 64), Project: "private-local-canary", Registered: true, Barrier: helperBarrier{Gateway: gatewayID, Recovery: "recovery", Generation: "generation", Open: true}}}
	if err = json.NewEncoder(os.Stdout).Encode(response); err != nil {
		return 96
	}
	return 0
}

func runtimeContextArgs(args []string) (root, gatewayID string) {
	for index, arg := range args {
		if index+1 >= len(args) {
			continue
		}
		switch arg {
		case "--root":
			root = args[index+1]
		case "--gateway-id":
			gatewayID = args[index+1]
		}
	}
	return root, gatewayID
}
