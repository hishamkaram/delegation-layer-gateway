package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestRecoveryCLIRejectsInvalidInputsBeforeNetwork(t *testing.T) {
	parent := t.TempDir()
	socket := filepath.Join(parent, "admin.sock")
	var calls atomic.Int64
	startAdminResponseServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	root := "ctx1_" + strings.Repeat("a", 64)
	task := strings.Repeat("b", 32)
	cases := []struct{ action, body string }{
		{"begin-recovery", `{}`},
		{"begin-recovery", `{"recovery_id":"recovery","epoch":"caller-chosen"}`},
		{"seal-recovery", `{"recovery_id":"recovery"}`},
		{"register-routing-recovery-roster", `{"recovery_id":"recovery"}`},
		{"register-routing-recovery-roster", `{"recovery_id":"recovery","device_ids":null}`},
		{"recovery-progress", `{"limit":101}`},
		{"list-administrative-tasks", `{"limit":0}`},
		{"drain-administrative-task", `{"device_id":"device","root_guard":"` + root + `","task_id":"` + task + `","project_alias":"project","action":"admit"}`},
		{"drain-administrative-task", `{"device_id":"device","root_guard":"` + root + `","task_id":"` + task + `","project_alias":"project","action":"cancel"}`},
		{"list-routing-permits", `{"limit":1,"after":{}}`},
		{"refresh-project", `{"device_id":"device","project_alias":"project"}`},
	}
	for _, test := range cases {
		path := filepath.Join(parent, "input.json")
		require(t, os.WriteFile(path, []byte(test.body), 0o600))
		code, out, _ := command(t, "admin", "--socket", socket, "--action", test.action, "--input-file", path)
		if code != 2 || out != "" || calls.Load() != 0 {
			t.Fatalf("invalid %s reached network or produced output", test.action)
		}
	}
}

func TestRecoveryCLIBindsValidSessionAndRejectsWrongResponse(t *testing.T) {
	parent := t.TempDir()
	socket := filepath.Join(parent, "admin.sock")
	var calls atomic.Int64
	startAdminResponseServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/recovery/begin" || r.Method != http.MethodPost {
			t.Error("wrong recovery route")
		}
		id := "recovery"
		if calls.Add(1) > 1 {
			id = "foreign"
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(adminapi.RecoverySession{RecoveryID: id, Kind: domain.RestoreRecovery, StartedAt: time.Unix(100, 0)}); err != nil {
			t.Error(err)
		}
	}))
	input := writePrivate(t, filepath.Join(parent, "input.json"), adminapi.RecoveryInput{RecoveryID: "recovery"})
	code, out, _ := command(t, "admin", "--socket", socket, "--action", "begin-recovery", "--input-file", input)
	if code != 0 || !strings.Contains(out, `"recovery_id":"recovery"`) || strings.Contains(out, "epoch") {
		t.Fatal("valid recovery metadata rejected or credential exposed")
	}
	code, out, _ = command(t, "admin", "--socket", socket, "--action", "begin-recovery", "--input-file", input)
	if code != 1 || out != "" || calls.Load() != 2 {
		t.Fatal("foreign recovery identity accepted or replayed")
	}
}

func TestAdminRejectsDuplicateActionBeforeNetwork(t *testing.T) {
	parent := t.TempDir()
	socket := filepath.Join(parent, "admin.sock")
	var calls atomic.Int64
	startAdminResponseServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(adminapi.Mutation{Committed: true}); err != nil {
			t.Error(err)
		}
	}))
	input := writePrivate(t, filepath.Join(parent, "input.json"), adminapi.RecoveryInput{RecoveryID: "recovery"})
	code, out, _ := command(t, "admin", "--socket", socket, "--action", "begin-recovery", "--action", "finish-recovery", "--input-file", input)
	if code != 2 || out != "" || calls.Load() != 0 {
		t.Fatal("ambiguous actions selected a mutation")
	}
}

func TestRecoveryMetadataRejectsUnboundCursorAndMissingTaskReceipt(t *testing.T) {
	root := "ctx1_" + strings.Repeat("a", 64)
	key := adminapi.TaskKey{DeviceID: "device", RootGuard: root, TaskID: strings.Repeat("b", 32)}
	summary := adminapi.AdministrativeTaskSummary{Key: key, Delivery: domain.PossibleSend, Reserved: true}
	if !validAdministrativeTaskPage(adminapi.TaskPageInput{Limit: 1}, adminapi.AdministrativeTaskPage{Items: []adminapi.AdministrativeTaskSummary{summary}, Next: &key}) {
		t.Fatal("valid moving task page rejected")
	}
	wrong := key
	wrong.TaskID = strings.Repeat("c", 32)
	if validAdministrativeTaskPage(adminapi.TaskPageInput{Limit: 1}, adminapi.AdministrativeTaskPage{Items: []adminapi.AdministrativeTaskSummary{summary}, Next: &wrong}) {
		t.Fatal("cursor skipped an unreturned task")
	}
	if validAdministrativeTask(key, adminapi.AdministrativeTask{Key: key, Attributed: false, Delivery: domain.PossibleSend}) {
		t.Fatal("unattributed task without native receipt accepted")
	}
}
