package cli

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/testsupport"
)

func TestUsersAllowBuildsTypedPolicyWithoutInputFiles(t *testing.T) {
	socket := filepath.Join(testsupport.PrivateSocketDirectory(t), "admin.sock")
	var calls atomic.Int64
	startAdminResponseServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var input adminapi.OwnerPolicyInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assertOwnerPolicyRequest(t, r, input)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(adminapi.OwnerPolicyView{PrincipalID: "owner", Enabled: true, Policy: input}); err != nil {
			t.Error(err)
		}
	}))
	code, out, diagnostic := command(t, "users", "allow", "--socket", socket, "--issuer", "https://issuer.example/", "--subject", "alice", "--max-devices", "2")
	if code != 0 || out == "" || diagnostic != "" || calls.Load() != 1 {
		t.Fatalf("typed owner command failed: exit%d diagnostic%s", code, diagnostic)
	}
	code, _, _ = command(t, "users", "allow", "--socket", socket, "--issuer", "https://issuer.example/", "--subject", "alice", "--scope", "device:manage")
	if code != 2 || calls.Load() != 1 {
		t.Fatal("invalid policy reached the administrative mutation boundary")
	}
}

func assertOwnerPolicyRequest(t *testing.T, r *http.Request, input adminapi.OwnerPolicyInput) {
	t.Helper()
	if r.URL.Path != "/v1/users/allow" || r.Method != http.MethodPost || input.Validate() != nil {
		t.Error("invalid policy request boundary")
	}
	if input.Issuer != "https://issuer.example/" || input.Subject != "alice" || input.MaxDevices != 2 {
		t.Error("flags changed the requested owner or limits")
	}
	if len(input.Scopes) != 4 {
		t.Error("flags changed the requested authority")
	}
}

func TestUsersAllowRejectsRemovedExecutionPolicyFlags(t *testing.T) {
	socket := filepath.Join(testsupport.PrivateSocketDirectory(t), "absent.sock")
	for _, flag := range []string{"--provider", "--permission", "--max-budget-seconds"} {
		code, _, _ := command(t, "users", "allow", "--socket", socket, "--issuer", "https://issuer.example/", "--subject", "alice", flag, "obsolete-value")
		if code != 2 {
			t.Fatalf("removed execution flag %s passed argument validation", flag)
		}
	}
}
