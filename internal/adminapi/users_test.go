package adminapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestOwnerPolicyAdministrationUsesPrivateUnixAndExactSubject(t *testing.T) {
	f := newFixture(t, nil)
	input := adminapi.OwnerPolicyInput{Issuer: "https://issuer.example/", Subject: "alice", Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60, MaxDevices: 2}
	body, err := json.Marshal(input)
	check(t, err)
	public := httptest.NewRecorder()
	f.handler.ServeHTTP(public, httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/users/allow", strings.NewReader(string(body))))
	if public.Code != http.StatusForbidden {
		t.Fatal("public context acquired owner eligibility")
	}
	if _, err = f.store.ReadOwnerPolicy(t.Context(), "owner"); err == nil {
		t.Fatal("public caller read private owner policy")
	}
	var allowed adminapi.OwnerPolicyView
	f.call(t, http.MethodPost, "/v1/users/allow", string(body), &allowed)
	if allowed.Validate() != nil || !allowed.Enabled || allowed.Policy.MaxDevices != 2 || allowed.Policy.MaxBudgetSeconds != 60 {
		t.Fatal("allow response lost the explicit ceiling")
	}
	var shown adminapi.OwnerPolicyView
	f.call(t, http.MethodPost, "/v1/users/show", `{"issuer":"https://issuer.example/","subject":"alice"}`, &shown)
	if shown.PrincipalID != allowed.PrincipalID || !shown.Enabled {
		t.Fatal("policy was not durably bound to its principal")
	}
	input.Issuer = "https://another-issuer.example/"
	body, err = json.Marshal(input)
	check(t, err)
	var other adminapi.OwnerPolicyView
	f.call(t, http.MethodPost, "/v1/users/allow", string(body), &other)
	if other.PrincipalID == allowed.PrincipalID {
		t.Fatal("same subject on another issuer inherited eligibility")
	}
	f.call(t, http.MethodPost, "/v1/principals/revocation", `{"principal_id":"`+allowed.PrincipalID+`","revoked":true}`, nil)
	f.call(t, http.MethodPost, "/v1/users/disable", `{"issuer":"https://issuer.example/","subject":"alice"}`, nil)
	f.call(t, http.MethodPost, "/v1/principals/revocation", `{"principal_id":"`+allowed.PrincipalID+`","revoked":false}`, nil)
	f.call(t, http.MethodPost, "/v1/users/show", `{"issuer":"https://issuer.example/","subject":"alice"}`, &shown)
	if shown.Enabled || shown.PrincipalID != allowed.PrincipalID || shown.Policy.MaxDevices != 2 || shown.Policy.MaxBudgetSeconds != 60 {
		t.Fatal("unrevocation resurrected disabled authority or changed its limits")
	}
}

func TestOwnerPolicyCannotGrantManagementAsTaskAuthority(t *testing.T) {
	f := newFixture(t, nil)
	status, _ := f.request(t, http.MethodPost, "/v1/users/allow", `{"issuer":"https://issuer.example/","subject":"alice","scopes":["device:manage"],"providers":["claude:print"],"permissions":["read-only"],"max_budget_seconds":60,"max_devices":2}`)
	if status != http.StatusBadRequest {
		t.Fatal("management scope became an owner task grant")
	}
}
