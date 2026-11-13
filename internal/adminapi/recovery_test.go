package adminapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
)

type unusedRecoveryLink struct{}

func (unusedRecoveryLink) Snapshot(domain.DeviceID) (gateway.LinkSnapshot, error) {
	return gateway.LinkSnapshot{}, domain.ErrInvalid
}

func (unusedRecoveryLink) Reserve(context.Context, domain.DeviceID, domain.OperationID, protocol.Command) (gateway.Reservation, error) {
	return nil, domain.ErrInvalid
}

type projectInspectorFunc func(context.Context, domain.Destination, domain.ContextBinding) (protocol.ProjectCapability, domain.Transmission, error)

func (f projectInspectorFunc) Inspect(ctx context.Context, route domain.Destination, binding domain.ContextBinding) (protocol.ProjectCapability, domain.Transmission, error) {
	return f(ctx, route, binding)
}

func configureRecovery(t *testing.T, f *fixture) {
	t.Helper()
	f.stop()
	namespace, err := recovery.New(f.store, unusedRecoveryLink{}, "gateway", func() time.Time { return f.now }, gateway.RoutingObserverFunc(func(gateway.RoutingObservation) {}))
	check(t, err)
	restorer, err := recovery.NewRestorer(f.store, namespace, func() time.Time { return f.now })
	check(t, err)
	drainer, err := recovery.NewDrainer(f.store, namespace, func() time.Time { return f.now })
	check(t, err)
	inspector := projectInspectorFunc(func(_ context.Context, route domain.Destination, binding domain.ContextBinding) (protocol.ProjectCapability, domain.Transmission, error) {
		return protocol.ProjectCapability{Alias: string(route.Project), Context: protocol.ContextBinding{Root: string(binding.Root), Project: string(binding.Project)}, ContractVersion: protocol.Version, Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}}, domain.Transmission{Credential: domain.CredentialRef{Epoch: "credential-must-stay-private"}}, nil
	})
	f.handler, err = adminapi.NewHandler(adminapi.Options{Store: f.store, Authority: f.authority, Disconnector: disconnectFunc(func(context.Context, domain.DeviceID) error { return nil }), Random: rand.Reader, Now: func() time.Time { return f.now }, Recoveries: restorer, Tasks: drainer, Permits: f.store, Projects: inspector})
	check(t, err)
	f.start(t)
}

func TestRecoveryControlsUsePrivateUnixAuthorityAndRegistry(t *testing.T) {
	f := newFixture(t, nil)
	configureRecovery(t, f)
	exerciseEmptyRecovery(t, f)
	checkRecoveryMetadataPrivacy(t, f)
}

func exerciseEmptyRecovery(t *testing.T, f *fixture) {
	t.Helper()
	var first, retry adminapi.RecoverySession
	f.call(t, http.MethodPost, "/v1/recovery/begin", `{"recovery_id":"restore-one"}`, &first)
	f.call(t, http.MethodPost, "/v1/recovery/begin", `{"recovery_id":"restore-one"}`, &retry)
	if first != retry || first.Kind != domain.RestoreRecovery || first.RecoveryID != "restore-one" {
		t.Fatal("recovery retry changed durable identity")
	}
	var progress adminapi.RecoveryProgress
	f.call(t, http.MethodPost, "/v1/recovery/progress", `{"recovery_id":"restore-one","limit":100}`, &progress)
	if progress.Validate() != nil || progress.Session.RecoveryID != first.RecoveryID || progress.Status != domain.RecoveryActive || len(progress.Destinations) != 0 {
		t.Fatal("progress did not read authoritative recovery")
	}
	f.call(t, http.MethodPost, "/v1/recovery/routing-roster", `{"recovery_id":"restore-one","device_ids":[]}`, nil)
	f.call(t, http.MethodPost, "/v1/recovery/seal", `{"recovery_id":"restore-one","expected_destinations":0}`, nil)
	f.call(t, http.MethodPost, "/v1/recovery/finish", `{"recovery_id":"restore-one"}`, nil)
	f.call(t, http.MethodPost, "/v1/recovery/progress", `{"recovery_id":"restore-one","limit":1}`, &progress)
	if progress.Status != domain.RecoveryFinished {
		t.Fatal("finish did not reach Registry")
	}
}

func checkRecoveryMetadataPrivacy(t *testing.T, f *fixture) {
	t.Helper()
	for _, path := range []string{"/v1/tasks/list", "/v1/routing/permits"} {
		status, data := f.request(t, http.MethodPost, path, `{"limit":100}`)
		if status != http.StatusOK || bytes.Contains(data, []byte("epoch")) || bytes.Contains(data, []byte("credential")) {
			t.Fatal("metadata page leaked credential data or failed")
		}
	}
	body := `{"device_id":"device","project_alias":"project","root_guard":"` + guard("root") + `","project_guard":"` + guard("project") + `"}`
	status, data := f.request(t, http.MethodPost, "/v1/projects/refresh", body)
	if status != http.StatusOK || bytes.Contains(data, []byte("credential-must-stay-private")) {
		t.Fatal("project refresh leaked transmission credentials")
	}
	var project protocol.ProjectCapability
	check(t, json.Unmarshal(data, &project))
	if project.Alias != "project" || project.Context.Root != guard("root") || project.Context.Project != guard("project") {
		t.Fatal("refresh changed explicit project selection")
	}
}

func TestRecoveryBoundaryRejectsMissingAmbiguousAndProofInputs(t *testing.T) {
	f := newFixture(t, nil)
	root := guard("root")
	task := strings.Repeat("a", 32)
	cases := []struct {
		path, body string
		status     int
	}{
		{"/v1/recovery/begin", `{}`, 400},
		{"/v1/recovery/begin", `{"recovery_id":"recovery","epoch":"caller-chosen"}`, 400},
		{"/v1/recovery/register-root", `{"recovery_id":"recovery","device_id":"device","root_guard":"` + root + `","generation":"caller-chosen"}`, 400},
		{"/v1/recovery/seal", `{"recovery_id":"recovery"}`, 400},
		{"/v1/recovery/routing-roster", `{"recovery_id":"recovery"}`, 400},
		{"/v1/recovery/routing-roster", `{"recovery_id":"recovery","device_ids":null}`, 400},
		{"/v1/recovery/routing-roster", `{"recovery_id":"recovery","device_ids":["device","device"]}`, 400},
		{"/v1/recovery/progress", `{"limit":101}`, 400},
		{"/v1/tasks/list", `{"limit":0}`, 400},
		{"/v1/tasks/get", `{"device_id":"device","root_guard":"` + root + `"}`, 400},
		{"/v1/tasks/drain", `{"device_id":"device","root_guard":"` + root + `","task_id":"` + task + `","project_alias":"project","action":"resume"}`, 400},
		{"/v1/tasks/drain", `{"device_id":"device","root_guard":"` + root + `","task_id":"` + task + `","project_alias":"project","action":"cancel"}`, 400},
		{"/v1/tasks/drain", `{"device_id":"device","root_guard":"` + root + `","task_id":"` + task + `","project_alias":"project","action":"resolve","cancellation_id":"` + task + `"}`, 400},
		{"/v1/tasks/drain", `{"device_id":"device","root_guard":"` + root + `","task_id":"` + task + `","project_alias":"project","action":"fence","proof":{"validated":true}}`, 400},
		{"/v1/routing/permits", `{"limit":1,"after":{"device_id":"device"}}`, 400},
		{"/v1/recovery/begin", `{"recovery_id":"recovery"}`, 409},
		{"/v1/tasks/list", `{"limit":1}`, 409},
		{"/v1/routing/permits", `{"limit":1}`, 409},
	}
	for _, test := range cases {
		status, data := f.request(t, http.MethodPost, test.path, test.body)
		if status != test.status || bytes.Contains(data, []byte("caller-chosen")) {
			t.Fatalf("%s returned %d %s", test.path, status, data)
		}
	}
}

func TestRecoveryRoutesDenyPublicContext(t *testing.T) {
	f := newFixture(t, nil)
	for _, path := range []string{"/v1/recovery/begin", "/v1/recovery/register-root", "/v1/recovery/routing-roster", "/v1/recovery/seal", "/v1/recovery/progress", "/v1/recovery/advance", "/v1/recovery/finish", "/v1/tasks/list", "/v1/tasks/get", "/v1/tasks/drain", "/v1/routing/permits", "/v1/projects/refresh"} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		f.handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("public %s acquired administrative authority", path)
		}
	}
}
