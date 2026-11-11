package adminapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

type disconnectFunc func(context.Context, domain.DeviceID) error

func (f disconnectFunc) Disconnect(ctx context.Context, id domain.DeviceID) error { return f(ctx, id) }

type fixture struct {
	store     *registry.Store
	authority *adminapi.Authorizer
	handler   *adminapi.Handler
	server    *adminapi.Server
	client    *http.Client
	transport *http.Transport
	socket    string
	now       time.Time
	cancel    context.CancelFunc
	done      chan error
	stop      func()
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T, disconnect disconnectFunc) *fixture {
	t.Helper()
	return newFixtureOptions(t, disconnect, nil)
}

func newFixtureOptions(t *testing.T, disconnect disconnectFunc, configure func(*adminapi.Options)) *fixture {
	t.Helper()
	parent := testsupport.PrivateSocketDirectory(t)
	check(t, os.Chmod(parent, 0o700))
	f := &fixture{socket: filepath.Join(parent, "admin.sock"), now: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC), authority: adminapi.NewAuthorizer()}
	var err error
	f.store, err = registry.Create(t.Context(), filepath.Join(parent, "registry.sqlite"), registry.CreateOptions{Admin: f.authority})
	check(t, err)
	t.Cleanup(func() { check(t, f.store.Close()) })
	if disconnect == nil {
		disconnect = func(context.Context, domain.DeviceID) error { return nil }
	}
	options := adminapi.Options{Store: f.store, Authority: f.authority, Disconnector: disconnect, Random: rand.Reader, Now: func() time.Time { return f.now }}
	if configure != nil {
		configure(&options)
	}
	f.handler, err = adminapi.NewHandler(options)
	check(t, err)
	f.start(t)
	return f
}

func (f *fixture) start(t *testing.T) {
	t.Helper()
	var err error
	f.server, err = adminapi.Listen(f.socket, f.handler)
	check(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	f.cancel = cancel
	f.done = make(chan error, 1)
	server, done := f.server, f.done
	go func() { done <- server.Serve(ctx) }()
	f.transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", f.socket)
	}}
	f.client = &http.Client{Transport: f.transport, Timeout: 5 * time.Second}
	transport := f.transport
	var once sync.Once
	f.stop = func() {
		once.Do(func() { transport.CloseIdleConnections(); cancel(); check(t, server.Close()); check(t, <-done) })
	}
	t.Cleanup(f.stop)
	status, _ := f.request(t, http.MethodPost, "/startup-probe", `{}`)
	if status != http.StatusNotFound {
		t.Fatal("server startup probe failed")
	}
}

func (f *fixture) request(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, "http://unix"+path, strings.NewReader(body))
	check(t, err)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(request)
	check(t, err)
	defer func() { check(t, response.Body.Close()) }()
	data, err := io.ReadAll(response.Body)
	check(t, err)
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("administrative response must not be cached")
	}
	return response.StatusCode, data
}

func (f *fixture) call(t *testing.T, method, path, body string, out any) {
	t.Helper()
	status, data := f.request(t, method, path, body)
	if status != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, path, status, data)
	}
	if out != nil {
		check(t, json.Unmarshal(data, out))
	}
}

func (f *fixture) device(t *testing.T) adminapi.Device {
	t.Helper()
	var device adminapi.Device
	f.call(t, http.MethodPost, "/v1/devices", `{"device_id":"device","name":"Workstation"}`, &device)
	return device
}

func guard(value string) string {
	digest := domain.Hash([]byte(value))
	return "ctx1_" + hex.EncodeToString(digest[:])
}

func TestUnixRegistryAdministrativeWorkflow(t *testing.T) {
	f := newFixture(t, nil)
	info, err := os.Stat(f.socket)
	check(t, err)
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("unsafe socket: %v", info.Mode())
	}
	f.device(t)
	body := `{"device_id":"device","project_alias":"project","root_guard":"` + guard("root") + `","project_guard":"` + guard("project") + `"}`
	f.call(t, http.MethodPost, "/v1/projects", body, nil)
	var principal adminapi.Principal
	f.call(t, http.MethodPost, "/v1/principals/resolve", `{"issuer":"https://issuer.example/","subject":"alice"}`, &principal)
	grant := `{"principal_id":"` + principal.PrincipalID + `","device_id":"device","project_alias":"project","scopes":["task:dispatch"],"providers":["codex"],"permissions":["read-only"],"max_budget_seconds":60}`
	f.call(t, http.MethodPut, "/v1/grants", grant, nil)
	actor := domain.Actor{Principal: domain.PrincipalID(principal.PrincipalID), Scopes: domain.ScopeSet{domain.TaskDispatch}}
	request := domain.AuthorizationRequest{Actor: actor, Destination: domain.Destination{Device: "device", Project: "project"}, Scope: domain.TaskDispatch}
	_, err = f.store.Authorize(t.Context(), request)
	check(t, err)
	f.call(t, http.MethodDelete, "/v1/grants", `{"principal_id":"`+principal.PrincipalID+`","device_id":"device","project_alias":"project"}`, nil)
	if _, err = f.store.Authorize(t.Context(), request); err == nil {
		t.Fatal("revoked grant authorized")
	}
	f.call(t, http.MethodPost, "/v1/principals/revocation", `{"principal_id":"`+principal.PrincipalID+`","revoked":true}`, nil)
	var revoked adminapi.Principal
	f.call(t, http.MethodPost, "/v1/principals/resolve", `{"issuer":"https://issuer.example/","subject":"alice"}`, &revoked)
	if !revoked.Revoked || revoked.PrincipalID != principal.PrincipalID {
		t.Fatal("revocation or immutable principal binding lost")
	}
}

func TestPublicMountAndContextSpoofCannotAcquireAdmin(t *testing.T) {
	f := newFixture(t, nil)
	for _, authority := range []*adminapi.Authorizer{f.authority, adminapi.NewAuthorizer(), {}} {
		if authority.AuthorizeAdmin(t.Context()) == nil {
			t.Fatal("public context granted admin")
		}
	}
	public := httptest.NewServer(f.handler)
	defer public.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, public.URL+"/v1/devices", strings.NewReader(`{"device_id":"spoof","name":"secret-canary"}`))
	check(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Admin", "true")
	request.Header.Set("X-Forwarded-For", "unix")
	response, err := public.Client().Do(request)
	check(t, err)
	defer func() { check(t, response.Body.Close()) }()
	data, err := io.ReadAll(response.Body)
	check(t, err)
	if response.StatusCode != 403 || bytes.Contains(data, []byte("secret-canary")) {
		t.Fatalf("public spoof: %d %s", response.StatusCode, data)
	}
	if _, err = f.store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "spoof", Name: "secret-canary"}); err == nil {
		t.Fatal("registry bypassed default-deny admin boundary")
	}
	// Handler invocation with a spoofed network address still has no owned connection proof.
	recorder := httptest.NewRecorder()
	request.RemoteAddr = "@unix"
	f.handler.ServeHTTP(recorder, request)
	if recorder.Code != 403 {
		t.Fatal("RemoteAddr spoof granted admin")
	}
}

func TestStrictRequestsAndRedactedErrors(t *testing.T) {
	f := newFixture(t, nil)
	cases := []struct {
		name, path, body string
		status           int
	}{
		{"unknown", "/v1/devices", `{"device_id":"device","name":"canary","authority":true}`, 400},
		{"caller-root-generation", "/v1/projects", `{"device_id":"device","project_alias":"project","root_guard":"canary","project_guard":"canary","admission_generation":"chosen"}`, 400},
		{"root-context-required", "/v1/roots/initialize", `{"device_id":"device","project_alias":"project"}`, 400},
		{"root-abandon-identity-required", "/v1/roots/abandon", `{"recovery_id":"../canary"}`, 400},
		{"duplicate", "/v1/devices", `{"device_id":"device","device_id":"other","name":"canary"}`, 400},
		{"missing-revocation", "/v1/devices/revocation", `{"device_id":"device"}`, 400},
		{"invalid-id", "/v1/devices", `{"device_id":"bad/~canary","name":"canary"}`, 400},
		{"missing-device", "/v1/devices/revocation", `{"device_id":"missing","revoked":true}`, 404},
		{"query-token", "/v1/devices?token=canary", `{}`, 400},
		{"oversize", "/v1/devices", `{"name":"` + strings.Repeat("x", adminapi.MaxBodyBytes) + `canary"}`, 400},
		{"unknown-route", "/v1/arbitrary-action", `{"canary":true}`, 404},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			status, data := f.request(t, http.MethodPost, test.path, test.body)
			if status != test.status || bytes.Contains(data, []byte("canary")) {
				t.Fatalf("%d %s", status, data)
			}
		})
	}
}

func TestDifferentAuthorizerCannotMutateRegistry(t *testing.T) {
	f := newFixture(t, nil)
	f.stop()
	var err error
	f.handler, err = adminapi.NewHandler(adminapi.Options{Store: f.store, Authority: adminapi.NewAuthorizer(), Disconnector: disconnectFunc(func(context.Context, domain.DeviceID) error { return nil }), Random: rand.Reader, Now: func() time.Time { return f.now }})
	check(t, err)
	f.start(t)
	status, data := f.request(t, http.MethodPost, "/v1/devices", `{"device_id":"device","name":"Workstation"}`)
	if status != http.StatusForbidden || string(data) != `{"code":"forbidden","committed":false}` {
		t.Fatalf("different registry authority accepted: %d %s", status, data)
	}
}

func TestEnrollmentTokenOneTimeDeliveryWithoutCredentialRotation(t *testing.T) {
	f := newFixture(t, nil)
	f.device(t)
	var first, second adminapi.Enrollment
	input := `{"device_id":"device","mode":"regular","generation":1}`
	f.call(t, http.MethodPost, "/v1/enrollment-tokens", input, &first)
	f.call(t, http.MethodPost, "/v1/enrollment-tokens", input, &second)
	if first.Token == second.Token || !first.ExpiresAt.Equal(f.now.Add(10*time.Minute)) {
		t.Fatal("token entropy or lifetime incorrect")
	}
	if device := f.device(t); device.CredentialGeneration != 0 {
		t.Fatal("mere token creation rotated active credential")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first.Token)
	check(t, err)
	if len(decoded) != 32 {
		t.Fatal("token entropy length incorrect")
	}
	serial := bytes.Repeat([]byte{1}, 16)
	intent, err := f.store.BeginEnrollment(t.Context(), domain.EnrollmentAttempt{TokenHash: domain.Hash(decoded), CSRHash: domain.Hash([]byte("csr")), PublicKeyHash: domain.Hash([]byte("key")), Issuance: "issuance", Serial: serial, Now: f.now})
	check(t, err)
	if intent.Credential.Device != "device" || intent.Credential.Generation != 1 {
		t.Fatalf("wrong token binding: %+v", intent.Credential)
	}
	rawSecond, err := base64.RawURLEncoding.DecodeString(second.Token)
	check(t, err)
	_, err = f.store.BeginEnrollment(t.Context(), domain.EnrollmentAttempt{TokenHash: domain.Hash(rawSecond), CSRHash: domain.Hash([]byte("other-csr")), PublicKeyHash: domain.Hash([]byte("other-key")), Issuance: "other", Serial: serial, Now: f.now})
	if err == nil {
		t.Fatal("second token reused already-reserved generation")
	}
	status, data := f.request(t, http.MethodGet, "/v1/enrollment-tokens", `{}`)
	if status != 405 || bytes.Contains(data, []byte(first.Token)) {
		t.Fatal("token was retrievable")
	}
}

func TestDeviceRevocationCommitsBeforeDisconnectFailure(t *testing.T) {
	var f *fixture
	called := false
	durableBeforeDisconnect := false
	f = newFixture(t, func(ctx context.Context, id domain.DeviceID) error {
		called = true
		device, err := f.store.RegisterDevice(ctx, domain.DeviceRegistration{ID: id, Name: "Workstation"})
		if err != nil || !device.Revoked {
			return errors.New("revocation not durable before disconnect")
		}
		durableBeforeDisconnect = true
		return errors.New("secret-path-and-credential-canary")
	})
	f.device(t)
	status, data := f.request(t, http.MethodPost, "/v1/devices/revocation", `{"device_id":"device","revoked":true}`)
	var failure adminapi.Failure
	check(t, json.Unmarshal(data, &failure))
	if status != 503 || failure.Code != "disconnect_unconfirmed" || !failure.Committed || !called || !durableBeforeDisconnect || bytes.Contains(data, []byte("canary")) {
		t.Fatalf("revocation response: %d %s", status, data)
	}
	if !f.device(t).Revoked {
		t.Fatal("disconnect error rolled back revocation")
	}
	called = false
	f.call(t, http.MethodPost, "/v1/devices/revocation", `{"device_id":"device","revoked":false}`, nil)
	if called || f.device(t).Revoked {
		t.Fatal("unrevocation disconnected or remained revoked")
	}
}
