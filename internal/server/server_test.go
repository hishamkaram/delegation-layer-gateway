package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (b bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(copy)
}

func (f *fixture) session(t *testing.T) *mcp.ClientSession {
	t.Helper()
	client := *f.client
	client.Transport = bearerTransport{base: f.client.Transport, token: f.token(t, f.cfg.Identity.Audience)}
	sdk := mcp.NewClient(&mcp.Implementation{Name: "runtime-test", Version: "1"}, &mcp.ClientOptions{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	connected, err := sdk.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: f.cfg.PublicURL + "/mcp", HTTPClient: &client, DisableStandaloneSSE: true, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	session := checked(t, connected, err)
	t.Cleanup(func() { require(t, session.Close()) })
	return session
}

func TestRuntimeRealJWKSJWTOfficialMCPAndPrivateAdmin(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		status, data := f.request(t, f.client, http.MethodGet, f.cfg.PublicURL+path, nil, "")
		if status != 200 || !bytes.Contains(data, []byte(f.cfg.PublicURL+"/mcp")) {
			t.Fatalf("metadata: %d %s", status, data)
		}
		assertNoCanary(t, data)
	}
	for _, token := range []string{"", "private-canary", f.token(t, "https://wrong.example/mcp")} {
		status, data := f.request(t, f.client, http.MethodPost, f.cfg.PublicURL+"/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`), token)
		if status != 401 {
			t.Fatalf("invalid bearer got%d %s", status, data)
		}
		assertNoCanary(t, data)
	}
	session := f.session(t)
	tools, err := session.ListTools(t.Context(), nil)
	if len(checked(t, tools, err).Tools) != 12 {
		t.Fatal("actual composed SDK did not expose 12 tools")
	}
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_devices", Arguments: json.RawMessage(`{}`)})
	listed := checked(t, result, err)
	if listed.IsError || listed.StructuredContent == nil {
		t.Fatal("signed current JWT could not call MCP inventory")
	}
	var principal adminapi.Principal
	f.adminCall(t, "/v1/principals/resolve", adminapi.ResolvePrincipalInput{Issuer: f.cfg.Identity.Issuer, Subject: "subject"}, &principal)
	revoked := true
	f.adminCall(t, "/v1/principals/revocation", adminapi.PrincipalRevocationInput{PrincipalID: principal.PrincipalID, Revoked: &revoked}, nil)
	status, _ := f.request(t, f.client, http.MethodPost, f.cfg.PublicURL+"/mcp", []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`), f.token(t, f.cfg.Identity.Audience))
	if status != 401 {
		t.Fatal("principal revocation ignored by composed auth")
	}
	for _, path := range []string{"/v1/devices", "/v1/metadata/metrics", "/v1/metadata/health", "/metrics", "/health"} {
		status, _ := f.request(t, f.client, http.MethodGet, f.cfg.PublicURL+path, nil, "")
		if status != 404 {
			t.Fatal("private administration mounted publicly")
		}
	}
	if !f.runtime.Health().AuditHealthy {
		t.Fatal("normal metadata recording failed")
	}
}

func TestAuditFailureIsProtectedHealthAndDoesNotRewriteMCPResult(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	session := f.session(t)
	require(t, f.runtime.audit.Close()) // Real sink fault after initialization.
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_devices", Arguments: json.RawMessage(`{}`)})
	listed := checked(t, result, err)
	if listed.IsError {
		t.Fatal("audit failure corrupted authorized inventory outcome")
	}
	health := f.runtime.Health()
	if health.AuditHealthy || health.AuditFailures == 0 {
		t.Fatal("audit error silently discarded")
	}
	status, data := f.request(t, f.admin, http.MethodGet, "http://unix/v1/metadata/health", nil, "")
	var protected observability.Health
	require(t, json.Unmarshal(data, &protected))
	if status != http.StatusOK || protected.AuditHealthy || protected.AuditFailures == 0 {
		t.Fatal("private Unix health lost sticky audit failure")
	}
	status, data = f.request(t, f.admin, http.MethodGet, "http://unix/v1/metadata/metrics", nil, "")
	if status != http.StatusOK || !bytes.Contains(data, []byte("gateway_audit_failures_total")) || bytes.Contains(data, []byte("private-canary")) {
		t.Fatal("protected metrics lost fixed failure state or leaked values")
	}
}

func TestPrivateStorageFailurePrecedesDatabaseCreation(t *testing.T) {
	f := configFixture(t)
	require(t, os.Remove(f.cfg.Database))
	parent := filepath.Dir(f.cfg.Database)
	require(t, os.Chmod(parent, 0o755))
	defer func() { require(t, os.Chmod(parent, 0o700)) }()
	if constructed, createErr := New(t.Context(), f.cfg, Options{JWKSClient: f.jwks.Client()}); createErr == nil {
		require(t, constructed.Close())
		t.Fatal("insecure storage parent accepted")
	}
	if _, err := os.Lstat(f.cfg.Database); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("database created before parent validation")
	}
}

func TestConstructorFailedBindReleasesOnlyOwnedResources(t *testing.T) {
	f := configFixture(t)
	occupied, err := net.Listen("tcp", f.cfg.PublicAddress)
	require(t, err)
	_, err = New(t.Context(), f.cfg, Options{JWKSClient: f.jwks.Client()})
	if err == nil {
		t.Fatal("occupied public bind accepted")
	}
	require(t, occupied.Close())
	runtime, err := New(t.Context(), f.cfg, Options{JWKSClient: f.jwks.Client()})
	require(t, err)
	require(t, runtime.Close())
	if _, err = os.Lstat(f.cfg.AdminSocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unused runtime leaked administrative socket")
	}
}

func TestConstructorDeviceBindFailureReleasesEarlierPublicBind(t *testing.T) {
	f := configFixture(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	t.Cleanup(func() { require(t, occupied.Close()) })
	f.cfg.DeviceAddress = occupied.Addr().String()
	if constructed, createErr := New(t.Context(), f.cfg, Options{JWKSClient: f.jwks.Client()}); createErr == nil {
		require(t, constructed.Close())
		t.Fatal("occupied device bind accepted")
	}
	// The earlier public listener and registry/audit leases must all be reusable.
	f.cfg.DeviceAddress = "127.0.0.1:0"
	runtime, err := New(t.Context(), f.cfg, Options{JWKSClient: f.jwks.Client()})
	require(t, err)
	require(t, runtime.Close())
}

func TestSignedTokenChallengeAndMetadataNeverEchoCanary(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.cfg.PublicURL+"/mcp?private-canary=secret", strings.NewReader(`{"private-canary":"secret"}`))
	require(t, err)
	request.Header.Set("Authorization", "Bearer private-canary")
	request.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(request)
	require(t, err)
	data, readErr := io.ReadAll(response.Body)
	require(t, readErr)
	require(t, response.Body.Close())
	if response.StatusCode != 401 || !strings.Contains(response.Header.Get("WWW-Authenticate"), "resource_metadata=") || !strings.Contains(response.Header.Get("WWW-Authenticate"), f.cfg.PublicURL+"/.well-known/oauth-protected-resource/mcp") {
		t.Fatal("configured OAuth resource challenge missing")
	}
	assertNoCanary(t, data)
	entries, err := os.ReadDir(f.cfg.AuditDirectory)
	require(t, err)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "audit-") {
			data, err := os.ReadFile(filepath.Join(f.cfg.AuditDirectory, entry.Name()))
			require(t, err)
			assertNoCanary(t, data)
		}
	}
}
