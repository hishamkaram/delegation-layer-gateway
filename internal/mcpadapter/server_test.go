package mcpadapter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type schemaWire struct {
	Type        json.RawMessage       `json:"type"`
	Additional  json.RawMessage       `json:"additionalProperties"`
	Properties  map[string]schemaWire `json:"properties"`
	Definitions map[string]schemaWire `json:"$defs"`
	Items       *schemaWire           `json:"items"`
	OneOf       []schemaWire          `json:"oneOf"`
	AnyOf       []schemaWire          `json:"anyOf"`
	Maximum     *float64              `json:"maximum"`
	MaxLength   *int                  `json:"maxLength"`
}
type toolWire struct {
	Name        string               `json:"name"`
	Input       schemaWire           `json:"inputSchema"`
	Output      schemaWire           `json:"outputSchema"`
	Annotations *mcp.ToolAnnotations `json:"annotations"`
	Meta        struct {
		Schemes []struct {
			Type   string   `json:"type"`
			Scopes []string `json:"scopes"`
		} `json:"securitySchemes"`
	} `json:"_meta"`
}

func assertClosed(t *testing.T, schema schemaWire) {
	t.Helper()
	if objectSchema(schema.Type) && !bytes.Equal(schema.Additional, []byte("false")) {
		t.Fatal("Go-derived object schema permits unknown properties")
	}
	for _, property := range schema.Properties {
		assertClosed(t, property)
	}
	for _, definition := range schema.Definitions {
		assertClosed(t, definition)
	}
	if schema.Items != nil {
		assertClosed(t, *schema.Items)
	}
	for _, branch := range schema.OneOf {
		assertClosed(t, branch)
	}
	for _, branch := range schema.AnyOf {
		assertClosed(t, branch)
	}
}

func objectSchema(raw json.RawMessage) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == "object"
	}
	var union []string
	if json.Unmarshal(raw, &union) != nil {
		return false
	}
	for _, kind := range union {
		if kind == "object" {
			return true
		}
	}
	return false
}

type toolExpectation struct {
	read, destructive, idempotent bool
	scopes                        []string
}

func assertToolHints(t *testing.T, tool toolWire, want toolExpectation) {
	t.Helper()
	if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil {
		t.Fatal("missing explicit tool annotations")
	}
	if tool.Annotations.ReadOnlyHint != want.read || *tool.Annotations.DestructiveHint != want.destructive || tool.Annotations.IdempotentHint != want.idempotent {
		t.Fatalf("incorrect annotations for %s", tool.Name)
	}
}

func assertToolOAuth(t *testing.T, tool toolWire, want []string) {
	t.Helper()
	if len(tool.Meta.Schemes) != len(want) {
		t.Fatalf("missing per-tool OAuth scheme for %s", tool.Name)
	}
	expected := make(map[string]bool)
	for _, scope := range want {
		expected[scope] = true
	}
	seen := make(map[string]bool)
	for _, scheme := range tool.Meta.Schemes {
		if scheme.Type != "oauth2" || len(scheme.Scopes) != 1 {
			t.Fatal("tool advertised anonymous or ambiguous auth policy")
		}
		scope := scheme.Scopes[0]
		if !expected[scope] || seen[scope] {
			t.Fatalf("wrong or duplicate scope %q for %s", scope, tool.Name)
		}
		seen[scope] = true
	}
}

func TestOfficialSDKHTTPSDiscoversTwelveClosedToolsAndOAuthMetadata(t *testing.T) {
	f := newFixture(t, 0)
	session := f.session(t, "alice")
	if session.InitializeResult().ProtocolVersion != "2026-07-28" {
		t.Fatal("SDK did not negotiate the configured protocol")
	}
	result, err := session.ListTools(t.Context(), nil)
	listed := checked(t, result, err)
	want := map[string]toolExpectation{
		"list_devices":      {true, false, true, []string{"inventory:read"}},
		"list_projects":     {true, false, true, []string{"inventory:read"}},
		"get_capabilities":  {true, false, true, []string{"inventory:read"}},
		"prepare_dispatch":  {false, false, false, []string{"task:dispatch"}},
		"dispatch_task":     {false, true, true, []string{"task:dispatch"}},
		"list_operations":   {true, false, true, []string{"task:read", "task:dispatch"}},
		"resolve_operation": {true, false, true, []string{"task:read"}},
		"get_task_status":   {true, false, true, []string{"task:read"}},
		"recover_admission": {false, true, true, []string{"task:dispatch"}},
		"collect_result":    {true, false, true, []string{"task:read"}},
		"read_result_chunk": {true, false, true, []string{"task:read"}},
		"cancel_task":       {false, true, true, []string{"task:cancel"}},
	}
	if len(listed.Tools) != len(want) {
		t.Fatalf("got %d registered tools, want12", len(listed.Tools))
	}
	for _, tool := range listed.Tools {
		wire := sdkValue[toolWire](t, tool)
		expected, ok := want[wire.Name]
		if !ok {
			t.Fatalf("unexpected tool %s", wire.Name)
		}
		delete(want, wire.Name)
		assertClosed(t, wire.Input)
		assertClosed(t, wire.Output)
		if len(wire.Output.OneOf) != 2 {
			t.Fatal("output schema does not partition data/error envelopes")
		}
		assertToolHints(t, wire, expected)
		assertToolOAuth(t, wire, expected.scopes)
	}
	if len(want) != 0 {
		t.Fatal("tool catalog omitted a required operation")
	}
	page := decodeResult[DevicePage](t, f.call(t, session, "list_devices", json.RawMessage(`{}`)))
	if page.Error != nil || page.Data == nil || len(page.Data.Devices) != 0 {
		t.Fatal("authorized empty inventory was not a structured success")
	}
}

func TestPublicMetadataAndHTTPBearerChallengesExposeNoInventoryOrSecrets(t *testing.T) {
	f := newFixture(t, 1)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/.well-known/oauth-protected-resource/mcp", nil)
	req := checked(t, request, err)
	resp, data := readHTTPResponse(t, f.server.Client(), req)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(data), privateCanary) || strings.Contains(string(data), "device-000") || strings.Contains(string(data), "Workstation") {
		t.Fatal("public metadata disclosed inventory or private configuration")
	}
	var metadata resourceMetadata
	check(t, json.Unmarshal(data, &metadata))
	if metadata.Resource != f.server.URL+"/mcp" || len(metadata.AuthorizationServers) != 1 || len(metadata.ScopesSupported) != 4 {
		t.Fatal("protected resource metadata does not match configured OAuth boundary")
	}
	for _, token := range []string{"", privateCanary, "expired", "management"} {
		request, err = http.NewRequestWithContext(t.Context(), http.MethodPost, f.server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		req = checked(t, request, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, data = readHTTPResponse(t, f.server.Client(), req)
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp") {
			t.Fatalf("missing HTTP401 protected-resource challenge for token %q", token)
		}
		if strings.Contains(string(data), privateCanary) || strings.Contains(resp.Header.Get("WWW-Authenticate"), privateCanary) {
			t.Fatal("auth failure reflected token canary")
		}
	}
}

func TestMissingToolScopeReturnsOAuthLinkingChallengeAndCompatibleContent(t *testing.T) {
	f := newFixture(t, 1)
	session := f.session(t, "inventory")
	result := f.call(t, session, "prepare_dispatch", json.RawMessage(`{"device_id":"device-000","project_alias":"public","brief":"brief","provider":"provider","permission":"read-only","budget_seconds":60}`))
	expectError[Prepared](t, result, "forbidden")
	wire := sdkValue[resultWire](t, result)
	if len(wire.Meta.Challenges) != 1 {
		t.Fatal("tool-level scope denial omitted mcp/www_authenticate metadata")
	}
	for _, required := range []string{"insufficient_scope", "error_description=", "resource_metadata=", "task:dispatch"} {
		if !strings.Contains(wire.Meta.Challenges[0], required) {
			t.Fatalf("tool challenge omitted %s", required)
		}
	}
	if len(f.link.commands) != 0 {
		t.Fatal("scope denial reached the connector")
	}
}

func TestAuthenticatedHTTPBurstIsBoundedAndRefillsUsingConfiguredClock(t *testing.T) {
	f := newFixture(t, 0)
	for i := range 21 {
		status := rateRequest(t, f)
		if i < 20 && status == http.StatusTooManyRequests {
			t.Fatal("HTTP limiter exhausted before its configured20 request burst")
		}
		if i == 20 && status != http.StatusTooManyRequests {
			t.Fatal("HTTP limiter admitted a request beyond its configured burst")
		}
	}
	f.clock.advance()
	if rateRequest(t, f) == http.StatusTooManyRequests {
		t.Fatal("production rate bucket did not refill at its configured clock")
	}
}

func rateRequest(t *testing.T, f *fixture) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req := checked(t, request, err)
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	resp, _ := readHTTPResponse(t, f.server.Client(), req)
	return resp.StatusCode
}

// The request helper owns the body even when reading or assertions fail. The
// returned metadata cannot accidentally transfer body ownership.
type responseMetadata struct {
	StatusCode int
	Header     http.Header
}

func readHTTPResponse(t *testing.T, client *http.Client, req *http.Request) (responseMetadata, []byte) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { check(t, resp.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	check(t, err)
	return responseMetadata{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}, body
}
