package mcpadapter

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
)

const proxyPublicOrigin = "https://gateway.example"

type proxyFixture struct {
	server *httptest.Server
	local  *atomic.Pointer[net.TCPAddr]
}

func newProxyFixture(t *testing.T) *proxyFixture {
	t.Helper()
	f := newFixture(t, 0)
	options := f.adapter.options
	options.ResourceURL = proxyPublicOrigin + "/mcp"
	adapter, err := New(options)
	public := checked(t, adapter, err)
	guard, err := httpguard.New(httpguard.Options{PublicOrigin: proxyPublicOrigin, ConcurrentRequests: 128, Timeout: 35 * time.Second, MaxBodyBytes: 1 << 20})
	secure := checked(t, guard, err)
	observed := &atomic.Pointer[net.TCPAddr]{}
	guarded := secure.Wrap(public.Handler())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		address, ok := request.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
		if ok {
			observed.Store(address)
		} else {
			observed.Store(nil)
		}
		guarded.ServeHTTP(w, request)
	}))
	t.Cleanup(server.Close)
	server.Client().Timeout = 5 * time.Second
	return &proxyFixture{server: server, local: observed}
}

func compatibilityRequest(t *testing.T, endpoint, host, origin, token, version, method string) *http.Request {
	t.Helper()
	params := json.RawMessage(`{}`)
	if method == "initialize" {
		params = jsonBytesCompatibility(t, struct {
			Version      string            `json:"protocolVersion"`
			Capabilities struct{}          `json:"capabilities"`
			Client       map[string]string `json:"clientInfo"`
		}{Version: version, Client: map[string]string{"name": "proxy-compatibility", "version": "1"}})
	}
	payload := jsonBytesCompatibility(t, struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint+"/mcp", bytes.NewReader(payload))
	req := checked(t, request, err)
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// initialize negotiates its body version without a header, as a legacy
	// client does. Subsequent calls explicitly carry the negotiated version.
	if method != "initialize" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	return req
}

func jsonBytesCompatibility(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	return checked(t, data, err)
}

func assertCompatibilityInitialize(t *testing.T, response responseMetadata, data []byte, version string) {
	t.Helper()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("initialize HTTP %d, want200: %s", response.StatusCode, data)
	}
	var message struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			Version string `json:"protocolVersion"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	check(t, json.Unmarshal(data, &message))
	if message.JSONRPC != "2.0" || message.ID != 1 || len(message.Error) != 0 || message.Result.Version != version {
		t.Fatalf("initialize negotiated %q, want %q; RPC error=%s", message.Result.Version, version, message.Error)
	}
}

func assertCompatibilityTools(t *testing.T, response responseMetadata, data []byte) {
	t.Helper()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("tools/list HTTP %d, want200: %s", response.StatusCode, data)
	}
	var message struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			Tools []toolWire `json:"tools"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	check(t, json.Unmarshal(data, &message))
	if message.JSONRPC != "2.0" || message.ID != 1 || len(message.Error) != 0 || len(message.Result.Tools) != 12 {
		t.Fatalf("tools/list omitted the12-tool catalog or returned an RPC error: %s", message.Error)
	}
	seen := make(map[string]bool)
	for _, tool := range message.Result.Tools {
		if tool.Name == "" || seen[tool.Name] {
			t.Fatalf("empty or duplicate tool name %q", tool.Name)
		}
		seen[tool.Name] = true
		assertClosed(t, tool.Input)
		assertClosed(t, tool.Output)
	}
	if !seen["list_devices"] || !seen["dispatch_task"] || !seen["collect_result"] {
		t.Fatal("catalog omitted required inventory, dispatch or collection tools")
	}
}

func (f *proxyFixture) request(t *testing.T, request *http.Request) (responseMetadata, []byte) {
	t.Helper()
	// The client connects to the real loopback TLS URL and verifies its test CA;
	// only HTTP Host/Origin model the reverse proxy's public authority.
	response, data := readHTTPResponse(t, f.server.Client(), request)
	local := f.local.Load()
	if local == nil || !local.IP.IsLoopback() {
		t.Fatalf("fixture did not exercise an actual loopback LocalAddr: %v", local)
	}
	return response, data
}

func TestPublicProxyHTTPSInitializeAndToolsList(t *testing.T) {
	for _, origin := range []string{proxyPublicOrigin, ""} {
		t.Run("origin="+origin, func(t *testing.T) {
			f := newProxyFixture(t)
			for _, method := range []string{"initialize", "tools/list"} {
				t.Run(method, func(t *testing.T) {
					request := compatibilityRequest(t, f.server.URL, "gateway.example", origin, "alice", "2025-11-25", method)
					response, data := f.request(t, request)
					if method == "initialize" {
						assertCompatibilityInitialize(t, response, data, "2025-11-25")
					} else {
						assertCompatibilityTools(t, response, data)
					}
				})
			}
		})
	}
}

func TestLegacyHTTPSProtocolCompatibility(t *testing.T) {
	for _, version := range []string{"2025-06-18", "2025-11-25"} {
		t.Run(version, func(t *testing.T) {
			f := newFixture(t, 0)
			parsed, err := url.Parse(f.server.URL)
			endpoint := checked(t, parsed, err)
			for _, method := range []string{"initialize", "tools/list"} {
				t.Run(method, func(t *testing.T) {
					request := compatibilityRequest(t, f.server.URL, endpoint.Host, f.server.URL, "alice", version, method)
					response, data := readHTTPResponse(t, f.server.Client(), request)
					if method == "initialize" {
						assertCompatibilityInitialize(t, response, data, version)
					} else {
						assertCompatibilityTools(t, response, data)
					}
				})
			}
		})
	}
}

func TestPublicProxyHTTPSKeepsHostOriginAndBearerGuards(t *testing.T) {
	for _, test := range []struct {
		name, host, origin, token string
		status                    int
	}{
		{"foreign-host", "foreign.example", proxyPublicOrigin, "alice", http.StatusForbidden},
		{"foreign-origin", "gateway.example", "https://foreign.example", "alice", http.StatusForbidden},
		{"missing-token", "gateway.example", proxyPublicOrigin, "", http.StatusUnauthorized},
		{"bad-token", "gateway.example", proxyPublicOrigin, "invalid-fixture-token", http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newProxyFixture(t)
			request := compatibilityRequest(t, f.server.URL, test.host, test.origin, test.token, "2025-11-25", "tools/list")
			response, data := f.request(t, request)
			if response.StatusCode != test.status {
				t.Fatalf("HTTP %d, want%d: %s", response.StatusCode, test.status, data)
			}
			if test.status == http.StatusUnauthorized && !strings.Contains(response.Header.Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatal("missing token lost its protected-resource challenge")
			}
		})
	}
}

// Count completed successful tool responses at the existing Recorder boundary,
// independently of how the transport serializes the JSON-RPC batch response.
type compatibilityToolResponses struct{ ready atomic.Int32 }

func (r *compatibilityToolResponses) Record(event observability.Event) {
	if event.Code == observability.MCPToolResponseReady {
		r.ready.Add(1)
	}
}

func TestHTTPSBatchRequiresSingleMessage(t *testing.T) {
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_devices","arguments":{}}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_devices","arguments":{}}}]`
	for _, test := range []struct{ name, prefix, version string }{
		{"no-header", "", ""},
		{"explicit-june", "", "2025-06-18"},
		{"leading-json-whitespace", " \t\n\r", ""},
		{"vertical-tab-is-not-json-whitespace", "\v", ""},
		{"utf8-bom-is-not-json-whitespace", "\ufeff", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			responses := &compatibilityToolResponses{}
			f := newRecordedFixture(t, 0, responses)
			request := framingRequest(t, f.server.URL, test.prefix+batch, test.version)
			started := time.Now()
			response, data := readHTTPResponse(t, f.server.Client(), request)
			var results []json.RawMessage
			arrayErr := json.Unmarshal(data, &results)
			// The preimage no-header request returned HTTP200, two RPC results
			// and two independently recorded successful list_devices responses.
			t.Logf("batch HTTP=%d, JSON-array=%t, RPC-responses=%d, successful-tool-responses=%d, elapsed=%s", response.StatusCode, arrayErr == nil, len(results), responses.ready.Load(), time.Since(started))
			if response.StatusCode != http.StatusBadRequest || responses.ready.Load() != 0 {
				t.Fatalf("single-message boundary: wantHTTP400 and zero tool executions; gotHTTP%d, successful-tool-responses=%d, body=%s", response.StatusCode, responses.ready.Load(), data)
			}
		})
	}
}

func framingRequest(t *testing.T, endpoint, payload, version string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint+"/mcp", strings.NewReader(payload))
	req := checked(t, request, err)
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	return req
}

func TestHTTPSFramingPreservesObjectsAndBodyCeiling(t *testing.T) {
	object := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	for _, test := range []struct {
		name, body string
		status     int
	}{
		{"leading-json-whitespace-object", " \t\n\r" + object, http.StatusOK},
		{"exact-body-ceiling", object + strings.Repeat(" ", (1<<20)-len(object)), http.StatusOK},
		{"object-body-overflow", object + strings.Repeat(" ", (1<<20)+1-len(object)), http.StatusRequestEntityTooLarge},
		{"whitespace-only-overflow", strings.Repeat(" ", (1<<20)+1), http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, 0)
			response, data := readHTTPResponse(t, f.server.Client(), framingRequest(t, f.server.URL, test.body, "2025-06-18"))
			if response.StatusCode != test.status {
				t.Fatalf("HTTP%d, want%d: %s", response.StatusCode, test.status, data)
			}
			if test.status == http.StatusOK {
				assertCompatibilityTools(t, response, data)
			}
		})
	}
}

func TestHTTPSRejectsBatchCapableLegacyProtocolHeaders(t *testing.T) {
	// March2025 and November2024 require batch receipt. The Gateway's explicit
	// one-message policy therefore does not advertise those protocol versions.
	for _, version := range []string{"2025-03-26", "2024-11-05"} {
		t.Run(version, func(t *testing.T) {
			f := newFixture(t, 0)
			object := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
			response, data := readHTTPResponse(t, f.server.Client(), framingRequest(t, f.server.URL, object, version))
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("unsupported batch-capable version returned HTTP%d, want400: %s", response.StatusCode, data)
			}
		})
	}
}
