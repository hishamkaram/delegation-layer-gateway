package workspaces_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/mcpadapter"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const workspaceMCPToken = "workspace-inventory-fixture-token"

// This authenticator supplies controlled verified claims for the SDK boundary;
// it is not evidence of OAuth/JWT or Cloud-client acceptance.
type workspaceMCPAuthenticator struct{ verified identity.VerifiedToken }

func (a workspaceMCPAuthenticator) AuthenticateToken(ctx context.Context, raw string) (identity.VerifiedToken, error) {
	if err := ctx.Err(); err != nil {
		return identity.VerifiedToken{}, err
	}
	if raw != workspaceMCPToken {
		return identity.VerifiedToken{}, &identity.Error{Code: identity.InvalidToken}
	}
	return a.verified, nil
}

type workspaceBearerTransport struct{ base http.RoundTripper }

func (b workspaceBearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+workspaceMCPToken)
	return b.base.RoundTrip(copy)
}

func TestSDKWorkspaceInventoryPreservesPresenceFailureHonesty(t *testing.T) {
	f := newFixture(t)
	for _, test := range workspaceInventoryFailures() {
		t.Run(test.name, func(t *testing.T) {
			service := workspaceInventoryService(t, f, workspaceFailedPresence{err: test.err})
			result := callWorkspaceInventorySDK(t, f, service)
			data, err := json.Marshal(result.StructuredContent)
			require(t, err)
			var envelope mcpadapter.Envelope[mcpadapter.WorkspaceInventory]
			require(t, protocol.DecodeStrict(data, &envelope, 1<<20))
			if test.offline {
				assertSDKOfflineWorkspaceInventory(t, result, envelope, string(f.device))
			} else if !result.IsError || envelope.Data != nil || envelope.Error == nil || envelope.Error.Code != "internal_error" || envelope.Error.Retryable {
				t.Fatal("workspace Presence uncertainty became successful offline metadata")
			}
			public, err := json.Marshal(result)
			require(t, err)
			if strings.Contains(string(public), inventoryFailureMarker) || strings.Contains(string(public), workspaceMCPToken) {
				t.Fatal("workspace inventory exposed a private failure or credential")
			}
		})
	}
	assertInventoryStartedNoControls(t, f)
}

func assertSDKOfflineWorkspaceInventory(t *testing.T, result *mcp.CallToolResult, envelope mcpadapter.Envelope[mcpadapter.WorkspaceInventory], device string) {
	t.Helper()
	if result.IsError || envelope.Error != nil || envelope.Data == nil {
		t.Fatal("sole offline cause did not return authorized offline workspace inventory")
	}
	inventory := envelope.Data
	if inventory.DeviceID != device || inventory.Online || inventory.DelegateReady || inventory.ObservedAt != nil || len(inventory.Workspaces) != 0 || inventory.ProjectBudget != nil {
		t.Fatal("offline workspace response invented dated live metadata")
	}
}

func callWorkspaceInventorySDK(t *testing.T, f *fixture, service *workspaces.Service) *mcp.CallToolResult {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	operations, err := gateway.New(f.store, f.link, f.gateway, rand.Reader, time.Now, gateway.RoutingObserverFunc(f.observations.record))
	require(t, err)
	adapter, err := mcpadapter.New(mcpadapter.Options{
		Registry: f.store, Operations: operations, Presence: f.link, Workspaces: service,
		Authenticator: workspaceMCPAuthenticator{verified: identity.VerifiedToken{Actor: f.actor, ExpiresAt: time.Now().Add(time.Hour)}},
		ResourceURL:   server.URL + "/mcp", Issuer: "https://fixture.example/", Timeout: 30 * time.Second, Now: time.Now,
	})
	require(t, err)
	guard, err := httpguard.New(httpguard.Options{PublicOrigin: server.URL, ConcurrentRequests: 16, Timeout: 35 * time.Second, MaxBodyBytes: 1 << 20})
	require(t, err)
	mux.Handle("/mcp", guard.Wrap(adapter.Handler()))
	clientHTTP := *server.Client()
	base, ok := clientHTTP.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected fixture HTTPS transport")
	}
	owned := base.Clone()
	t.Cleanup(owned.CloseIdleConnections)
	clientHTTP.Transport = workspaceBearerTransport{base: owned}
	client := mcp.NewClient(&mcp.Implementation{Name: "workspace-inventory-test", Version: "1"}, &mcp.ClientOptions{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &clientHTTP, DisableStandaloneSSE: true, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	require(t, err)
	t.Cleanup(func() { require(t, session.Close()) })
	input, err := json.Marshal(mcpadapter.WorkspacesInput{DeviceID: string(f.device)})
	require(t, err)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_workspaces", Arguments: json.RawMessage(input)})
	require(t, err)
	return result
}
