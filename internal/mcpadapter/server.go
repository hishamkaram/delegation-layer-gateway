package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
)

type Options struct {
	Registry      Registry
	Operations    Operations
	Presence      Presence
	Authenticator Authenticator
	Recorder      Recorder
	ResourceURL   string
	Issuer        string
	Timeout       time.Duration
	Now           func() time.Time
}
type Adapter struct {
	options     Options
	server      *mcp.Server
	handler     http.Handler
	metadataURL string
	limits      *httpguard.RateLimits
}

func New(options Options) (*Adapter, error) {
	resource, err := config.HTTPSURL(options.ResourceURL)
	if err != nil || resource.Path != "/mcp" {
		return nil, config.ErrInvalid
	}
	if _, err = config.HTTPSURL(options.Issuer); err != nil {
		return nil, config.ErrInvalid
	}
	if options.Registry == nil || options.Operations == nil || options.Presence == nil || options.Authenticator == nil || options.Now == nil || options.Timeout <= 0 || options.Timeout > 305*time.Second {
		return nil, config.ErrInvalid
	}
	limits, err := httpguard.NewRateLimits(10, 20, 4096, 2*time.Minute, options.Now)
	if err != nil {
		return nil, err
	}
	// SDK diagnostics may include protocol values. Only the separately owned
	// allowlisted audit/metrics path may write application observability.
	quiet := slog.New(slog.NewJSONHandler(io.Discard, nil))
	// Older versions require batches; this boundary admits one RPC per HTTP request.
	server := mcp.NewServer(&mcp.Implementation{Name: "delegation-layer-gateway", Version: "0.0.0-dev"}, &mcp.ServerOptions{Logger: quiet, Instructions: "Select a device and project explicitly. Prepare a dispatch, retain its operation ID, then confirm it. Retry by the same handle; never create a replacement after an unknown admission. Accepted results and confirmed execution closure are separate. A project grant does not provide an OS sandbox.", SupportedProtocolVersions: []string{"2026-07-28", "2025-11-25", "2025-06-18"}})
	adapter := &Adapter{options: options, server: server, metadataURL: resource.Scheme + "://" + resource.Host + "/.well-known/oauth-protected-resource/mcp", limits: limits}
	if err = adapter.registerTools(); err != nil {
		return nil, err
	}
	// The composition guard owns exact public Host/Origin checks, including behind
	// a loopback reverse proxy. See Handler's required security precondition.
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, Logger: quiet, MaxRequestBodyBytes: maxRequestBodyBytes, PropagateRequestCancellation: true, DisableLocalhostProtection: true})
	adapter.handler = auth.RequireBearerToken(adapter.verifyToken, &auth.RequireBearerTokenOptions{ResourceMetadataURL: adapter.metadataURL})(adapter.limitHTTP(transport))
	return adapter, nil
}

// Handler requires a TLS/Host/Origin/body/concurrency guard from server
// composition. Authentication is never optional for the MCP endpoint itself.
func (a *Adapter) Handler() http.Handler { return a.handler }

func (a *Adapter) verifyToken(ctx context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
	verified, err := a.options.Authenticator.AuthenticateToken(ctx, raw)
	if err != nil {
		var failure *identity.Error
		if errors.As(err, &failure) && (failure.Code == identity.InvalidToken || failure.Code == identity.PrincipalRevoked) {
			return nil, auth.ErrInvalidToken
		}
		return nil, errors.New("identity_unavailable")
	}
	scopes := make([]string, 0, len(verified.Actor.Scopes))
	for _, scope := range verified.Actor.Scopes {
		scopes = append(scopes, string(scope))
	}
	return &auth.TokenInfo{UserID: string(verified.Actor.Principal), Scopes: scopes, Expiration: verified.ExpiresAt}, nil
}

func (a *Adapter) limitHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		info := auth.TokenInfoFromContext(request.Context())
		if info == nil || !a.limits.Allow(info.UserID) {
			if a.options.Recorder != nil {
				principal := domain.PrincipalID("")
				if info != nil && domain.Token(info.UserID) == nil {
					principal = domain.PrincipalID(info.UserID)
				}
				a.options.Recorder.Record(observability.Event{Code: observability.ResourceDenied, Principal: principal})
			}
			writer.Header().Set("Retry-After", "1")
			http.Error(writer, "resource_limit", http.StatusTooManyRequests)
			return
		}
		framing := singleMessage(writer, request)
		if framing != framingAdmitted {
			if a.options.Recorder != nil {
				if framing == framingOversized {
					a.options.Recorder.Record(observability.Event{Code: observability.ResourceDenied, Principal: domain.PrincipalID(info.UserID)})
				}
				a.options.Recorder.Record(observability.Event{Code: observability.MCPToolErrorReady, Principal: domain.PrincipalID(info.UserID)})
			}
			return
		}
		next.ServeHTTP(writer, request)
	})
}

type resourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

func (a *Adapter) Metadata() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method_not_allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := json.Marshal(resourceMetadata{Resource: a.options.ResourceURL, AuthorizationServers: []string{a.options.Issuer}, ScopesSupported: []string{string(domain.InventoryRead), string(domain.TaskDispatch), string(domain.TaskRead), string(domain.TaskCancel)}, BearerMethodsSupported: []string{"header"}})
		if err != nil {
			http.Error(writer, "internal_error", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		if request.Method == http.MethodHead {
			return
		}
		if _, err = writer.Write(data); err != nil {
			return
		} // The peer can no longer receive a response.
	})
}

func (a *Adapter) actor(request *mcp.CallToolRequest, scopes []domain.Scope) (domain.Actor, *ToolError, string) {
	if request == nil || request.Extra == nil || request.Extra.TokenInfo == nil {
		return domain.Actor{}, &ToolError{Code: "unauthenticated"}, a.challenge("invalid_token", "Authentication required", scopes)
	}
	info := request.Extra.TokenInfo
	if info.Expiration.IsZero() || !a.options.Now().Before(info.Expiration) {
		return domain.Actor{}, &ToolError{Code: "unauthenticated"}, a.challenge("invalid_token", "Access token expired", scopes)
	}
	actor := domain.Actor{Principal: domain.PrincipalID(info.UserID)}
	for _, scope := range info.Scopes {
		typed := domain.Scope(scope)
		if typed.Validate() == nil {
			actor.Scopes = append(actor.Scopes, typed)
		}
	}
	if actor.Validate() != nil {
		return domain.Actor{}, &ToolError{Code: "unauthenticated"}, a.challenge("invalid_token", "Authentication required", scopes)
	}
	for _, scope := range scopes {
		if actor.Scopes.Has(scope) {
			return actor, nil, ""
		}
	}
	return actor, &ToolError{Code: "forbidden"}, a.challenge("insufficient_scope", "Required scope is missing", scopes)
}

func (a *Adapter) challenge(code, description string, scopes []domain.Scope) string {
	scope := ""
	if len(scopes) > 0 {
		scope = string(scopes[0])
	}
	return fmt.Sprintf("Bearer resource_metadata=%q, error=%q, error_description=%q, scope=%q", a.metadataURL, code, description, scope)
}
