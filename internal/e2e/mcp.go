//go:build e2e

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type (
	callInput struct {
		Endpoint   string          `json:"endpoint"`
		CA         string          `json:"ca_file"`
		TokenFile  string          `json:"token_file"`
		Tool       string          `json:"tool"`
		Arguments  json.RawMessage `json:"arguments"`
		AllowedIPs []string        `json:"allowed_ips,omitempty"`
	}
	bearerTransport struct {
		base  http.RoundTripper
		token string
	}
)

func (b bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	owned := request.Clone(request.Context())
	owned.Header = request.Header.Clone()
	owned.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(owned)
}

func callMCP(ctx context.Context, input callInput) (result *mcp.CallToolResult, returned error) {
	addresses, err := fixtureIPs(input.AllowedIPs)
	if err != nil {
		return nil, err
	}
	endpoint, err := fixtureEndpoint(input.Endpoint, addresses)
	if err != nil {
		return nil, err
	}
	if endpoint.Path != "/mcp" {
		return nil, errors.New("fixture MCP endpoint path must be /mcp")
	}
	var token struct {
		Token string `json:"token"`
	}
	if err = readPrivate(input.TokenFile, &token); err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(input.CA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid fixture CA")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, MaxConnsPerHost: 1, DisableCompression: true, ResponseHeaderTimeout: 35 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: bearerTransport{base: transport, token: token.Token}, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sdk := mcp.NewClient(&mcp.Implementation{Name: "local-process-e2e", Version: "1"}, &mcp.ClientOptions{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	session, err := sdk.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: input.Endpoint, HTTPClient: client, DisableStandaloneSSE: true, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		return nil, err
	}
	defer func() { returned = errors.Join(returned, session.Close()) }()
	return session.CallTool(ctx, &mcp.CallToolParams{Name: input.Tool, Arguments: input.Arguments})
}
