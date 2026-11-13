//go:build e2e

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type (
	callInput struct {
		DiscardToolResponse bool            `json:"discard_tool_response,omitempty"`
		TrustMode           string          `json:"trust_mode,omitempty"`
		Endpoint            string          `json:"endpoint"`
		CA                  string          `json:"ca_file"`
		TokenFile           string          `json:"token_file"`
		Tool                string          `json:"tool"`
		Arguments           json.RawMessage `json:"arguments"`
		AllowedIPs          []string        `json:"allowed_ips,omitempty"`
	}
)

func callMCP(ctx context.Context, input callInput) (result *mcp.CallToolResult, returned error) {
	if input.DiscardToolResponse && input.Tool != "dispatch_task" {
		return nil, errors.New("fixture response discard requires dispatch_task")
	}
	endpoint, err := callEndpoint(input)
	if err != nil {
		return nil, err
	}
	var token struct {
		Token string `json:"token"`
	}
	if err = readPrivate(input.TokenFile, &token); err != nil {
		return nil, err
	}
	client, transport, err := helperHTTPClient(input, *endpoint, token.Token)
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()

	sdk := mcp.NewClient(&mcp.Implementation{Name: "local-process-e2e", Version: "1"}, &mcp.ClientOptions{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	session, err := sdk.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: input.Endpoint, HTTPClient: client, DisableStandaloneSSE: true, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		return nil, err
	}
	defer func() { returned = finishMCPCall(returned, session.Close()) }()
	return session.CallTool(ctx, &mcp.CallToolParams{Name: input.Tool, Arguments: input.Arguments})
}
