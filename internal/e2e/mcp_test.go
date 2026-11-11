//go:build e2e

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPExplicitAllowlistUsesRealHTTPSAndSDK(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "literal-fixture", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "literal"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "literal response"}}}, struct{}{}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	var authenticated atomic.Int32
	fixture, input := newMCPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer literal-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authenticated.Add(1)
		handler.ServeHTTP(w, r)
	}))
	input.Endpoint = fixture.URL + "/mcp"
	input.AllowedIPs = []string{"127.0.0.1"}
	input.Tool = "literal"
	input.Arguments = json.RawMessage(`{}`)
	result, err := callMCP(t.Context(), input)
	fixtureOK(t, err)
	if result.IsError || len(result.Content) != 1 || authenticated.Load() == 0 {
		t.Fatal("HTTPS MCP tool call failed")
	}
	content, ok := result.Content[0].(*mcp.TextContent)
	if !ok || content.Text != "literal response" {
		t.Fatal("literal SDK result changed")
	}
}

func TestMCPRedirectIsNeverFollowed(t *testing.T) {
	var redirected atomic.Int32
	fixture, input := newMCPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			redirected.Add(1)
		}
		http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
	}))
	input.Endpoint = fixture.URL + "/mcp"
	if _, err := callMCP(t.Context(), input); err == nil {
		t.Fatal("redirect accepted as MCP session")
	}
	if redirected.Load() != 0 {
		t.Fatal("helper followed redirect")
	}
}

func TestMCPRejectsDestinationBeforeCredentialAccess(t *testing.T) {
	for _, input := range []callInput{
		{Endpoint: "https://192.0.2.10/mcp"},
		{Endpoint: "https://127.0.0.1/other"},
		{Endpoint: "https://127.0.0.1/mcp#"},
		{Endpoint: "https://127.0.0.1/mcp", AllowedIPs: []string{"*"}},
	} {
		if _, err := callMCP(t.Context(), input); err == nil || !strings.HasPrefix(err.Error(), "fixture ") {
			t.Fatal("invalid destination reached credential access")
		}
	}
}

func TestMCPRejectsOversizedHTTPResponseBeforeSDKDecoding(t *testing.T) {
	fixture, input := newMCPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// A flushed response uses chunked transfer rather than a trusted length.
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("fixture writer cannot flush")
			return
		}
		flusher.Flush()
		if _, err := io.WriteString(w, strings.Repeat("x", expectedResponseLimit+1)); err != nil {
			return // Client may close the oversized response before the server finishes.
		}
	}))
	input.Endpoint = fixture.URL + "/mcp"
	if _, err := callMCP(t.Context(), input); !errors.Is(err, errResponseLimit) {
		t.Fatalf("SDK decoded an oversized streamed response: %v", err)
	}
}

func newMCPFixture(t *testing.T, handler http.Handler) (*httptest.Server, callInput) {
	t.Helper()
	directory := t.TempDir()
	addresses, err := fixtureIPs(nil)
	fixtureOK(t, err)
	authority, err := newCA(directory, "fixture-ca", time.Now())
	fixtureOK(t, err)
	files, err := newServer(directory, authority, time.Now(), addresses)
	fixtureOK(t, err)
	certificate, err := tls.LoadX509KeyPair(files.Certificate, files.PrivateKey)
	fixtureOK(t, err)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	token := filepath.Join(directory, "token.json")
	fixtureOK(t, privateWrite(token, []byte(`{"token":"literal-token"}`)))
	return server, callInput{CA: authority.files.Certificate, TokenFile: token}
}
