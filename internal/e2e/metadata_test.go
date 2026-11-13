//go:build e2e

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMetadataUsesFixedTokenlessEndpointAndActualSchema(t *testing.T) {
	const endpoint = "https://gateway.example/.well-known/oauth-protected-resource/mcp"
	parsed, err := url.Parse(endpoint)
	fixtureOK(t, err)
	called := 0
	client, transport, err := helperHTTPClient(callInput{TrustMode: "system"}, *parsed, "")
	fixtureOK(t, err)
	defer transport.CloseIdleConnections()
	guard, ok := client.Transport.(bearerTransport)
	if !ok {
		t.Fatal("metadata transport does not enforce endpoint pinning")
	}
	if _, bounded := guard.base.(boundedTransport); !bounded {
		t.Fatal("metadata transport does not bound HTTP response bodies")
	}
	guard.base = boundedTransport{base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called++
		if request.Method != http.MethodGet || request.URL.String() != endpoint || request.Header.Get("Authorization") != "" {
			t.Fatal("metadata request carried credentials or changed its endpoint")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"resource":"https://gateway.example/mcp","authorization_servers":["https://issuer.example/"],"scopes_supported":["inventory:read"],"bearer_methods_supported":["header"]}`))}, nil
	})}
	client.Transport = guard
	metadata, err := fetchMetadata(t.Context(), client, endpoint)
	fixtureOK(t, err)
	if called != 1 || metadata.Resource != "https://gateway.example/mcp" || len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://issuer.example/" || len(metadata.ScopesSupported) != 1 || metadata.ScopesSupported[0] != "inventory:read" || len(metadata.BearerMethodsSupported) != 1 || metadata.BearerMethodsSupported[0] != "header" {
		t.Fatal("metadata was invented or issuer URL was followed")
	}
}

func TestMetadataRejectsCredentialOrToolInputsWithoutRequests(t *testing.T) {
	for name, input := range map[string]callInput{
		"default-fixture": {Endpoint: "https://gateway.example/mcp"},
		"token":           {TrustMode: "system", Endpoint: "https://gateway.example/mcp", TokenFile: "/missing/private-token"},
		"tool":            {TrustMode: "system", Endpoint: "https://gateway.example/mcp", Tool: "prepare_dispatch"},
		"arguments":       {TrustMode: "system", Endpoint: "https://gateway.example/mcp", Arguments: json.RawMessage(`{}`)},
		"null-arguments":  {TrustMode: "system", Endpoint: "https://gateway.example/mcp", Arguments: json.RawMessage(`null`)},
		"CA":              {TrustMode: "system", Endpoint: "https://gateway.example/mcp", CA: "/missing/CA"},
		"IP-override":     {TrustMode: "system", Endpoint: "https://gateway.example/mcp", AllowedIPs: []string{"127.0.0.1"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readMetadata(t.Context(), input); err == nil || !strings.HasPrefix(err.Error(), "fixture ") {
				t.Fatal("invalid metadata input reached credential or network access")
			}
		})
	}
}

func TestMetadataRedirectFailsWithoutFollowingLocation(t *testing.T) {
	parsed, err := url.Parse("https://gateway.example/.well-known/oauth-protected-resource/mcp")
	fixtureOK(t, err)
	client, transport, err := helperHTTPClient(callInput{TrustMode: "system"}, *parsed, "")
	fixtureOK(t, err)
	defer transport.CloseIdleConnections()
	called := 0
	client.Transport = bearerTransport{endpoint: *parsed, base: boundedTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called++
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://issuer.example/private"}}, Body: http.NoBody}, nil
	})}}
	if _, err := fetchMetadata(t.Context(), client, parsed.String()); err == nil || called != 1 {
		t.Fatal("metadata redirect was accepted or followed")
	}
}
