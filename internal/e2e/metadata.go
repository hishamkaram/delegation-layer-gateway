//go:build e2e

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type protectedMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

func readMetadata(ctx context.Context, input callInput) (protectedMetadata, error) {
	if input.DiscardToolResponse || input.TrustMode != "system" || input.TokenFile != "" || input.Tool != "" || len(input.Arguments) != 0 {
		return protectedMetadata{}, errors.New("fixture metadata requires tokenless system trust input")
	}
	endpoint, err := callEndpoint(input)
	if err != nil {
		return protectedMetadata{}, err
	}
	endpoint.Path = "/.well-known/oauth-protected-resource/mcp"
	client, transport, err := helperHTTPClient(input, *endpoint, "")
	if err != nil {
		return protectedMetadata{}, err
	}
	defer transport.CloseIdleConnections()
	return fetchMetadata(ctx, client, endpoint.String())
}

func fetchMetadata(ctx context.Context, client *http.Client, endpoint string) (protectedMetadata, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return protectedMetadata{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return protectedMetadata{}, err
	}
	data, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err = errors.Join(readErr, closeErr); err != nil {
		return protectedMetadata{}, err
	}
	if response.StatusCode != http.StatusOK {
		return protectedMetadata{}, errors.New("fixture metadata HTTP status rejected")
	}
	var result protectedMetadata
	if err = json.Unmarshal(data, &result); err != nil {
		return protectedMetadata{}, err
	}
	return result, nil
}
