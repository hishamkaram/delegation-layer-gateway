package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPublicHostnameLoopbackTLSKeepsComposedSecurityAndDiscovery(t *testing.T) {
	f := configFixture(t)
	public, err := url.Parse(f.cfg.PublicURL)
	require(t, err)
	const hostname = "gateway.example"
	public.Host = net.JoinHostPort(hostname, public.Port())
	f.cfg.PublicURL = public.String()
	f.cfg.Identity.Audience = f.cfg.PublicURL + "/mcp"
	f.cfg.TLS = serverPair(t, filepath.Dir(f.cfg.TLS.Certificate), f.publicCA, hostname)

	// A fresh, counted JWKS endpoint proves rejected authorities never reach
	// authentication. Calling the existing fixture handler preserves its keys.
	var keyRequests atomic.Int32
	originalKeys := f.jwks.Config.Handler
	f.jwks = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyRequests.Add(1)
		originalKeys.ServeHTTP(w, r)
	}))
	t.Cleanup(f.jwks.Close)
	f.cfg.Identity.Issuer = f.jwks.URL + "/"
	f.cfg.Identity.JWKSURL = f.jwks.URL + "/keys"

	base, ok := f.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("fixture client lacks its owned TLS transport")
	}
	transport := base.Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, f.cfg.PublicAddress)
	}
	t.Cleanup(transport.CloseIdleConnections)
	f.client.Transport = transport
	f.start(t)
	token := f.token(t, f.cfg.Identity.Audience)

	for _, test := range []struct {
		name, host, origin, bearer string
		status                     int
	}{
		{"foreign-host", "foreign.example", "", token, http.StatusForbidden},
		{"foreign-origin", public.Host, "https://foreign.example", token, http.StatusForbidden},
		{"no-token", public.Host, "", "", http.StatusUnauthorized},
		{"invalid-token", public.Host, "", "invalid-acceptance-canary", http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodPost, f.cfg.PublicURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
			require(t, requestErr)
			request.Host = test.host
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			response, requestErr := f.client.Do(request)
			require(t, requestErr)
			_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
			require(t, readErr)
			require(t, response.Body.Close())
			if response.StatusCode != test.status {
				t.Fatalf("HTTP %d, want %d", response.StatusCode, test.status)
			}
			if keyRequests.Load() != 0 {
				t.Fatal("rejected public request reached JWT key retrieval")
			}
		})
	}

	plain, err := url.Parse(f.cfg.PublicURL)
	require(t, err)
	plain.Scheme = "http"
	status, _ := f.request(t, f.client, http.MethodGet, plain.String()+"/mcp", nil, "")
	if status != http.StatusBadRequest || keyRequests.Load() != 0 {
		t.Fatal("plain HTTP reached the authenticated handler")
	}

	session := f.session(t)
	tools, err := session.ListTools(t.Context(), nil)
	if len(checked(t, tools, err).Tools) != 12 || keyRequests.Load() == 0 {
		t.Fatal("public-host discovery did not verify JWT and return twelve tools")
	}
}
