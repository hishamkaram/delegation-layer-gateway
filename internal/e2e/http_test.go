//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// These expectations come from the acceptance contract, independently of the
// implementation constants, so increasing a production limit fails the tests.
const (
	expectedResponseLimit = 1 << 20
	expectedOutputLimit   = 2 << 20
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestSystemTrustRejectsOverridesAndInvalidEndpointBeforeTokenRead(t *testing.T) {
	cases := []callInput{
		{TrustMode: "unknown", Endpoint: "https://gateway.example/mcp"},
		{TrustMode: "system", Endpoint: "https://gateway.example/mcp", CA: "private-canary"},
		{TrustMode: "system", Endpoint: "https://gateway.example/mcp", AllowedIPs: []string{}},
		{TrustMode: "system", Endpoint: "https://gateway.example/mcp", AllowedIPs: []string{"127.0.0.1"}},
	}
	for _, endpoint := range []string{
		"http://gateway.example/mcp", "https://GATEWAY.example/mcp", "https://gateway.example./mcp",
		"https://127.0.0.1/mcp", "https://[::1]/mcp", "https://user@gateway.example/mcp",
		"https://gateway.example/mcp?", "https://gateway.example/mcp?secret=x", "https://gateway.example/mcp#",
		"https://gateway.example/%6dcp", "https://gateway.example/other", "https://gateway.example:0443/mcp",
		"https://gateway.example:0/mcp", "https://gateway.example:65536/mcp", "https://gateway.example:/mcp",
		"https://-gateway.example/mcp", "https://gateway_.example/mcp", "https://gateway..example/mcp",
	} {
		cases = append(cases, callInput{TrustMode: "system", Endpoint: endpoint})
	}
	for _, input := range cases {
		// A missing token pathname produces a different error. Every rejection
		// here must occur while validating the boundary, before opening secrets.
		if _, err := callMCP(t.Context(), input); err == nil || !strings.HasPrefix(err.Error(), "fixture ") {
			t.Fatalf("invalid system endpoint reached credential access: %s", input.Endpoint)
		}
	}
}

func TestSystemTrustUsesInstalledRootsAndFixedClientPolicy(t *testing.T) {
	for _, endpoint := range []string{"https://gateway.example/mcp", "https://gateway/mcp", "https://gateway.example:9443/mcp"} {
		input := callInput{TrustMode: "system", Endpoint: endpoint}
		parsed, err := callEndpoint(input)
		fixtureOK(t, err)
		client, transport, err := helperHTTPClient(input, *parsed, "private-canary")
		fixtureOK(t, err)
		transport.CloseIdleConnections()
		if transport.TLSClientConfig.RootCAs != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 || transport.Proxy != nil {
			t.Fatal("system mode changed installed-root TLS policy")
		}
		if !errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
			t.Fatal("system mode permits redirects")
		}
	}
}

func TestBearerTransportPinsDestinationBeforeCredentialDelivery(t *testing.T) {
	endpoint, err := url.Parse("https://gateway.example:9443/mcp")
	fixtureOK(t, err)
	called := 0
	transport := bearerTransport{endpoint: *endpoint, token: "private-canary", base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called++
		if request.Header.Get("Authorization") != "Bearer private-canary" {
			t.Fatal("valid destination lost its token")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}
	request := httptest.NewRequest("POST", endpoint.String(), nil)
	response, err := transport.RoundTrip(request)
	fixtureOK(t, err)
	fixtureOK(t, response.Body.Close())
	if called != 1 || request.Header.Get("Authorization") != "" {
		t.Fatal("transport mutated the caller request")
	}
	for name, mutate := range map[string]func(*http.Request){
		"scheme":        func(r *http.Request) { r.URL.Scheme = "http" },
		"host":          func(r *http.Request) { r.URL.Host = "attacker.example:9443" },
		"port":          func(r *http.Request) { r.URL.Host = "gateway.example" },
		"path":          func(r *http.Request) { r.URL.Path = "/other" },
		"opaque":        func(r *http.Request) { r.URL.Opaque = "//attacker.example/mcp" },
		"user":          func(r *http.Request) { r.URL.User = url.User("someone") },
		"raw-path":      func(r *http.Request) { r.URL.RawPath = "/%6dcp" },
		"query":         func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"force-query":   func(r *http.Request) { r.URL.ForceQuery = true },
		"fragment":      func(r *http.Request) { r.URL.Fragment = "private" },
		"raw-fragment":  func(r *http.Request) { r.URL.RawFragment = "private" },
		"host-override": func(r *http.Request) { r.Host = "attacker.example" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := httptest.NewRequest("POST", endpoint.String(), nil)
			mutate(candidate)
			response, roundErr := transport.RoundTrip(candidate)
			if response != nil {
				fixtureOK(t, response.Body.Close())
			}
			if roundErr == nil || called != 1 {
				t.Fatal("credential reached an unpinned endpoint")
			}
		})
	}
}

type countedBody struct {
	reader   io.Reader
	read     int
	closed   bool
	closeErr error
}

func (b *countedBody) Read(data []byte) (int, error) {
	n, err := b.reader.Read(data)
	b.read += n
	return n, err
}
func (b *countedBody) Close() error { b.closed = true; return b.closeErr }

func TestBoundedTransportRejectsOverflowAndPreservesCloseErrors(t *testing.T) {
	for _, contentType := range []string{"application/json", "text/event-stream"} {
		t.Run(contentType, func(t *testing.T) {
			body := &countedBody{reader: strings.NewReader(strings.Repeat("x", expectedResponseLimit+100)), closeErr: io.ErrClosedPipe}
			transport := boundedTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body, Header: http.Header{"Content-Type": []string{contentType}}, TransferEncoding: []string{"chunked"}}, nil
			})}
			response, err := transport.RoundTrip(httptest.NewRequest("GET", "https://gateway.example/mcp", nil))
			if response != nil {
				fixtureOK(t, response.Body.Close())
			}
			if response != nil || !errors.Is(err, errResponseLimit) || !errors.Is(err, io.ErrClosedPipe) || !body.closed || body.read != expectedResponseLimit+1 {
				t.Fatal("overflow was truncated, over-read, or lost its close failure")
			}
		})
	}
}

func TestBoundedTransportClosesOriginalBodyOnSuccessAndBaseFailure(t *testing.T) {
	for _, baseErr := range []error{nil, context.Canceled} {
		body := &countedBody{reader: strings.NewReader("literal")}
		transport := boundedTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: body}, baseErr
		})}
		response, err := transport.RoundTrip(httptest.NewRequest("GET", "https://gateway.example/mcp", nil))
		if !body.closed || !errors.Is(err, baseErr) {
			t.Fatal("original body not closed or base failure lost")
		}
		if baseErr == nil {
			data, readErr := io.ReadAll(response.Body)
			fixtureOK(t, readErr)
			fixtureOK(t, response.Body.Close())
			if string(data) != "literal" {
				t.Fatal("buffered response changed")
			}
		}
	}
}

type failedBodyReader struct{}

func (failedBodyReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestBoundedTransportPreservesReadAndCloseFailure(t *testing.T) {
	body := &countedBody{reader: failedBodyReader{}, closeErr: io.ErrClosedPipe}
	transport := boundedTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body}, nil
	})}
	response, err := transport.RoundTrip(httptest.NewRequest("GET", "https://gateway.example/mcp", nil))
	if response != nil {
		fixtureOK(t, response.Body.Close())
	}
	if response != nil || !body.closed || !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("failed response lost its read error, close error, or body ownership")
	}
}

func TestHelperOutputIsBoundedBeforeAnyWrite(t *testing.T) {
	var output bytes.Buffer
	if err := writeOutput(&output, strings.Repeat("x", expectedOutputLimit)); err == nil || output.Len() != 0 {
		t.Fatal("oversized helper result reached capture")
	}
	fixtureOK(t, writeOutput(&output, strings.Repeat("x", expectedOutputLimit-3)))
	if output.Len() != expectedOutputLimit || output.Bytes()[expectedOutputLimit-1] != '\n' {
		t.Fatal("output bound does not include its newline")
	}
}
