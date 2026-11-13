//go:build e2e

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	maxResponseBytes = 1 << 20
	maxOutputBytes   = 2 << 20
)

var errResponseLimit = errors.New("fixture response limit exceeded")

// The transport owns an immutable copy of the validated destination. SDK or
// server-derived requests cannot deliver the credential to another authority.
type bearerTransport struct {
	base     http.RoundTripper
	endpoint url.URL
	token    string
}

func (b bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !b.matches(request) {
		var closeErr error
		if request.Body != nil {
			closeErr = request.Body.Close()
		}
		return nil, errors.Join(errors.New("fixture request escaped its pinned endpoint"), closeErr)
	}
	owned := request.Clone(request.Context())
	owned.Header = request.Header.Clone()
	if owned.Header == nil {
		owned.Header = make(http.Header)
	}
	owned.Header.Del("Authorization")
	if b.token != "" {
		owned.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(owned)
}

func (b bearerTransport) matches(request *http.Request) bool {
	u := request.URL
	return u != nil && u.Scheme == b.endpoint.Scheme && u.Host == b.endpoint.Host && u.Path == b.endpoint.Path &&
		u.Opaque == "" && u.User == nil && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == "" &&
		(request.Host == "" || request.Host == b.endpoint.Host)
}

// Gateway's acceptance transport is JSON-response/stateless. Buffer each
// response before SDK decoding, including chunked/SSE bodies, with explicit
// overflow rather than silently accepting a truncated JSON prefix.
type boundedTransport struct{ base http.RoundTripper }

func (b boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := b.base.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			err = errors.Join(err, response.Body.Close())
		}
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("fixture response body missing")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if len(data) > maxResponseBytes {
		readErr = errors.Join(errResponseLimit, readErr)
	}
	if err = errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	return response, nil
}

func helperHTTPClient(input callInput, endpoint url.URL, token string) (*http.Client, *http.Transport, error) {
	var roots *x509.CertPool // nil means the installed system trust roots.
	if input.TrustMode != "system" {
		ca, err := os.ReadFile(input.CA)
		if err != nil {
			return nil, nil, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, nil, errors.New("invalid fixture CA")
		}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, MaxConnsPerHost: 1, DisableCompression: true, ResponseHeaderTimeout: 35 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	client := &http.Client{Transport: bearerTransport{base: boundedTransport{base: transport}, endpoint: endpoint, token: token}, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if input.DiscardToolResponse {
		client.Transport = discardResponseTransport{base: client.Transport}
	}
	return client, transport, nil
}
