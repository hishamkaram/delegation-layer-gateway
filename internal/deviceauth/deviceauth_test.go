package deviceauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIssuerRequestsAndSlowDown(t *testing.T) {
	t.Parallel()
	issuer := &pollingIssuer{t: t}
	server := httptest.NewTLSServer(issuer)
	t.Cleanup(server.Close)
	client := testClient(t, server.Client(), server.URL, 15*time.Second)
	challenge, err := client.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if challenge.UserCode() != "USER-CODE" || challenge.VerificationURI() != "https://issuer.example/activate" || challenge.VerificationURIComplete() != "https://issuer.example/activate?user_code=USER-CODE" {
		t.Fatal("caller cannot present the issuer's code and verification URLs")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, challenge), "SECRET") || strings.Contains(fmt.Sprintf(format, challenge), "USER-CODE") {
			t.Fatal("formatted challenge exposed authorization material")
		}
	}
	token, err := client.Await(t.Context(), challenge)
	if err != nil || token != "TOKEN_SECRET" || issuer.attempts.Load() != 3 {
		t.Fatalf("bounded device flow did not complete: %v; attempts=%d", err, issuer.attempts.Load())
	}
	if _, err = client.Await(t.Context(), challenge); !errors.Is(err, ErrConsumed) {
		t.Fatal("same challenge started a second polling flow")
	}
	copyChallenge := *challenge
	if _, err = client.Await(t.Context(), &copyChallenge); !errors.Is(err, ErrConsumed) {
		t.Fatal("copying the challenge bypassed its single polling owner")
	}
}

func TestTokenFailuresAreTerminalAndRedacted(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		body string
		code int
		want error
	}{
		{"denied", `{"error":"access_denied","error_description":"PRIVATE_SECRET"}`, 400, ErrDenied},
		{"expired", `{"error":"expired_token","error_uri":"https://PRIVATE_SECRET"}`, 400, ErrExpired},
		{"unknown", `{"error":"PRIVATE_SECRET"}`, 500, ErrIssuer},
		{"client", `{"error":"invalid_client","error_description":"PRIVATE_SECRET"}`, 401, ErrConfiguration},
		{"malformed", `PRIVATE_SECRET`, 200, ErrResponse},
		{"missing token", `{"token_type":"Bearer"}`, 200, ErrResponse},
		{"wrong type", `{"access_token":"PRIVATE_SECRET","token_type":"Basic"}`, 200, ErrResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var attempts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/device" {
					writeJSON(t, w, validResponse("https://issuer.example/activate"))
					return
				}
				attempts.Add(1)
				w.WriteHeader(test.code)
				if _, err := io.WriteString(w, test.body); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)
			client := testClient(t, server.Client(), server.URL, 5*time.Second)
			challenge, err := client.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Await(t.Context(), challenge)
			if !errors.Is(err, test.want) || strings.Contains(fmt.Sprintf("%#v", err), "PRIVATE_SECRET") || attempts.Load() != 1 {
				t.Fatalf("incorrect sanitized terminal failure: %v; attempts=%d", err, attempts.Load())
			}
		})
	}
}

func TestInitialResponseValidationAndClosure(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"device code", func(v map[string]any) { delete(v, "device_code") }},
		{"user terminal escape", func(v map[string]any) { v["user_code"] = "\x1b[31m" }},
		{"negative interval", func(v map[string]any) { v["interval"] = -1 }},
		{"zero interval", func(v map[string]any) { v["interval"] = 0 }},
		{"null interval", func(v map[string]any) { v["interval"] = nil }},
		{"overflow interval", func(v map[string]any) { v["interval"] = int64(9223372036854775807) }},
		{"negative expiry", func(v map[string]any) { v["expires_in"] = -1 }},
		{"zero expiry", func(v map[string]any) { v["expires_in"] = 0 }},
		{"null expiry", func(v map[string]any) { v["expires_in"] = nil }},
		{"overflow expiry", func(v map[string]any) { v["expires_in"] = int64(9223372036854775807) }},
		{"noninteger expiry", func(v map[string]any) { v["expires_in"] = "60" }},
		{"insecure verification", func(v map[string]any) { v["verification_uri"] = "http://issuer.example/activate" }},
		{"verification userinfo", func(v map[string]any) { v["verification_uri"] = "https://secret@issuer.example/activate" }},
		{"changed complete origin", func(v map[string]any) { v["verification_uri_complete"] = "https://other.example/activate" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := validResponse("https://issuer.example/activate")
			test.change(response)
			body, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			var closed atomic.Int32
			client := testClient(t, responseClient(body, 200, &closed, nil), "https://issuer.example", time.Minute)
			if _, err = client.Begin(t.Context()); !errors.Is(err, ErrResponse) {
				t.Fatalf("accepted invalid issuer response: %v", err)
			}
			if closed.Load() != 1 {
				t.Fatal("initial response body not closed on rejection")
			}
		})
	}
}

func TestInitialResponseCleanupFailuresAndLimits(t *testing.T) {
	t.Parallel()
	valid, err := json.Marshal(validResponse("https://issuer.example/activate"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		body     []byte
		status   int
		closeErr error
		want     error
	}{
		{"oversized", []byte(strings.Repeat("x", MaxResponseBytes+1)), 200, nil, ErrResponse},
		{"malformed", []byte(`PRIVATE_SECRET`), 200, nil, ErrResponse},
		{"issuer", []byte(`{"error":"PRIVATE_SECRET"}`), 401, nil, ErrIssuer},
		{"denied", []byte(`{"error":"access_denied"}`), 403, nil, ErrDenied},
		{"redirect", valid, 302, nil, ErrIssuer},
		{"close failure", valid, 200, errors.New("PRIVATE_SECRET"), ErrTransport},
	} {
		t.Run(test.name, func(t *testing.T) {
			var closed atomic.Int32
			client := testClient(t, responseClient(test.body, test.status, &closed, test.closeErr), "https://issuer.example", time.Minute)
			challenge, err := client.Begin(t.Context())
			if challenge != nil || !errors.Is(err, test.want) || strings.Contains(fmt.Sprintf("%#v", err), "PRIVATE_SECRET") || closed.Load() != 1 {
				t.Fatalf("unexpected failure or leaked response: %v; close count=%d", err, closed.Load())
			}
		})
	}
}

func TestFlowDeadlineStartsAtBeginAndMissingExpiryIsBounded(t *testing.T) {
	t.Parallel()
	response := validResponse("https://issuer.example/activate")
	delete(response, "expires_in")
	delete(response, "interval")
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int32
	client := testClient(t, responseClient(body, 200, &closed, nil), "https://issuer.example", time.Second)
	before := time.Now()
	challenge, err := client.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if challenge.ExpiresAt().After(time.Now().Add(time.Second)) || challenge.ExpiresAt().Before(before) {
		t.Fatal("missing issuer expiry did not inherit a finite local deadline")
	}
	timer := time.NewTimer(time.Until(challenge.ExpiresAt()) + time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if _, err = client.Await(t.Context(), challenge); !errors.Is(err, ErrExpired) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fresh caller context extended an expired challenge: %v", err)
	}
	if closed.Load() != 1 {
		t.Fatal("expired Await started another request")
	}
}

func TestMissingIntervalWaitsFiveSecondsBeforePolling(t *testing.T) {
	t.Parallel()
	response := validResponse("https://issuer.example/activate")
	delete(response, "interval")
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int32
	initial := responseClient(body, 200, &closed, nil).Transport
	var first atomic.Int64
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/device" {
			return initial.RoundTrip(req)
		}
		first.Store(time.Now().UnixNano())
		return responseClient([]byte(`{"access_token":"TOKEN_SECRET","token_type":"Bearer"}`), 200, &closed, nil).Transport.RoundTrip(req)
	})}
	client := testClient(t, httpClient, "https://issuer.example", 10*time.Second)
	challenge, err := client.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err = client.Await(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	if time.Unix(0, first.Load()).Sub(start) < 4800*time.Millisecond {
		t.Fatal("missing interval did not preserve RFC 8628's five-second default")
	}
}

func TestInitialReadFailureClosesAndRedactsResponse(t *testing.T) {
	t.Parallel()
	var closed atomic.Int32
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if closeErr := req.Body.Close(); closeErr != nil {
			return nil, closeErr
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: observedBody{Reader: failedReader{}, closed: &closed}, Request: req}, nil
	})}
	client := testClient(t, httpClient, "https://issuer.example", time.Minute)
	if _, err := client.Begin(t.Context()); !errors.Is(err, ErrTransport) || closed.Load() != 1 || strings.Contains(fmt.Sprintf("%#v", err), "PRIVATE_SECRET") {
		t.Fatalf("read failure lost cleanup or error redaction: %v", err)
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_SECRET") }

func TestCallerDeadlineAndCancellation(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, validResponse("https://issuer.example/activate"))
	}))
	t.Cleanup(server.Close)
	client := testClient(t, server.Client(), server.URL, time.Minute)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	challenge, err := client.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	if challenge.ExpiresAt().After(deadline) {
		t.Fatal("issuer or configured lifetime extended the caller deadline")
	}
	cancel()
	if _, err = client.Await(ctx, challenge); !errors.Is(err, ErrCancelled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost its safe classification: %v", err)
	}
}

func TestCancellationJoinsAnInFlightTokenRequest(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	var attempts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/device" {
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, validResponse("https://issuer.example/activate"))
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if attempts.Add(1) == 1 {
			close(started)
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	client := testClient(t, server.Client(), server.URL, 10*time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	challenge, err := client.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var waitErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, waitErr = client.Await(ctx, challenge)
	}()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("token request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not join token polling")
	}
	if !errors.Is(waitErr, context.Canceled) || !errors.Is(waitErr, ErrCancelled) || attempts.Load() != 1 {
		t.Fatalf("cancellation lost classification or retried: %v", waitErr)
	}
}

func TestNetworkFailureDoesNotProbeAnotherAuthenticationStyle(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	var closed atomic.Int32
	response, err := json.Marshal(validResponse("https://issuer.example/activate"))
	if err != nil {
		t.Fatal(err)
	}
	transport := responseClient(response, 200, &closed, nil).Transport
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/device" {
			return transport.RoundTrip(req)
		}
		attempts.Add(1)
		if closeErr := req.Body.Close(); closeErr != nil {
			return nil, closeErr
		}
		return nil, &url.Error{Op: "Post", URL: "https://PRIVATE_SECRET", Err: errors.New("PRIVATE_SECRET")}
	})}
	client := testClient(t, httpClient, "https://issuer.example", 5*time.Second)
	challenge, err := client.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Await(t.Context(), challenge)
	if !errors.Is(err, ErrTransport) || attempts.Load() != 1 || strings.Contains(fmt.Sprintf("%#v", err), "PRIVATE_SECRET") {
		t.Fatalf("transport error caused a retry or leaked private output: %v; attempts=%d", err, attempts.Load())
	}
}

func TestClientRejectsForeignChallengeAndLeavesHTTPClientUnchanged(t *testing.T) {
	t.Parallel()
	var closed atomic.Int32
	body, err := json.Marshal(validResponse("https://issuer.example/activate"))
	if err != nil {
		t.Fatal(err)
	}
	httpClient := responseClient(body, 200, &closed, nil)
	first := testClient(t, httpClient, "https://issuer.example", time.Minute)
	second := testClient(t, httpClient, "https://issuer.example", time.Minute)
	challenge, err := first.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = second.Await(t.Context(), challenge); !errors.Is(err, ErrConfiguration) {
		t.Fatal("foreign client consumed another authorization flow")
	}
	if challenge.consumed.Load() {
		t.Fatal("foreign client invalidated the owning client's challenge")
	}
	if httpClient.Timeout != 0 || httpClient.CheckRedirect != nil {
		t.Fatal("New mutated the caller-owned HTTP client")
	}
}

func TestBeginDisallowsRedirects(t *testing.T) {
	t.Parallel()
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	t.Cleanup(target.Close)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	client := testClient(t, server.Client(), server.URL, time.Minute)
	if _, err := client.Begin(t.Context()); !errors.Is(err, ErrIssuer) || redirected.Load() != 0 {
		t.Fatalf("device authorization followed a redirect: %v", err)
	}
}

func TestConfigurationRejectsUnsafeValues(t *testing.T) {
	t.Parallel()
	for _, change := range []func(*Config){
		func(v *Config) { v.HTTPClient = nil },
		func(v *Config) { v.DeviceEndpoint = "http://issuer.example/device" },
		func(v *Config) { v.TokenEndpoint = "https://secret@issuer.example/token" },
		func(v *Config) { v.TokenEndpoint = "https://issuer.example/token#fragment" },
		func(v *Config) { v.FlowTimeout = -time.Second },
		func(v *Config) { v.FlowTimeout = MaxFlowTimeout + time.Second },
		func(v *Config) { v.Scopes = []string{"device:enroll", "device:enroll"} },
		func(v *Config) { v.Scopes = []string{"device:enroll device:manage"} },
		func(v *Config) { v.ClientID = "native\nclient" },
	} {
		config := testConfig(&http.Client{}, "https://issuer.example", time.Minute)
		change(&config)
		if _, err := New(config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("accepted unsafe configuration: %v", err)
		}
	}
}

func validResponse(verification string) map[string]any {
	return map[string]any{
		"device_code":               "DEVICE_SECRET",
		"user_code":                 "USER-CODE",
		"verification_uri":          verification,
		"verification_uri_complete": verification + "?user_code=USER-CODE",
		"expires_in":                60,
		"interval":                  1,
	}
}

func testConfig(httpClient *http.Client, origin string, timeout time.Duration) Config {
	return Config{ClientID: "native-client", DeviceEndpoint: origin + "/device", TokenEndpoint: origin + "/token", Audience: "https://gateway.example/mcp", Scopes: []string{"device:enroll"}, HTTPClient: httpClient, FlowTimeout: timeout}
}

func testClient(t *testing.T, httpClient *http.Client, origin string, timeout time.Duration) *Client {
	t.Helper()
	client, err := New(testConfig(httpClient, origin, timeout))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type observedBody struct {
	io.Reader
	closed   *atomic.Int32
	closeErr error
}

func (b observedBody) Close() error {
	b.closed.Add(1)
	return b.closeErr
}

func responseClient(body []byte, status int, closed *atomic.Int32, responseCloseErr error) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if closeErr := req.Body.Close(); closeErr != nil {
			return nil, closeErr
		}
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       observedBody{Reader: strings.NewReader(string(body)), closed: closed, closeErr: responseCloseErr},
			Request:    req,
		}, nil
	})}
}

func TestTransportErrorDoesNotExposeURL(t *testing.T) {
	t.Parallel()
	client := testClient(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Post", URL: "https://PRIVATE_SECRET", Err: errors.New("PRIVATE_SECRET")}
	})}, "https://issuer.example", time.Minute)
	if _, err := client.Begin(t.Context()); !errors.Is(err, ErrTransport) || strings.Contains(fmt.Sprintf("%#v", err), "PRIVATE_SECRET") {
		t.Fatalf("transport diagnostic exposed raw URL or provider error: %v", err)
	}
}

type pollingIssuer struct {
	t        *testing.T
	attempts atomic.Int32
	second   atomic.Int64
}

func (p *pollingIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !checkPublicForm(p.t, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/device" {
		if r.Form.Get("audience") != "https://gateway.example/mcp" {
			p.t.Error("missing explicit API audience")
		}
		writeJSON(p.t, w, validResponse("https://issuer.example/activate"))
		return
	}
	if r.URL.Path != "/token" || r.Form.Get("device_code") != "DEVICE_SECRET" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
		p.t.Error("incorrect token request")
	}
	p.tokenResponse(w)
}

func checkPublicForm(t *testing.T, r *http.Request) bool {
	t.Helper()
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
		t.Error("authorization must use one form POST without header authentication or URL credentials")
	}
	if err := r.ParseForm(); err != nil {
		t.Error(err)
		return false
	}
	if r.Form.Get("client_id") != "native-client" || r.Form.Get("scope") != "device:enroll" || r.Form.Get("client_secret") != "" {
		t.Error("public client identity, scope or absent-secret contract changed")
	}
	return true
}

func (p *pollingIssuer) tokenResponse(w http.ResponseWriter) {
	switch p.attempts.Add(1) {
	case 1:
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(p.t, w, map[string]string{"error": "authorization_pending"})
	case 2:
		p.second.Store(time.Now().UnixNano())
		w.WriteHeader(http.StatusTooManyRequests)
		writeJSON(p.t, w, map[string]string{"error": "slow_down"})
	case 3:
		// Initial interval is one second; RFC 8628 requires adding five.
		if time.Since(time.Unix(0, p.second.Load())) < 5800*time.Millisecond {
			p.t.Error("polling ignored the mandatory slow_down interval increase")
		}
		writeJSON(p.t, w, map[string]string{"access_token": "TOKEN_SECRET", "token_type": "Bearer", "refresh_token": "REFRESH_SECRET"})
	default:
		p.t.Error("flow restarted or retried after success")
	}
}
