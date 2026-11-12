package httpguard

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newGuard(t *testing.T) *Guard {
	t.Helper()
	guard, err := New(Options{PublicOrigin: "https://gateway.example", ConcurrentRequests: 1, Timeout: time.Second, MaxBodyBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func tlsRequest() *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/mcp", strings.NewReader("{}"))
	request.TLS = &tls.ConnectionState{}
	return request
}

func TestHostOriginAndTLSBoundary(t *testing.T) {
	guard := newGuard(t)
	cases := map[string]func(*http.Request){
		"plaintext":      func(r *http.Request) { r.TLS = nil },
		"wrong host":     func(r *http.Request) { r.Host = "attacker.example" },
		"foreign origin": func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") },
		"duplicate origin": func(r *http.Request) {
			r.Header.Add("Origin", "https://gateway.example")
			r.Header.Add("Origin", "https://gateway.example")
		},
		"opaque origin": func(r *http.Request) { r.Header.Set("Origin", "null") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var observed []Rejection
			guard.rejected = func(reason Rejection) { observed = append(observed, reason) }
			request := tlsRequest()
			mutate(request)
			writer := httptest.NewRecorder()
			guard.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("denied request reached handler") })).ServeHTTP(writer, request)
			if writer.Code != http.StatusForbidden {
				t.Fatalf("status=%d", writer.Code)
			}
			if len(observed) != 1 || observed[0] != OriginRejected {
				t.Fatalf("boundary rejection metadata: %v", observed)
			}
		})
	}
}

func TestBodyBoundAndContextDeadline(t *testing.T) {
	guard := newGuard(t)
	request := tlsRequest()
	request.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 17)))
	guard.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("missing handler deadline")
		}
		_, err := io.ReadAll(r.Body)
		var limit *http.MaxBytesError
		if !errors.As(err, &limit) {
			t.Errorf("body limit missing: %v", err)
		}
	})).ServeHTTP(httptest.NewRecorder(), request)
}

func TestCancelledHandlerRetainsActiveSlotUntilReturn(t *testing.T) {
	guard := newGuard(t)
	rejected := make(chan Rejection, 1)
	guard.rejected = func(reason Rejection) { rejected <- reason }
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := tlsRequest().WithContext(ctx)
	handler := guard.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release }))
	go func() { defer close(done); handler.ServeHTTP(httptest.NewRecorder(), request) }()
	t.Cleanup(func() { close(release); <-done })
	<-entered
	cancel()
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, tlsRequest())
	if writer.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancellation freed still-owned slot: %d", writer.Code)
	}
	if reason := <-rejected; reason != CapacityRejected {
		t.Fatalf("capacity rejection category: %s", reason)
	}
}
