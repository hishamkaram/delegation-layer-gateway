package adminapi_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
)

func metadataFixture(t *testing.T, metrics http.Handler, health func() observability.Health) *fixture {
	t.Helper()
	f := newFixture(t, nil)
	f.stop()
	handler, handlerErr := adminapi.NewHandler(adminapi.Options{Store: f.store, Authority: f.authority, Disconnector: disconnectFunc(func(_ context.Context, _ domain.DeviceID) error { return nil }), Random: rand.Reader, Now: func() time.Time { return f.now }, MetadataMetrics: metrics, MetadataHealth: health})
	check(t, handlerErr)
	f.handler = handler
	f.start(t)
	return f
}

func metadataRequest(t *testing.T, client *http.Client, method, endpoint string, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()
	request, requestErr := http.NewRequestWithContext(t.Context(), method, endpoint, nil)
	check(t, requestErr)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, responseErr := client.Do(request)
	check(t, responseErr)
	defer func() { check(t, response.Body.Close()) }()
	data, readErr := io.ReadAll(response.Body)
	check(t, readErr)
	return response.StatusCode, response.Header, data
}

func boundedMetrics(t *testing.T, metrics *observability.Metrics) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, present := r.Context().Deadline()
		if !present || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
			t.Error("metadata handler lacks existing finite admin context")
		}
		metrics.ServeHTTP(w, r)
	})
}

func TestPrivateUnixMetadataReadOnlyAndClosedHealth(t *testing.T) {
	var metrics observability.Metrics
	check(t, metrics.Record(observability.AuthenticationDenied))
	f := metadataFixture(t, boundedMetrics(t, &metrics), func() observability.Health {
		return observability.Health{AuditHealthy: false, AuditFailures: 7, MetricFailures: 2}
	})
	status, headers, body := metadataRequest(t, f.client, http.MethodGet, "http://unix/v1/metadata/metrics", nil)
	if status != http.StatusOK || !strings.HasPrefix(headers.Get("Content-Type"), "text/plain;") || !strings.Contains(string(body), `gateway_events_total{event="authentication_denied"} 1`) {
		t.Fatalf("metadata metrics mismatch: status=%d", status)
	}
	status, headers, body = metadataRequest(t, f.client, http.MethodGet, "http://unix/v1/metadata/health", nil)
	if status != http.StatusOK || headers.Get("Content-Type") != "application/json" || string(body) != `{"audit_healthy":false,"audit_failures":7,"metric_failures":2}` {
		t.Fatalf("closed metadata health mismatch: status=%d body=%s", status, body)
	}
	var health observability.Health
	check(t, json.Unmarshal(body, &health))
	if health.AuditHealthy || health.AuditFailures != 7 || health.MetricFailures != 2 {
		t.Fatal("metadata health changed authoritative snapshot")
	}
	for _, path := range []string{"metrics", "health"} {
		status, headers, body = metadataRequest(t, f.client, http.MethodHead, "http://unix/v1/metadata/"+path, nil)
		if status != http.StatusOK || len(body) != 0 || headers.Get("Cache-Control") != "no-store" || headers.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("HEAD metadata emitted body or lost private response headers")
		}
	}
}

func TestUnixMetadataRejectsMethodsQueryOriginEncodingAndArbitraryPath(t *testing.T) {
	f := metadataFixture(t, &observability.Metrics{}, func() observability.Health { return observability.Health{AuditHealthy: true} })
	cases := []struct {
		method, path string
		headers      map[string]string
		status       int
	}{
		{http.MethodPost, "/v1/metadata/metrics", nil, http.StatusMethodNotAllowed},
		{http.MethodDelete, "/v1/metadata/health", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/metadata/metrics?token=canary", nil, http.StatusBadRequest},
		{http.MethodGet, "/v1/metadata/health?", nil, http.StatusBadRequest},
		{http.MethodGet, "/v1/metadata/metrics", map[string]string{"Origin": "https://canary.example"}, http.StatusBadRequest},
		{http.MethodGet, "/v1/metadata/health", map[string]string{"Content-Encoding": "gzip"}, http.StatusUnsupportedMediaType},
		{http.MethodGet, "/v1/metadata/%6detrics", nil, http.StatusBadRequest},
		{http.MethodGet, "/v1/metadata/arbitrary", map[string]string{"Content-Type": "application/json"}, http.StatusNotFound},
		{http.MethodGet, "/metrics", map[string]string{"Content-Type": "application/json"}, http.StatusNotFound},
	}
	for _, test := range cases {
		status, headers, body := metadataRequest(t, f.client, test.method, "http://unix"+test.path, test.headers)
		if status != test.status || strings.Contains(string(body), "canary") {
			t.Fatalf("metadata restriction method=%s path=%s status=%d", test.method, test.path, status)
		}
		if status == http.StatusMethodNotAllowed && headers.Get("Allow") != "GET, HEAD" {
			t.Fatal("metadata Allow header must name exactly GET and HEAD")
		}
	}
}

func TestMetadataHooksDisabledAndPublicMountDenied(t *testing.T) {
	disabled := newFixture(t, nil)
	for _, path := range []string{"metrics", "health"} {
		status, _, _ := metadataRequest(t, disabled.client, http.MethodGet, "http://unix/v1/metadata/"+path, nil)
		if status != http.StatusNotFound {
			t.Fatal("nil metadata hook was enabled")
		}
	}
	f := metadataFixture(t, &observability.Metrics{}, func() observability.Health { return observability.Health{AuditHealthy: true} })
	public := httptest.NewServer(f.handler)
	t.Cleanup(public.Close)
	for _, path := range []string{"metrics", "health"} {
		status, _, body := metadataRequest(t, public.Client(), http.MethodGet, public.URL+"/v1/metadata/"+path, map[string]string{"X-Admin": "true", "X-Forwarded-For": "unix"})
		if status != http.StatusForbidden || strings.Contains(string(body), "gateway_") || strings.Contains(string(body), "audit_healthy") {
			t.Fatal("public mount bypassed private metadata authority")
		}
		request := httptest.NewRequest(http.MethodGet, "http://unix/v1/metadata/"+path, nil)
		request.RemoteAddr = "@unix"
		writer := httptest.NewRecorder()
		f.handler.ServeHTTP(writer, request)
		if writer.Code != http.StatusForbidden {
			t.Fatal("public handler context acquired metadata authority")
		}
	}
}
