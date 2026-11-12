package observability

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBoundaryCountersNeverClaimAuditWritesOrDynamicLabels(t *testing.T) {
	directory := privateDirectory(t)
	audit, err := Open(directory, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	metrics := &Metrics{}
	recorder, err := NewRecorder(audit, metrics)
	if err != nil {
		t.Fatal(err)
	}
	if err = audit.Close(); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []BoundaryReason{BoundaryOrigin, BoundaryOrigin, BoundaryCapacity, BoundaryReason("private-canary"), BoundaryReason(AuthenticationDenied)} {
		recorder.CountBoundaryRejection(reason)
	}
	health := recorder.Health()
	if !health.AuditHealthy || health.AuditFailures != 0 || health.MetricFailures != 2 {
		t.Fatalf("counter-only accounting invented audit writes: %+v", health)
	}
	writer := httptest.NewRecorder()
	metrics.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "http://unix/metrics", nil))
	data := writer.Body.Bytes()
	for _, expected := range []string{`gateway_boundary_rejections_total{reason="origin"} 2`, `gateway_boundary_rejections_total{reason="capacity"} 1`, `gateway_events_total{event="authentication_denied"} 0`} {
		if !bytes.Contains(data, []byte(expected)) {
			t.Fatalf("fixed boundary counter missing: %s", expected)
		}
	}
	if bytes.Contains(data, []byte("private-canary")) {
		t.Fatal("invalid reason became an arbitrary metric label")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "audit-") {
			t.Fatal("counter path created a durable audit row")
		}
	}
}
