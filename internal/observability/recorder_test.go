package observability

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRecorderSurfacesAuditFailureWithoutPrivateDiagnostics(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	audit, err := Open(directory, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := audit.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	var metrics Metrics
	recorder, err := NewRecorder(audit, &metrics)
	if err != nil {
		t.Fatal(err)
	}
	recorder.Record(Event{Code: MCPRequestStarted})
	if !recorder.Health().AuditHealthy {
		t.Fatal("healthy sink reported failure")
	}
	if err = audit.Close(); err != nil {
		t.Fatal(err)
	}
	recorder.Record(Event{Code: MCPRequestCompleted})
	recorder.Record(Event{Code: Code("private-canary")})
	health := recorder.Health()
	if health.AuditHealthy || health.AuditFailures != 2 || health.MetricFailures != 1 {
		t.Fatalf("metadata failure state: %+v", health)
	}
	writer := httptest.NewRecorder()
	metrics.ServeHTTP(writer, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(writer.Body.String(), "private-canary") || !strings.Contains(writer.Body.String(), "gateway_metric_failures_total 1") {
		t.Fatal("metric failure leaked unchecked label or disappeared")
	}
}
