package mcpadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
)

func TestAuthenticatedBodyOverflowRecordsResourceDenialWithoutRouting(t *testing.T) {
	directory := t.TempDir()
	check(t, os.Chmod(directory, 0o700))
	audit, err := observability.Open(directory, time.Now)
	check(t, err)
	t.Cleanup(func() { check(t, audit.Close()) })
	metrics := &observability.Metrics{}
	recorder, err := observability.NewRecorder(audit, metrics)
	check(t, err)
	f := newRecordedFixture(t, 1, recorder)
	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"prepare_dispatch","arguments":` + string(args(t, prepareFixture(privateCanary))) + `}}`
	body := payload + strings.Repeat(" ", maxRequestBodyBytes+1-len(payload))
	response, data := readHTTPResponse(t, f.server.Client(), framingRequest(t, f.server.URL, body, "2025-06-18"))
	if response.StatusCode != http.StatusRequestEntityTooLarge || strings.Contains(string(data), privateCanary) {
		t.Fatalf("body overflow response: HTTP%d", response.StatusCode)
	}
	operations, err := f.store.ListOperations(t.Context(), f.alice, domain.OperationPageRequest{})
	check(t, err)
	if len(operations.Items) != 0 {
		t.Fatal("oversized body reached task preparation")
	}
	writer := httptest.NewRecorder()
	metrics.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "http://unix/metrics", nil))
	if !strings.Contains(writer.Body.String(), `gateway_events_total{event="resource_denied"} 1`) || strings.Contains(writer.Body.String(), privateCanary) {
		t.Fatal("authenticated overflow lost its exact resource-denial counter")
	}
	assertFramingDenialAudit(t, directory, f.alice.Principal)
	if !recorder.Health().AuditHealthy || recorder.Health().MetricFailures != 0 {
		t.Fatal("overflow metadata failed recording")
	}
}

func assertFramingDenialAudit(t *testing.T, directory string, principal domain.PrincipalID) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	check(t, err)
	denials := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "audit-") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		check(t, readErr)
		if strings.Contains(string(data), privateCanary) {
			t.Fatal("rejected body appeared in audit")
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var event observability.Event
			check(t, json.Unmarshal([]byte(line), &event))
			if event.Code == observability.ResourceDenied {
				denials++
				if event.Principal != principal || event.Device != "" || event.Project != "" || event.Operation != "" {
					t.Fatalf("overflow fabricated destination authority: %+v", event)
				}
			}
		}
	}
	if denials != 1 {
		t.Fatalf("resource-denial audit count=%d, want1", denials)
	}
}
