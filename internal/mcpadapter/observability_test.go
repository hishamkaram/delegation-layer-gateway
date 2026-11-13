package mcpadapter

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type toolEvents struct{ values []observability.Event }

func (e *toolEvents) Record(event observability.Event) { e.values = append(e.values, event) }

func TestToolEncodingFallbackIsRecordedAsErrorWithoutContent(t *testing.T) {
	schema, err := jsonschema.For[Envelope[DevicePage]](nil)
	check(t, err)
	validator, err := schema.Resolve(nil)
	check(t, err)
	events := &toolEvents{}
	adapter := &Adapter{options: Options{Recorder: events}}
	value := DevicePage{Devices: []Device{{Name: strings.Repeat(privateCanary, (1<<20)/len(privateCanary)+1)}}}
	result := recordedToolResult(adapter, domain.Actor{Principal: "principal"}, validator, Envelope[DevicePage]{Data: &value}, "")
	expectError[DevicePage](t, result, "evidence_invalid")
	if len(events.values) != 1 || events.values[0] != (observability.Event{Code: observability.MCPToolErrorReady, Principal: "principal"}) {
		t.Fatal("encoding fallback was recorded as successful data or leaked a caller value")
	}
	assertPublic(t, result)
}

func TestSDKToolAuditAndMetricsContainOnlyClosedMetadata(t *testing.T) {
	directory := t.TempDir()
	check(t, os.Chmod(directory, 0o700))
	audit, err := observability.Open(directory, time.Now)
	check(t, err)
	t.Cleanup(func() { check(t, audit.Close()) })
	metrics := &observability.Metrics{}
	recorder, err := observability.NewRecorder(audit, metrics)
	check(t, err)
	f := newRecordedFixture(t, 1, recorder)
	session := f.session(t, "alice")
	prepared := f.call(t, session, "prepare_dispatch", args(t, prepareFixture(privateCanary)))
	if prepared.IsError {
		t.Fatal("valid tool preparation failed")
	}
	expectError[DevicePage](t, f.call(t, session, "list_devices", json.RawMessage(`{"unknown":"`+privateCanary+`"}`)), "invalid_request")
	f.link.err = errors.New(privateCanary)
	expectError[DevicePage](t, f.call(t, session, "list_devices", json.RawMessage(`{}`)), "internal_error")
	limited := f.session(t, "inventory")
	expectError[Prepared](t, f.call(t, limited, "prepare_dispatch", args(t, prepareFixture(privateCanary))), "forbidden")

	entries, err := os.ReadDir(directory)
	check(t, err)
	var recorded strings.Builder
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "audit-") {
			data, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
			check(t, readErr)
			recorded.Write(data)
		}
	}
	data := recorded.String()
	if strings.Contains(data, privateCanary) || strings.Count(data, `"code":"mcp_tool_response_ready"`) != 1 || strings.Count(data, `"code":"mcp_tool_error_ready"`) != 3 || strings.Count(data, `"principal":"`+string(f.alice.Principal)+`"`) != 5 {
		t.Fatal("audit lost closed tool metadata or retained caller/native data")
	}
	assertScopeDenialEvents(t, data, f.alice.Principal)
	writer := httptest.NewRecorder()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://unix/v1/metadata/metrics", nil)
	check(t, err)
	metrics.ServeHTTP(writer, request)
	if !strings.Contains(writer.Body.String(), `gateway_events_total{event="mcp_tool_response_ready"} 1`) || !strings.Contains(writer.Body.String(), `gateway_events_total{event="mcp_tool_error_ready"} 3`) || strings.Contains(writer.Body.String(), string(f.alice.Principal)) || strings.Contains(writer.Body.String(), privateCanary) {
		t.Fatal("metric labels lost fixed counts or contain caller values")
	}
	if !recorder.Health().AuditHealthy || recorder.Health().MetricFailures != 0 {
		t.Fatal("valid events failed metadata recording")
	}
}

func assertScopeDenialEvents(t *testing.T, data string, principal domain.PrincipalID) {
	t.Helper()
	denials := 0
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		var event observability.Event
		check(t, json.Unmarshal([]byte(line), &event))
		if event.Code == observability.AuthorizationDenied {
			denials++
			if event.Principal != principal || event.Control.Class != routing.PrepareClass || event.Control.Authorization != routing.DeniedOrMissing || event.Device != "" || event.Project != "" || event.Operation != "" {
				t.Fatalf("early scope denial enriched rejected arguments: %+v", event)
			}
		}
	}
	if denials != 1 {
		t.Fatalf("missing explicit scope-denial audit: %d", denials)
	}
}

func TestInvalidRoutingArgumentsDoNotClaimGrantAuthorization(t *testing.T) {
	events := &toolEvents{}
	adapter := &Adapter{options: Options{Recorder: events}}
	adapter.recordToolRejection(domain.Actor{Principal: "principal"}, "dispatch_task", "invalid_request", time.Nanosecond)
	if len(events.values) != 1 {
		t.Fatal("missing bounded argument-rejection observation")
	}
	event := events.values[0]
	if event.Control.Authorization != routing.NotEvaluated || event.Principal != "principal" || event.Device != "" || event.Project != "" || event.Operation != "" {
		t.Fatalf("argument rejection invented authorized correlation: %+v", event)
	}
}
