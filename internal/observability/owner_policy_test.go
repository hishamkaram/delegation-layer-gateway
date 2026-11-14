package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func TestOwnerPolicyAuditAndProjectResolutionMetricsHaveBoundedLabels(t *testing.T) {
	event := Event{Code: OwnerPolicyChanged, Principal: "owner"}
	if !event.validate() {
		t.Fatal("opaque owner policy event rejected")
	}
	for _, invalid := range []Event{{Code: OwnerPolicyChanged}, {Code: OwnerPolicyChanged, Principal: "private/path"}, {Code: OwnerPolicyChanged, Principal: "owner", Device: "device"}} {
		if invalid.validate() {
			t.Fatal("unbounded or unrelated owner policy metadata accepted")
		}
	}
	var metrics Metrics
	if err := metrics.recordEvent(event); err != nil {
		t.Fatal(err)
	}
	control := completedAuditFixture()
	control.Control.Class = routing.ControlClass(protocol.ResolveProject)
	if err := metrics.recordEvent(control); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	metrics.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(out.Body.String(), `gateway_events_total{event="owner_policy_changed"} 1`) || !strings.Contains(out.Body.String(), `gateway_control_observations_total{class="resolve_project",transport="reply_received"} 1`) {
		t.Fatal("new fixed metadata vocabulary is absent from metrics")
	}
	if strings.Contains(out.Body.String(), `principal="owner"`) {
		t.Fatal("principal identity became a metric label")
	}
}

func TestRootControlsAndOwnedEnrollmentAuditKeepExactIdentityScope(t *testing.T) {
	event := completedAuditFixture()
	event.RootOnly = true
	event.Project = ""
	event.Control.Class = routing.ControlClass(protocol.ResolveProject)
	if !event.validate() {
		t.Fatal("root-routed metadata required a fictional project")
	}
	for _, change := range []func(*Event){
		func(e *Event) { e.Project = "project" },
		func(e *Event) { e.Device = "" },
		func(e *Event) { e.Control.Class = routing.ControlClass(protocol.Admit) },
		func(e *Event) { e.Code = OwnerPolicyChanged },
	} {
		invalid := event
		change(&invalid)
		if invalid.validate() {
			t.Fatal("root metadata accepted unrelated identity or operation")
		}
	}
	grant := Event{Code: EnrollmentGrantCreated, Principal: "owner", Device: "device"}
	if !grant.validate() {
		t.Fatal("bounded owner enrollment event refused")
	}
	grant.Operation = "operation"
	if grant.validate() {
		t.Fatal("enrollment event accepted unrelated operation metadata")
	}
	if (Event{Code: ResourceDenied, RootOnly: true}).validate() {
		t.Fatal("root-only denial omitted its route identity")
	}
}
