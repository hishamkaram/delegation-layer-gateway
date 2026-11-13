package observability

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestRevocationCleanupFailureCarriesOnlyBoundedIdentity(t *testing.T) {
	event := Event{Code: RevocationCleanupUnavailable, Principal: "principal-canary-73ac", Device: "device-canary-b190"}
	if !event.validate() {
		t.Fatal("bounded revocation cleanup metadata rejected")
	}
	for _, invalid := range []Event{
		{Code: RevocationCleanupUnavailable, Device: "device"},
		{Code: RevocationCleanupUnavailable, Principal: "owner"},
		{Code: RevocationCleanupUnavailable, Principal: "owner", Device: "/private-canary"},
		{Code: RevocationCleanupUnavailable, Principal: "owner", Device: "device", Operation: "operation"},
		{Code: RevocationCleanupUnavailable, Principal: "owner", Device: "device", Project: domain.ProjectAlias("project")},
	} {
		if invalid.validate() {
			t.Fatal("unbounded or unrelated cleanup metadata accepted")
		}
	}
	var metrics Metrics
	if err := metrics.recordEvent(event); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	metrics.ServeHTTP(out, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(out.Body.String(), `gateway_events_total{event="revocation_cleanup_unavailable"} 1`) {
		t.Fatal("cleanup failure metric absent")
	}
	// Fixed vocabulary such as owner_policy_changed is allowed; actual
	// identity values must never appear anywhere in rendered metrics.
	if strings.Contains(out.Body.String(), string(event.Principal)) || strings.Contains(out.Body.String(), string(event.Device)) {
		t.Fatal("owner or device became a metric label")
	}
}
