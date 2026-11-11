package observability

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Fixed event names are the complete metric label vocabulary. Opaque IDs, URLs,
// projects and provider names are deliberately absent from metric dimensions.
const metricCodeCount = 26

func metricCodes() [metricCodeCount]Code {
	return [metricCodeCount]Code{AuthenticationDenied, DeviceCredentialDenied, EnrollmentIssued, DeviceConnected, DeviceDisconnected, CredentialRevoked, OperationPrepared, ControlSent, ControlCompleted, ControlUnknown, AuthorizationDenied, ResourceDenied, RecoveryBlocked, ShutdownStarted, MCPRequestStarted, MCPRequestCompleted, MCPToolResponseReady, MCPToolErrorReady, EnrollmentRequestStarted, EnrollmentRequestCompleted, MetadataRequestStarted, MetadataRequestCompleted, DeviceRequestStarted, DeviceRequestCompleted, RenewalIssued, RenewalUnavailable}
}

type Metrics struct {
	events         [metricCodeCount]atomic.Uint64
	auditFailures  atomic.Uint64
	metricFailures atomic.Uint64
}

func (m *Metrics) Record(code Code) error {
	for i, candidate := range metricCodes() {
		if candidate == code {
			m.events[i].Add(1)
			return nil
		}
	}
	return ErrUnavailable
}
func (m *Metrics) AuditFailed() { m.auditFailures.Add(1) }

// ServeHTTP must be mounted only behind the protected local administration
// listener. It exposes fixed counters, never task data or arbitrary labels.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	for i, code := range metricCodes() {
		if _, err := fmt.Fprintf(w, "gateway_events_total{event=%q} %d\n", code, m.events[i].Load()); err != nil {
			return
		}
	}
	if _, err := fmt.Fprintf(w, "gateway_audit_failures_total %d\n", m.auditFailures.Load()); err != nil {
		return
	}
	if _, err := fmt.Fprintf(w, "gateway_metric_failures_total %d\n", m.metricFailures.Load()); err != nil {
		return
	}
}
