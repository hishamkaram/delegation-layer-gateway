package observability

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// Labels use only the fixed event, control, transport and boundary vocabularies.
// Opaque IDs, URLs, projects and provider names are absent from metric dimensions.
const (
	metricCodeCount       = 27
	controlClassCount     = 13
	transportOutcomeCount = 6
)

func metricCodes() [metricCodeCount]Code {
	return [metricCodeCount]Code{AuthenticationDenied, DeviceCredentialDenied, EnrollmentIssued, DeviceConnected, DeviceDisconnected, DeviceConnectionFailed, CredentialRevoked, OperationPrepared, ControlSent, ControlCompleted, ControlUnknown, AuthorizationDenied, ResourceDenied, RecoveryBlocked, ShutdownStarted, MCPRequestStarted, MCPRequestCompleted, MCPToolResponseReady, MCPToolErrorReady, EnrollmentRequestStarted, EnrollmentRequestCompleted, MetadataRequestStarted, MetadataRequestCompleted, DeviceRequestStarted, DeviceRequestCompleted, RenewalIssued, RenewalUnavailable}
}

func controlClasses() [controlClassCount]routing.ControlClass {
	return [controlClassCount]routing.ControlClass{routing.PrepareClass, routing.ControlClass(protocol.ContextInspect), routing.ControlClass(protocol.Admit), routing.ControlClass(protocol.Resolve), routing.ControlClass(protocol.ResumeExisting), routing.ControlClass(protocol.FenceAbsent), routing.ControlClass(protocol.Status), routing.ControlClass(protocol.Collect), routing.ControlClass(protocol.ResultChunk), routing.ControlClass(protocol.Cancel), routing.ControlClass(protocol.OriginBarrier), routing.ControlClass(protocol.OriginInventory), routing.ControlClass(protocol.OriginReopen)}
}

func transportOutcomes() [transportOutcomeCount]routing.TransportOutcome {
	return [transportOutcomeCount]routing.TransportOutcome{routing.NotAttempted, routing.NotSent, routing.WriteUnknown, routing.WrittenNoReply, routing.ReplyReceived, routing.ReplyInvalid}
}

type controlMetrics struct {
	observations       atomic.Uint64
	durationNS         atomic.Uint64
	requestFrameBytes  atomic.Uint64
	responseFrameBytes atomic.Uint64
}

// RuntimeSnapshot is one dated value collected by the current Registry/Hub
// owners. Metrics neither retain it nor become an authority for live presence.
type RuntimeSnapshot struct {
	ActiveDevices     uint64
	AuthorizedDevices uint64
	WSSConnections    uint64
	RegisteredDevices uint64
}

type Metrics struct {
	events         [metricCodeCount]atomic.Uint64
	auditFailures  atomic.Uint64
	metricFailures atomic.Uint64
	reconnections  atomic.Uint64
	controls       [controlClassCount][transportOutcomeCount]controlMetrics
	boundary       [boundaryReasonCount]atomic.Uint64
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

func (m *Metrics) recordEvent(event Event) error {
	if !event.validate() {
		return ErrUnavailable
	}
	var control *controlMetrics
	if finalControlEvent(event) {
		control = m.controlCounter(event.Control)
		if control == nil {
			return ErrUnavailable
		}
	}
	if err := m.Record(event.Code); err != nil {
		return err
	}
	// Registry's durable counter survives Gateway boots. A successful repeat
	// generation does not prove that any earlier handshake succeeded.
	if event.Code == DeviceConnected && event.Connection.Counter > 1 {
		m.reconnections.Add(1)
	}
	if control != nil {
		control.observations.Add(1)
		control.durationNS.Add(uint64(event.Control.DurationNS))
		control.requestFrameBytes.Add(uint64(event.Control.EncodedRequestFrameBytes))
		control.responseFrameBytes.Add(uint64(event.Control.EncodedResponseFrameBytes))
	}
	return nil
}

func finalControlEvent(event Event) bool {
	if event.Control == (routing.ControlMetadata{}) {
		return false
	}
	return event.Code == OperationPrepared || event.Code == ControlCompleted || event.Code == ControlUnknown || event.Code == AuthorizationDenied || event.Code == ResourceDenied || event.Code == RecoveryBlocked
}

func (m *Metrics) controlCounter(metadata routing.ControlMetadata) *controlMetrics {
	for i, class := range controlClasses() {
		if class != metadata.Class {
			continue
		}
		for j, outcome := range transportOutcomes() {
			if outcome == metadata.Transport {
				return &m.controls[i][j]
			}
		}
	}
	return nil
}

// ServeHTTP must be mounted only behind the protected local administration
// listener. It exposes fixed counters, never task data or arbitrary labels.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(w, r, nil)
}

// WriteSnapshot renders explicit current-owner counts. A caller with an unknown
// snapshot must report that failure instead of supplying invented zero counts.
func (m *Metrics) WriteSnapshot(w http.ResponseWriter, r *http.Request, snapshot RuntimeSnapshot) {
	m.serve(w, r, &snapshot)
}

func (m *Metrics) serve(w http.ResponseWriter, r *http.Request, snapshot *RuntimeSnapshot) {
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
	if err := m.writeCounters(w); err != nil {
		return
	}
	if snapshot != nil {
		if _, err := fmt.Fprintf(w, "gateway_active_devices %d\ngateway_authorized_devices %d\ngateway_wss_connections %d\ngateway_registered_devices %d\n", snapshot.ActiveDevices, snapshot.AuthorizedDevices, snapshot.WSSConnections, snapshot.RegisteredDevices); err != nil {
			return
		}
	}
}

func (m *Metrics) writeCounters(w io.Writer) error {
	for i, code := range metricCodes() {
		if _, err := fmt.Fprintf(w, "gateway_events_total{event=%q} %d\n", code, m.events[i].Load()); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "gateway_audit_failures_total %d\n", m.auditFailures.Load()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "gateway_metric_failures_total %d\n", m.metricFailures.Load()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "gateway_device_reconnections_total %d\n", m.reconnections.Load()); err != nil {
		return err
	}
	if err := m.writeBoundaryCounters(w); err != nil {
		return err
	}
	for i, class := range controlClasses() {
		for j, outcome := range transportOutcomes() {
			if err := m.controls[i][j].write(w, class, outcome); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *controlMetrics) write(w io.Writer, class routing.ControlClass, outcome routing.TransportOutcome) error {
	for _, measurement := range [...]struct {
		name  string
		value uint64
	}{
		{"gateway_control_observations_total", m.observations.Load()},
		{"gateway_control_observation_duration_ns_total", m.durationNS.Load()},
		{"gateway_observed_request_frame_bytes_total", m.requestFrameBytes.Load()},
		{"gateway_observed_response_frame_bytes_total", m.responseFrameBytes.Load()},
	} {
		if _, err := fmt.Fprintf(w, "%s{class=%q,transport=%q} %d\n", measurement.name, class, outcome, measurement.value); err != nil {
			return err
		}
	}
	return nil
}
