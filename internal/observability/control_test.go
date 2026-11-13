package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func preparedAuditFixture() Event {
	return Event{Code: OperationPrepared, Principal: "principal-one", Device: "device-one", Project: "project-one", Operation: "operation-one", Control: routing.ControlMetadata{Class: routing.PrepareClass, Actor: routing.PrincipalActor, Authorization: routing.Allowed, Recheck: routing.NotEvaluated, Transport: routing.NotAttempted, TransferSnapshot: routing.TransferSnapshot{WriteState: routing.WriteNotStarted}}}
}

func completedAuditFixture() Event {
	return Event{Code: ControlCompleted, Principal: "principal-one", Device: "device-one", Project: "project-one", Operation: "operation-one", Control: routing.ControlMetadata{Class: routing.ControlClass(protocol.Admit), Actor: routing.PrincipalActor, Authorization: routing.Allowed, Recheck: routing.Allowed, Transport: routing.ReplyReceived, DurationNS: 37, Connection: domain.ConnectionGeneration{BootEpoch: "boot-one", Counter: 2}, Request: "g:3", TransferSnapshot: routing.TransferSnapshot{WriteState: routing.WriteCompleted, EncodedRequestFrameBytes: 101, EncodedResponseFrameBytes: 202, ResponseKnown: true}}}
}

func readAuditRecords(t *testing.T, directory string) []record {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var records []record
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "audit-") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(data, []byte("private-canary")) {
			t.Fatal("audit retained rejected metadata")
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var value record
			if decodeErr := json.Unmarshal(line, &value); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			records = append(records, value)
		}
	}
	return records
}

func TestControlAuditPersistsCorrelationAndMeasuresFinalObservationOnce(t *testing.T) {
	directory := privateDirectory(t)
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
	prepared := preparedAuditFixture()
	completed := completedAuditFixture()
	sent := completed
	sent.Code = ControlSent
	sent.Control.Transport = routing.WrittenNoReply
	sent.Control.ResponseKnown = false
	sent.Control.EncodedResponseFrameBytes = 0
	recorder.Record(prepared)
	recorder.Record(sent)
	recorder.Record(completed)
	rows := readAuditRecords(t, directory)
	if len(rows) != 3 || rows[0].Event != prepared || rows[1].Event != sent || rows[2].Event != completed {
		t.Fatal("persisted control metadata lost immutable identity or observations")
	}
	out := httptest.NewRecorder()
	metrics.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		`gateway_control_observations_total{class="admit",transport="reply_received"} 1` + "\n",
		`gateway_control_observation_duration_ns_total{class="admit",transport="reply_received"} 37` + "\n",
		`gateway_observed_request_frame_bytes_total{class="admit",transport="reply_received"} 101` + "\n",
		`gateway_observed_response_frame_bytes_total{class="admit",transport="reply_received"} 202` + "\n",
		`gateway_control_observations_total{class="admit",transport="written_no_reply"} 0` + "\n",
	} {
		if !strings.Contains(out.Body.String(), expected) {
			t.Fatalf("fixed observation measurement missing: %s", expected)
		}
	}
	for _, forbidden := range []string{"principal-one", "device-one", "project-one", "operation-one", "boot-one", "g:3"} {
		if strings.Contains(out.Body.String(), forbidden) {
			t.Fatal("audit identity became a metric label")
		}
	}
	if !recorder.Health().AuditHealthy || recorder.Health().MetricFailures != 0 {
		t.Fatal("valid control metadata failed a sink")
	}
}

func invalidControlFixtures() map[string]Event {
	valid := completedAuditFixture()
	mutate := func(change func(*Event)) Event { value := valid; change(&value); return value }
	return map[string]Event{
		"unclassified-recovery":         {Code: RecoveryBlocked, Principal: "principal-one"},
		"missing-control":               mutate(func(e *Event) { e.Control = routing.ControlMetadata{} }),
		"unsafe-project":                mutate(func(e *Event) { e.Project = "/private-canary/path" }),
		"partial-destination":           mutate(func(e *Event) { e.Project = "" }),
		"unknown-class":                 mutate(func(e *Event) { e.Control.Class = "private-canary" }),
		"unknown-actor":                 mutate(func(e *Event) { e.Control.Actor = "private-canary" }),
		"unverified-principal":          mutate(func(e *Event) { e.Principal = "" }),
		"admin-with-principal":          mutate(func(e *Event) { e.Control.Actor = routing.LocalAdminActor }),
		"unknown-decision":              mutate(func(e *Event) { e.Control.Authorization = "private-canary" }),
		"negative-duration":             mutate(func(e *Event) { e.Control.DurationNS = -1 }),
		"response-without-proof":        mutate(func(e *Event) { e.Control.ResponseKnown = false }),
		"unbounded-frame":               mutate(func(e *Event) { e.Control.EncodedResponseFrameBytes = protocol.MaxFrameBytes + 1 }),
		"cross-event-metadata":          mutate(func(e *Event) { e.Code = AuthenticationDenied }),
		"connection-mixed-with-control": mutate(func(e *Event) { e.Connection = e.Control.Connection }),
		"prepare-with-wire-transfer":    mutate(func(e *Event) { e.Code = OperationPrepared; e.Control.Class = routing.PrepareClass }),
	}
}

func TestInvalidControlMetadataReachesNeitherSink(t *testing.T) {
	directory := privateDirectory(t)
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
	invalid := invalidControlFixtures()
	for name, event := range invalid {
		t.Run(name, func(t *testing.T) {
			if recordErr := audit.Record(event); !errors.Is(recordErr, ErrUnavailable) {
				t.Fatal("invalid metadata was accepted by audit")
			}
			recorder.Record(event)
		})
	}
	if rows := readAuditRecords(t, directory); len(rows) != 0 {
		t.Fatal("rejected metadata changed durable audit")
	}
	health := recorder.Health()
	if health.AuditHealthy || health.AuditFailures != uint64(len(invalid)) || health.MetricFailures != uint64(len(invalid)) {
		t.Fatal("invalid metadata did not remain visible in protected failure counts")
	}
	for i := range metrics.events {
		if metrics.events[i].Load() != 0 {
			t.Fatal("invalid metadata incremented an event counter before validation")
		}
	}
}

func TestConnectionMetadataKeepsCredentialAndGenerationQualified(t *testing.T) {
	credential := CredentialIdentity{DeviceID: "device-one", Epoch: "epoch-one", Generation: 7}
	connection := domain.ConnectionGeneration{BootEpoch: "boot-one", Counter: 2}
	connected := Event{Code: DeviceConnected, Device: "device-one", Credential: credential, Connection: connection, ConnectionDurationNS: 3}
	closed := connected
	closed.Code, closed.ConnectionDurationNS = DeviceDisconnected, 19
	for _, event := range []Event{connected, closed, {Code: DeviceConnectionFailed}, {Code: AuthorizationDenied}, {Code: ResourceDenied, Principal: "principal-one"}} {
		if !event.validate() {
			t.Fatal("valid connection or explicitly unavailable early metadata rejected")
		}
	}
	for _, event := range []Event{
		{Code: DeviceConnected, Device: "device-one", Credential: credential},
		{Code: DeviceDisconnected, Device: "device-one", Credential: credential, ConnectionDurationNS: 19},
		{Code: DeviceConnectionFailed, Device: "device-one"},
		{Code: DeviceConnectionFailed, Connection: connection},
		{Code: DeviceConnected, Device: "device-two", Credential: credential, Connection: connection},
		{Code: DeviceDisconnected, Device: "device-one", Credential: credential, Connection: connection, ConnectionDurationNS: -1},
	} {
		if event.validate() {
			t.Fatal("unqualified connection metadata accepted")
		}
	}
}

func TestFailedPreparationIsAnUnsentObservationWithoutCommittedOperation(t *testing.T) {
	failed := preparedAuditFixture()
	failed.Code, failed.Operation = ControlUnknown, ""
	if !failed.validate() {
		t.Fatal("failed local preparation requires fabricated committed operation")
	}
	failed.Control.Request = "g:1"
	if failed.validate() {
		t.Fatal("failed local preparation acquired a transport request")
	}
}

func TestRuntimeMetricsSnapshotIsExplicitAndNotRetained(t *testing.T) {
	var metrics Metrics
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	withSnapshot := httptest.NewRecorder()
	metrics.WriteSnapshot(withSnapshot, request, RuntimeSnapshot{ActiveDevices: 2, AuthorizedDevices: 3, WSSConnections: 5, RegisteredDevices: 7})
	for _, expected := range []string{"gateway_active_devices 2\n", "gateway_authorized_devices 3\n", "gateway_wss_connections 5\n", "gateway_registered_devices 7\n"} {
		if !strings.Contains(withSnapshot.Body.String(), expected) {
			t.Fatal("current-owner snapshot count missing")
		}
	}
	withoutSnapshot := httptest.NewRecorder()
	metrics.ServeHTTP(withoutSnapshot, request)
	if strings.Contains(withoutSnapshot.Body.String(), "gateway_active_devices") || strings.Contains(withoutSnapshot.Body.String(), "gateway_wss_connections") || strings.Contains(withoutSnapshot.Body.String(), "gateway_authorized_devices") || strings.Contains(withoutSnapshot.Body.String(), "gateway_registered_devices") {
		t.Fatal("metrics retained prior runtime counts or fabricated unknown zero counts")
	}
}
