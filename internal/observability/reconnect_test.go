package observability

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func reconnectEvent(code Code, boot domain.BootEpoch, counter uint64) Event {
	return Event{Code: code, Device: "device-one", Credential: CredentialIdentity{DeviceID: "device-one", Epoch: "epoch-one", Generation: 7}, Connection: domain.ConnectionGeneration{BootEpoch: boot, Counter: counter}}
}

func newReconnectRecorder(t *testing.T) (*Recorder, *Metrics, string) {
	t.Helper()
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
	metrics := &Metrics{}
	recorder, err := NewRecorder(audit, metrics)
	if err != nil {
		t.Fatal(err)
	}
	return recorder, metrics, directory
}

func assertReconnectMetric(t *testing.T, metrics *Metrics, count uint64) {
	t.Helper()
	writer := httptest.NewRecorder()
	metrics.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	data := writer.Body.String()
	if !strings.Contains(data, fmt.Sprintf("gateway_device_reconnections_total %d\n", count)) || strings.Count(data, "gateway_device_reconnections_total") != 1 {
		t.Fatalf("missing or incorrect aggregate reconnection counter: want %d", count)
	}
	for _, identity := range []string{"device-one", "epoch-one", "boot-one", "boot-two"} {
		if strings.Contains(data, identity) {
			t.Fatal("connection identity became a reconnection metric label")
		}
	}
}

func TestDeviceReconnectionsCountOnlyEstablishedRepeatGenerations(t *testing.T) {
	for _, test := range []struct {
		name   string
		events []Event
		want   uint64
	}{
		{name: "first-generation", events: []Event{reconnectEvent(DeviceConnected, "boot-one", 1)}, want: 0},
		// Fresh Metrics still recognize a repeat generation without prior history.
		{name: "repeat-without-observed-first", events: []Event{reconnectEvent(DeviceConnected, "boot-two", 2)}, want: 1},
		{name: "failed-first-then-established-repeat", events: []Event{reconnectEvent(DeviceConnectionFailed, "boot-one", 1), reconnectEvent(DeviceConnected, "boot-one", 2)}, want: 1},
		{name: "durable-counter-across-boots", events: []Event{reconnectEvent(DeviceConnected, "boot-one", 2), reconnectEvent(DeviceConnected, "boot-two", 3)}, want: 2},
		{name: "failed-and-closed", events: []Event{reconnectEvent(DeviceConnectionFailed, "boot-one", 2), reconnectEvent(DeviceDisconnected, "boot-one", 3)}, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder, metrics, directory := newReconnectRecorder(t)
			for _, event := range test.events {
				recorder.Record(event)
			}
			rows := readAuditRecords(t, directory)
			if len(rows) != len(test.events) {
				t.Fatal("valid connection metadata did not reach the existing audit sink")
			}
			for i, event := range test.events {
				if rows[i].Event != event {
					t.Fatal("reconnection accounting changed persisted connection metadata")
				}
			}
			assertReconnectMetric(t, metrics, test.want)
			if health := recorder.Health(); !health.AuditHealthy || health.MetricFailures != 0 {
				t.Fatal("valid reconnection metadata failed a sink")
			}
		})
	}
}

func TestInvalidReconnectionMetadataReachesNeitherSink(t *testing.T) {
	recorder, metrics, directory := newReconnectRecorder(t)
	invalid := reconnectEvent(DeviceConnected, "boot-one", 2)
	invalid.Credential.DeviceID = "another-device"
	recorder.Record(invalid)
	if rows := readAuditRecords(t, directory); len(rows) != 0 {
		t.Fatal("invalid reconnection metadata reached durable audit")
	}
	for i := range metrics.events {
		if metrics.events[i].Load() != 0 {
			t.Fatal("invalid reconnection metadata incremented an event counter")
		}
	}
	assertReconnectMetric(t, metrics, 0)
	if health := recorder.Health(); health.AuditHealthy || health.AuditFailures != 1 || health.MetricFailures != 1 {
		t.Fatal("rejected reconnection metadata lost its protected failure counts")
	}
}
