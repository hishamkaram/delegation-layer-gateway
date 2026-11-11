package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestCredentialDenialAuditEncodingAndMetrics(t *testing.T) {
	directory := privateDirectory(t)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	audit, err := Open(directory, func() time.Time { return now })
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
	event := Event{Code: DeviceCredentialDenied, Device: "device-one", Credential: CredentialIdentity{DeviceID: "device-one", Epoch: "epoch-one", Generation: 7}}
	recorder.Record(event)
	recorder.Record(Event{Code: ShutdownStarted})
	data, err := os.ReadFile(filepath.Join(directory, "audit-20261111-00.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"at\":\"2026-11-11T12:00:00Z\",\"code\":\"device_credential_denied\",\"credential\":{\"device_id\":\"device-one\",\"epoch\":\"epoch-one\",\"generation\":7},\"device\":\"device-one\"}\n{\"at\":\"2026-11-11T12:00:00Z\",\"code\":\"shutdown_started\"}\n"
	if string(data) != want {
		t.Fatalf("audit encoding changed: %s", data)
	}
	if !recorder.Health().AuditHealthy || recorder.Health().MetricFailures != 0 {
		t.Fatal("valid metadata was not recorded")
	}
	out := httptest.NewRecorder()
	metrics.ServeHTTP(out, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(out.Body.String(), "gateway_events_total{event=\"device_credential_denied\"} 1\n") || strings.Contains(out.Body.String(), "device-one") || strings.Contains(out.Body.String(), "epoch-one") {
		t.Fatal("credential event was missing or became a metric label")
	}
}

func TestCredentialIdentityCannotAttachToOtherEvents(t *testing.T) {
	valid := Event{Code: DeviceCredentialDenied, Device: "device-one", Credential: CredentialIdentity{DeviceID: "device-one", Epoch: "epoch-one", Generation: 7}}
	cases := map[string]Event{
		"missing":         {Code: DeviceCredentialDenied, Device: "device-one"},
		"partial":         {Code: DeviceCredentialDenied, Device: "device-one", Credential: CredentialIdentity{DeviceID: "device-one", Generation: 7}},
		"zero-generation": {Code: DeviceCredentialDenied, Device: "device-one", Credential: CredentialIdentity{DeviceID: "device-one", Epoch: "epoch-one"}},
		"other-device":    {Code: DeviceCredentialDenied, Device: "device-two", Credential: valid.Credential},
		"unsafe-epoch":    {Code: DeviceCredentialDenied, Device: "device-one", Credential: CredentialIdentity{DeviceID: "device-one", Epoch: "private/path", Generation: 7}},
		"principal":       {Code: DeviceCredentialDenied, Device: "device-one", Principal: "principal-one", Credential: valid.Credential},
		"operation":       {Code: DeviceCredentialDenied, Device: "device-one", Operation: "operation-one", Credential: valid.Credential},
	}
	for _, code := range metricCodes() {
		if code != DeviceCredentialDenied {
			cases[string(code)] = Event{Code: code, Credential: valid.Credential}
		}
	}
	audit, err := Open(privateDirectory(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := audit.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	for name, event := range cases {
		t.Run(name, func(t *testing.T) {
			if recordErr := audit.Record(event); !errors.Is(recordErr, ErrUnavailable) {
				t.Fatalf("invalid credential metadata accepted: %v", recordErr)
			}
		})
	}
}

func TestAuditDTOLeavesDomainCredentialEncodingUnchanged(t *testing.T) {
	// This literal is the existing registry JSON shape, independent of the audit
	// DTO. Changing shared domain tags would make strict stored rows unreadable.
	stored := []byte(`{"Ref":{"Device":"device-one","Epoch":"epoch-one","Generation":7},"Mode":"regular","PublicKeyHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"NotBefore":"2026-11-11T00:00:00Z","NotAfter":"2026-11-12T00:00:00Z"}`)
	var credential domain.Credential
	decoder := json.NewDecoder(bytes.NewReader(stored))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		t.Fatal(err)
	}
	if credential.Ref != (domain.CredentialRef{Device: "device-one", Epoch: "epoch-one", Generation: 7}) {
		t.Fatal("existing credential reference changed")
	}
	encoded, err := json.Marshal(credential.Ref)
	if err != nil || string(encoded) != `{"Device":"device-one","Epoch":"epoch-one","Generation":7}` {
		t.Fatalf("registry reference encoding changed: %s %v", encoded, err)
	}
}
