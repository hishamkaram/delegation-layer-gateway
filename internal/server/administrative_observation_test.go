package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func TestAdministrativeRevocationRecordsCommittedRequestsOnly(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	_, _ = f.enrollDevice(t)
	var mutation adminapi.Mutation
	revoked := false
	f.adminCall(t, "/v1/devices/revocation", adminapi.DeviceRevocationInput{DeviceID: "device", Revoked: &revoked}, &mutation)
	if !mutation.Committed || len(administrativeRevocations(t, f)) != 0 {
		t.Fatal("non-revoking administrative request fabricated a revocation event")
	}
	revoked = true
	for range 2 {
		f.adminCall(t, "/v1/devices/revocation", adminapi.DeviceRevocationInput{DeviceID: "device", Revoked: &revoked}, &mutation)
		if !mutation.Committed {
			t.Fatal("explicit revocation or its idempotent replay failed")
		}
	}
	events := administrativeRevocations(t, f)
	want := observability.Event{Code: observability.CredentialRevoked, Device: "device"}
	if len(events) != 2 || events[0] != want || events[1] != want {
		t.Fatal("successful administrative requests lost exact bounded revocation metadata")
	}
	if health := f.runtime.Health(); !health.AuditHealthy || health.AuditFailures != 0 || health.MetricFailures != 0 {
		t.Fatal("valid administrative event failed its sinks")
	}
}

func administrativeRevocations(t *testing.T, f *fixture) []observability.Event {
	t.Helper()
	var events []observability.Event
	for _, event := range routingAuditRecords(t, f) {
		if event.Code == observability.CredentialRevoked {
			events = append(events, event)
		}
	}
	return events
}

func TestAdministrativeRevocationSurvivesAuditFailure(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	_, certificate := f.enrollDevice(t)
	require(t, f.runtime.audit.Close())
	revoked := true
	var mutation adminapi.Mutation
	f.adminCall(t, "/v1/devices/revocation", adminapi.DeviceRevocationInput{DeviceID: "device", Revoked: &revoked}, &mutation)
	if !mutation.Committed {
		t.Fatal("audit failure changed the committed registry mutation")
	}
	status, _ := f.request(t, f.deviceHTTP(t, &certificate), http.MethodGet, f.deviceURL(t), nil, "")
	if status != http.StatusForbidden {
		t.Fatal("failed audit sink undid actual certificate revocation")
	}
	if health := f.runtime.Health(); health.AuditHealthy || health.AuditFailures == 0 || health.MetricFailures != 0 {
		t.Fatal("audit failure was hidden or corrupted fixed metric recording")
	}
}

type administrativeFailureAuthority struct{ cause error }

func (a administrativeFailureAuthority) AuthorizeAdmin(context.Context) error { return a.cause }

func TestAdministrativeRevocationPreservesRegistryErrorGraph(t *testing.T) {
	directory := t.TempDir()
	require(t, os.Chmod(directory, 0o700))
	auditDirectory := filepath.Join(directory, "audit")
	require(t, os.Mkdir(auditDirectory, 0o700))
	audit, err := observability.Open(auditDirectory, time.Now)
	require(t, err)
	t.Cleanup(func() { require(t, audit.Close()) })
	var metrics observability.Metrics
	recorder, err := observability.NewRecorder(audit, &metrics)
	require(t, err)
	storage := errors.New("fixture storage unavailable")
	native := &os.PathError{Op: "open", Path: "/private-canary/administrative", Err: storage}
	cause := errors.Join(native, context.Canceled)
	store, err := registry.Create(t.Context(), filepath.Join(directory, "registry.sqlite"), registry.CreateOptions{Admin: administrativeFailureAuthority{cause: cause}})
	require(t, err)
	t.Cleanup(func() { require(t, store.Close()) })
	adapter := auditedAdministrativeStore{Store: store, recorder: recorder}
	actual := adapter.SetDeviceRevoked(t.Context(), domain.DeviceID("device"), true)
	var observed *os.PathError
	if !errors.Is(actual, native) || !errors.Is(actual, storage) || !errors.Is(actual, context.Canceled) || !errors.As(actual, &observed) {
		t.Fatal("administrative observation changed the original registry error graph")
	}
	entries, err := os.ReadDir(auditDirectory)
	require(t, err)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "audit-") {
			t.Fatal("failed registry mutation fabricated a committed audit event")
		}
	}
	if health := recorder.Health(); !health.AuditHealthy || health.AuditFailures != 0 || health.MetricFailures != 0 {
		t.Fatal("registry failure was incorrectly sent to metadata sinks")
	}
}
