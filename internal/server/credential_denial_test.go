package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
)

func TestVerifiedRevokedRegistrationRecordsExactCredentialIdentity(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	_, certificate := f.enrollDevice(t)
	ref, err := devicecert.CredentialFromCertificate(certificate.Leaf)
	require(t, err)
	if got := credentialDenials(t, f); len(got) != 0 {
		t.Fatal("fixture contained denial evidence before revocation")
	}
	revoked := true
	f.adminCall(t, "/v1/devices/revocation", adminapi.DeviceRevocationInput{DeviceID: "device", Revoked: &revoked}, nil)
	status, _ := f.request(t, f.deviceHTTP(t, &certificate), http.MethodGet, f.deviceURL(t), nil, "")
	if status != http.StatusForbidden {
		t.Fatal("fresh revoked-certificate request was not refused")
	}
	events := credentialDenials(t, f)
	if len(events) != 1 || events[0] != (observability.Event{Code: observability.DeviceCredentialDenied, Device: ref.Device, Credential: observability.CredentialIdentity{DeviceID: ref.Device, Epoch: ref.Epoch, Generation: ref.Generation}}) {
		t.Fatalf("fresh registration denial identity mismatch: %+v", events)
	}
	if !f.runtime.Health().AuditHealthy {
		t.Fatal("credential evidence was recorded with an unhealthy sink")
	}
}

func TestCredentialAuditFailureDoesNotChangeRegistrationDenial(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	_, certificate := f.enrollDevice(t)
	revoked := true
	f.adminCall(t, "/v1/devices/revocation", adminapi.DeviceRevocationInput{DeviceID: "device", Revoked: &revoked}, nil)
	require(t, f.runtime.audit.Close())
	status, _ := f.request(t, f.deviceHTTP(t, &certificate), http.MethodGet, f.deviceURL(t), nil, "")
	if status != http.StatusForbidden {
		t.Fatal("audit failure changed the credential denial outcome")
	}
	health := f.runtime.Health()
	// Request start/end, exact credential denial and connection failure each
	// attempted the closed sink; all four failures remain sticky and explicit.
	if health.AuditHealthy || health.AuditFailures != 4 || health.MetricFailures != 0 {
		t.Fatalf("credential audit failure disappeared: %+v", health)
	}
}

func credentialDenials(t *testing.T, f *fixture) []observability.Event {
	t.Helper()
	entries, err := os.ReadDir(f.cfg.AuditDirectory)
	require(t, err)
	var events []observability.Event
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "audit-") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(f.cfg.AuditDirectory, entry.Name()))
		require(t, readErr)
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var event observability.Event
			require(t, json.Unmarshal([]byte(line), &event))
			if event.Code == observability.DeviceCredentialDenied {
				events = append(events, event)
			}
		}
	}
	return events
}
