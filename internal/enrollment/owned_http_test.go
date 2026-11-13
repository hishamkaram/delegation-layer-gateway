package enrollment

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func TestHTTPSRequiredOwnershipRejectsLegacyAndAcceptsOwnedTokenIncludingReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store, err := registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.sqlite"), registry.CreateOptions{Admin: testAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	legacyToken := registerTestDevice(t, store, now)
	service, err := New(store, certificateAuthority(t, now), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := HTTPHandler(service, func() time.Time { return now }, false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	request := EnrollmentRequest{Token: legacyToken, CSRDERBase64: base64.StdEncoding.EncodeToString(requestCSR(t)), RequireOwned: true}
	assertOwnedRedemptionStatus(t, server, request, http.StatusForbidden)
	request.RequireOwned = false
	assertOwnedRedemptionStatus(t, server, request, http.StatusOK)
	request.RequireOwned = true
	assertOwnedRedemptionStatus(t, server, request, http.StatusForbidden)
	principal, err := store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.PutOwnerPolicy(t.Context(), principal.ID, domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 2}); err != nil {
		t.Fatal(err)
	}
	token, hash, err := NewToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.CreateOwnedEnrollment(t.Context(), principal.ID, "owned", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	request = EnrollmentRequest{Token: token, CSRDERBase64: base64.StdEncoding.EncodeToString(requestCSR(t)), RequireOwned: true}
	first := assertOwnedRedemptionStatus(t, server, request, http.StatusOK)
	second := assertOwnedRedemptionStatus(t, server, request, http.StatusOK)
	if first != second || first.DeviceID != string(device.ID) || first.CertificateDERBase64 == "" {
		t.Fatal("owned-required redemption did not preserve the exact receipt")
	}
}

func assertOwnedRedemptionStatus(t *testing.T, server *httptest.Server, request EnrollmentRequest, want int) EnrollmentResponse {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	status, data := enrollmentPOST(t, server, body)
	if status != want {
		t.Fatalf("redemption status=%d, want%d", status, want)
	}
	var response EnrollmentResponse
	if status == http.StatusOK {
		if err = json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
	}
	return response
}
