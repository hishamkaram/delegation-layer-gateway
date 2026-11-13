package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Real Unix tests exercise the unforgeable connection proof. Here a package-
// owned proof isolates request capacity from the separate 32-connection limit,
// which otherwise closes the 33rd socket before HTTP can reach the gate.
func TestMetadataCannotBypassSaturatedAdminRequestGate(t *testing.T) {
	authority := NewAuthorizer()
	gate := &requestGate{}
	for range 32 {
		if !gate.begin() {
			t.Fatal("admin gate refused capacity before declared bound")
		}
		t.Cleanup(gate.end)
	}
	called := false
	handler := &Handler{options: Options{Authority: authority, MetadataMetrics: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })}}
	ctx := context.WithValue(t.Context(), privateKey{}, privateProof{marker: authority.marker, gate: gate})
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/metadata/metrics", nil)
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, request)
	if writer.Code != http.StatusServiceUnavailable || called || writer.Body.String() != `{"code":"resource_limit","committed":false}` {
		t.Fatal("metadata bypassed shared private request capacity")
	}
}
