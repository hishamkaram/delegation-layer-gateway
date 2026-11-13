package enrollment

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type unusedProxyRedeemer struct{}

func (unusedProxyRedeemer) Redeem(context.Context, string, []byte) (domain.CertificateReceipt, error) {
	return domain.CertificateReceipt{}, domain.ErrInvalid
}

func TestHTTPSLegacyEnrollmentProxySeparatesClientBuckets(t *testing.T) {
	handler, err := HTTPHandler(unusedProxyRedeemer{}, time.Now, true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	for attempt := range 6 {
		status := proxyEnrollmentStatus(t, server, "192.0.2.10")
		want := http.StatusBadRequest
		if attempt == 5 {
			want = http.StatusTooManyRequests
		}
		if status != want {
			t.Fatalf("enrollment attempt %d status=%d, want %d", attempt, status, want)
		}
	}
	if status := proxyEnrollmentStatus(t, server, "198.51.100.20"); status != http.StatusBadRequest {
		t.Fatal("one proxy client exhausted another client's enrollment bucket")
	}
}

func proxyEnrollmentStatus(t *testing.T, server *httptest.Server, clientIP string) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Real-IP", clientIP)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, MaxEnrollmentBodyBytes)); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}
