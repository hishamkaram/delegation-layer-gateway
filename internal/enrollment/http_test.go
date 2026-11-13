package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func TestHTTPSRedemptionUsesRealDurableIssuanceAndDoesNotReflectSecrets(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store, err := registry.Create(context.Background(), filepath.Join(t.TempDir(), "registry.db"), registry.CreateOptions{Admin: testAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	token := registerTestDevice(t, store, now)
	service, err := New(store, certificateAuthority(t, now), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := HTTPHandler(service, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	encoded, err := json.Marshal(EnrollmentRequest{Token: token, CSRDERBase64: base64.StdEncoding.EncodeToString(requestCSR(t))})
	if err != nil {
		t.Fatal(err)
	}
	assertHTTPSReplay(t, server, encoded, token, store, now)
	for _, body := range [][]byte{[]byte(`{"token":"credential-canary","csr_der_base64":""}`), []byte(`{"token":"credential-canary","token":"duplicate"}`), bytes.Repeat([]byte("x"), MaxEnrollmentBodyBytes+1)} {
		status, data := enrollmentPOST(t, server, body)
		if status < 400 || bytes.Contains(data, []byte("credential-canary")) {
			t.Fatal("invalid request reflected credential")
		}
	}
	status, _ := enrollmentPOST(t, server, encoded)
	if status != http.StatusTooManyRequests {
		t.Fatal("forged forwarded IP bypassed socket bucket")
	}
}

func enrollmentPOST(t *testing.T, server *httptest.Server, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", strings.Repeat("9", len(body)%10+1))
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxEnrollmentBodyBytes))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func assertHTTPSReplay(t *testing.T, server *httptest.Server, encoded []byte, token string, store *registry.Store, now time.Time) {
	t.Helper()
	var first EnrollmentResponse
	for attempt := range 2 {
		status, data := enrollmentPOST(t, server, encoded)
		if status != http.StatusOK {
			t.Fatalf("redeem status %d: %s", status, data)
		}
		var response EnrollmentResponse
		if decodeErr := json.Unmarshal(data, &response); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if response.DeviceID != "device" || response.Epoch == "" || response.Generation != 1 || response.CertificateDERBase64 == "" || bytes.Contains(data, []byte(token)) {
			t.Fatal("invalid public credential receipt")
		}
		if _, credentialErr := store.CheckCredential(t.Context(), domain.CredentialRef{Device: domain.DeviceID(response.DeviceID), Epoch: domain.CredentialEpoch(response.Epoch), Generation: response.Generation}, now); credentialErr != nil {
			t.Fatal("public receipt does not match persisted credential authority")
		}
		if attempt == 0 {
			first = response
		} else if first != response {
			t.Fatal("duplicate HTTPS redemption issued a different identity")
		}
	}
}
