package deviceclient

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUnattendedAndCredentialReuseDoNotDiscoverUnavailableIssuer(t *testing.T) {
	t.Run("unattended", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.issuerUnavailable = true
		f.options.PresentChallenge = nil
		token, err := json.Marshal(enrollmentToken{Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), DeviceID: "device-one", ExpiresAt: time.Now().Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		f.options.EnrollmentTokenReader = strings.NewReader(string(token))
		status, err := Connect(t.Context(), f.options)
		if err != nil || status.CredentialState != "valid" {
			t.Fatal("unattended depended on issuer", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.issuerRequests != 0 {
			t.Fatal("unattended queried issuer")
		}
	})
	t.Run("existing credential", func(t *testing.T) {
		f := newGatewayFixture(t)
		first, err := Connect(t.Context(), f.options)
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.issuerUnavailable = true
		before := f.issuerRequests
		f.mu.Unlock()
		next, err := Connect(t.Context(), f.options)
		if err != nil || next.DeviceID != first.DeviceID {
			t.Fatal("existing identity depended on issuer", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.issuerRequests != before {
			t.Fatal("credential reuse queried issuer")
		}
	})
}
