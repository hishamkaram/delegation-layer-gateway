package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type registrationStore struct {
	credential domain.Credential
	checkErr   error
	nextErr    error
}

func (s registrationStore) CheckCredential(context.Context, domain.CredentialRef, time.Time) (domain.Credential, error) {
	return s.credential, s.checkErr
}

func (s registrationStore) NextConnectionGeneration(context.Context, domain.CredentialRef, domain.BootEpoch, time.Time) (domain.ConnectionGeneration, error) {
	return domain.ConnectionGeneration{}, s.nextErr
}

func TestRegistrationDenialOnlyObservesSolePolicyError(t *testing.T) {
	f := newFixture(t, Settings{})
	forbidden := domain.Reject(domain.Forbidden)
	var nilPolicy *domain.Error
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"sole-forbidden", forbidden, true},
		{"joined-storage", errors.Join(forbidden, errors.New("storage-failed")), false},
		{"joined-single", errors.Join(forbidden), false},
		{"wrapped-forbidden", fmt.Errorf("check failed: %w", forbidden), false},
		{"storage", errors.New("storage-failed"), false},
		{"context", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
		{"expired", domain.Reject(domain.Expired), false},
		{"not-found", domain.Reject(domain.NotFound), false},
		{"typed-nil", nilPolicy, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observed := []domain.CredentialRef{}
			hub := registrationHub(t, f, registrationStore{checkErr: test.err}, func(ref domain.CredentialRef) { observed = append(observed, ref) })
			_, err := hub.register(t.Context(), registrationRequest(f))
			var failure *Error
			if !errors.As(err, &failure) || !errors.Is(failure.kind, ErrForbidden) {
				t.Fatal("registration changed its refusal classification")
			}
			if failure.cause != test.err { //nolint:errorlint // Exact cause identity proves the complete original chain was preserved.
				t.Fatal("registration changed the original denial chain")
			}
			if test.want {
				if len(observed) != 1 || observed[0] != f.store.value.Ref {
					t.Fatal("sole verified registration denial not observed exactly once")
				}
			} else if len(observed) != 0 {
				t.Fatal("non-policy failure became credential denial evidence")
			}
		})
	}
}

func registrationHub(t *testing.T, f *fixture, store CredentialStore, observe func(domain.CredentialRef)) *Hub {
	t.Helper()
	hub, err := NewHub(t.Context(), Config{GatewayID: "gateway-one", BootEpoch: "boot-one", CredentialDenied: observe}, store, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := hub.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return hub
}

func registrationRequest(f *fixture) *http.Request {
	r := httptest.NewRequest("GET", "https://gateway.example/device", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.certificate}, VerifiedChains: [][]*x509.Certificate{{f.certificate}}}
	return r
}

func TestCredentialDenialExcludesMalformedPeersAndLaterGenerationFailures(t *testing.T) {
	f := newFixture(t, Settings{})
	observed := 0
	hub := registrationHub(t, f, registrationStore{credential: f.store.value, nextErr: domain.Reject(domain.Forbidden)}, func(domain.CredentialRef) { observed++ })
	if _, err := hub.register(t.Context(), httptest.NewRequest("GET", "https://gateway.example/device", nil)); err == nil {
		t.Fatal("unverified peer accepted")
	}
	// CheckCredential succeeds; a subsequent generation rejection is not a new
	// sole credential-check denial, even though both HTTP outcomes are 403.
	out := httptest.NewRecorder()
	hub.ServeHTTP(out, registrationRequest(f))
	if out.Code != http.StatusForbidden || observed != 0 {
		t.Fatal("later generation failure was observed as credential denial")
	}
}

func TestCredentialDenialExcludesExistingSessionChecks(t *testing.T) {
	f := newFixture(t, Settings{})
	observed := 0
	f.hub.config.CredentialDenied = func(domain.CredentialRef) { observed++ }
	client := f.dial(t)
	if err := f.hub.WaitReady(t.Context(), "device-one"); err != nil {
		t.Fatal(err)
	}
	// Duplicate registration has a valid credential but is rejected by h.add.
	if _, err := f.hub.register(t.Context(), registrationRequest(f)); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate registration did not preserve its refusal")
	}
	// Capture the currently live session before closing it, so this assertion
	// cannot disappear merely because the asynchronous session retired early.
	f.hub.mu.Lock()
	s := f.hub.sessions["device-one"]
	f.hub.mu.Unlock()
	if s == nil {
		t.Fatal("live session missing before revocation")
	}
	f.store.revoke()
	if err := s.check(t.Context()); !errors.Is(err, ErrForbidden) {
		t.Fatal("existing revoked session did not refuse")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if observed != 0 {
		t.Fatal("duplicate or existing-session denial became fresh registration evidence")
	}
}
