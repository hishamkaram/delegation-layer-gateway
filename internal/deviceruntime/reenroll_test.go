package deviceruntime

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
)

func TestReenrollExpiredRecordLostResponseAndSameRefRetry(t *testing.T) {
	a := newCA(t)
	var originalCSR []byte
	responder := &reenrollmentResponder{t: t}
	transportCA := newCA(t)
	server := newTLSServer(t, transportCA, responder)
	cfg := fixtureConfigWithDeviceCA(t, transportCA, &a, server.URL, "")
	store := openStore(t, cfg)
	roots, err := cfg.DeviceRoots()
	require(t, err)
	originalCSR, err = store.EnsureKey(rand.Reader)
	require(t, err)
	prior := domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}
	oldTime := a.now.Add(-31 * 24 * time.Hour)
	require(t, store.InstallEnrollment(a.sign(t.Context(), t, originalCSR, prior, oldTime), prior, roots, oldTime))
	if _, _, err = store.Certificate(roots, a.now); err == nil {
		t.Fatal("fixture prior credential was not expired")
	}
	oldPending, err := store.BeginRenewal(prior, rand.Reader)
	require(t, err)
	newer := prior
	newer.Generation = 2
	newDER := a.sign(t.Context(), t, originalCSR, newer, a.now.Add(-time.Hour))
	responder.originalCSR = originalCSR
	responder.output = enrollmentOutput(newDER)
	responder.output.Generation = 2
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err = Reenroll(t.Context(), cfg, store, token); !errors.Is(err, ErrEnrollment) {
		t.Fatal("lost replacement response not reported")
	}
	pending, err := store.PendingRenewal()
	require(t, err)
	if pending.ID != oldPending.ID {
		t.Fatal("lost response discarded unresolved renewal")
	}
	require(t, store.Close())
	reopened, err := deviceidentity.Open(cfg.IdentityDirectory())
	current := checked(t, reopened, err)
	t.Cleanup(func() { require(t, current.Close()) })
	require(t, Reenroll(t.Context(), cfg, current, token))
	_, ref, err := current.Certificate(roots, a.now)
	require(t, err)
	if ref != newer {
		t.Fatal("expired prior did not advance through explicit replacement")
	}
	if err = current.CompleteRenewal(oldPending.ID, a.sign(t.Context(), t, oldPending.CSRDER, prior, a.now), roots, a.now); !errors.Is(err, deviceidentity.ErrConflict) {
		t.Fatal("superseded renewal was fabricated as completed")
	}
	newPending, err := current.BeginRenewal(newer, rand.Reader)
	require(t, err)
	require(t, Reenroll(t.Context(), cfg, current, token)) // Captured prior now equals response; exact DER only.
	retained, err := current.PendingRenewal()
	require(t, err)
	if retained.ID != newPending.ID {
		t.Fatal("exact replacement retry discarded a newer pending renewal")
	}
	// A real same-ref renewal advances the local DER. The older enrollment receipt
	// must not roll it back, even though key/ref/trust are all otherwise valid.
	renewedDER := a.sign(t.Context(), t, newPending.CSRDER, newer, a.now)
	require(t, current.CompleteRenewal(newPending.ID, renewedDER, roots, a.now))
	if err = Reenroll(t.Context(), cfg, current, token); !errors.Is(err, ErrEnrollment) {
		t.Fatal("same-ref different enrollment DER overwrote renewed certificate")
	}
	certificate, actual, err := current.Certificate(roots, a.now)
	require(t, err)
	if actual != newer || !bytes.Equal(certificate.Certificate[0], renewedDER) {
		t.Fatal("replacement retry regressed current renewal")
	}
}

func TestOrdinaryEnrollNeverImplicitlyReplacesAndReenrollCASRejectsRace(t *testing.T) {
	a := newCA(t)
	var output enrollment.EnrollmentResponse
	var beforeResponse func()
	transportCA := newCA(t)
	server := newTLSServer(t, transportCA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enrollmentInput(t, r)
		if beforeResponse != nil {
			beforeResponse()
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(output); err != nil {
			t.Error(err)
		}
	}))
	cfg := fixtureConfigWithDeviceCA(t, transportCA, &a, server.URL, "")
	store := openStore(t, cfg)
	csr, err := store.EnsureKey(rand.Reader)
	require(t, err)
	roots, err := cfg.DeviceRoots()
	require(t, err)
	prior := domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}
	require(t, store.InstallEnrollment(a.sign(t.Context(), t, csr, prior, a.now), prior, roots, a.now))
	next := prior
	next.Generation = 2
	der := a.sign(t.Context(), t, csr, next, a.now)
	output = enrollmentOutput(der)
	output.Generation = 2
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err = Enroll(t.Context(), cfg, store, token); !errors.Is(err, ErrEnrollment) {
		t.Fatal("ordinary enrollment silently replaced existing identity")
	}
	latest := next
	latest.Generation = 3
	latestDER := a.sign(t.Context(), t, csr, latest, a.now)
	beforeResponse = func() {
		if replaceErr := store.ReplaceEnrollment(latestDER, prior, latest, roots, a.now); replaceErr != nil {
			t.Error(replaceErr)
		}
	}
	if err = Reenroll(t.Context(), cfg, store, token); !errors.Is(err, ErrEnrollment) {
		t.Fatal("stale captured prior replaced a concurrent identity")
	}
	certificate, ref, err := store.Certificate(roots, a.now)
	require(t, err)
	if ref != latest || !bytes.Equal(certificate.Certificate[0], latestDER) {
		t.Fatal("CAS race changed newer credential")
	}
}

func TestReenrollSameRefExpiredDERCannotClaimSuccess(t *testing.T) {
	a := newCA(t)
	var output enrollment.EnrollmentResponse
	transportCA := newCA(t)
	server := newTLSServer(t, transportCA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enrollmentInput(t, r)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(output); err != nil {
			t.Error(err)
		}
	}))
	cfg := fixtureConfigWithDeviceCA(t, transportCA, &a, server.URL, "")
	store := openStore(t, cfg)
	csr, err := store.EnsureKey(rand.Reader)
	require(t, err)
	roots, err := cfg.DeviceRoots()
	require(t, err)
	prior := domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}
	old := a.now.Add(-31 * 24 * time.Hour)
	der := a.sign(t.Context(), t, csr, prior, old)
	require(t, store.InstallEnrollment(der, prior, roots, old))
	output = enrollmentOutput(der)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err = Reenroll(t.Context(), cfg, store, token); !errors.Is(err, ErrEnrollment) {
		t.Fatal("same-ref expired certificate falsely reported valid replacement")
	}
	actual, err := store.StoredCredentialRef()
	require(t, err)
	if actual != prior {
		t.Fatal("invalid retry mutated expired identity")
	}
}

type reenrollmentResponder struct {
	t           *testing.T
	originalCSR []byte
	output      enrollment.EnrollmentResponse
	calls       int
}

func (responder *reenrollmentResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := responder.t
	input := enrollmentInput(t, r)
	csr, err := base64.StdEncoding.Strict().DecodeString(input.CSRDERBase64)
	require(t, err)
	responder.calls++
	if responder.calls <= 3 && !bytes.Equal(csr, responder.originalCSR) {
		t.Error("replacement or retry changed persisted CSR")
	}
	if responder.calls == 1 {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("HTTP1 hijacker unavailable")
			return
		}
		connection, _, hijackErr := hijacker.Hijack()
		if hijackErr != nil {
			t.Error(hijackErr)
			return
		}
		if err = connection.Close(); err != nil {
			t.Error(err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(responder.output); err != nil {
		t.Error(err)
	}
}
