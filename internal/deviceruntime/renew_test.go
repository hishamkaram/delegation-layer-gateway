package deviceruntime

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestRenewalIntentAndStrictResponseSurviveIdentityRestart(t *testing.T) {
	a := newCA(t)
	cfg := fixtureConfig(t, a, "https://gateway.example", "")
	store := openStore(t, cfg)
	roots, err := cfg.Roots()
	require(t, err)
	csr, err := store.EnsureKey(rand.Reader)
	require(t, err)
	ref := domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}
	require(t, store.InstallEnrollment(a.sign(t.Context(), t, csr, ref, a.now.Add(-21*24*time.Hour)), ref, roots, a.now))
	original, _, err := store.Certificate(roots, a.now)
	require(t, err)
	delay, err := nextRenewal(store, original.Leaf, a.now)
	require(t, err)
	if delay != 0 {
		t.Fatal("renewal after day20 was not due")
	}
	intent, err := store.BeginRenewal(ref, rand.Reader)
	require(t, err)
	require(t, store.Close())
	reopened, err := deviceidentity.Open(cfg.IdentityDirectory())
	restored := checked(t, reopened, err)
	t.Cleanup(func() { require(t, restored.Close()) })
	pending, err := restored.PendingRenewal()
	require(t, err)
	if pending.ID != intent.ID || string(pending.CSRDER) != string(intent.CSRDER) {
		t.Fatal("lost ACK/restart changed renewal ID or CSR")
	}
	issued := a.sign(t.Context(), t, pending.CSRDER, ref, a.now)
	response := protocol.RenewalResult{DeviceID: "device", Epoch: "epoch", Generation: 1, RenewalID: pending.ID, CertificateDERBase64: base64.StdEncoding.EncodeToString(issued)}
	rejectRenewalResponses(t, a, restored, pending, response)
	encoded, err := json.Marshal(response)
	require(t, err)
	require(t, installRenewal(encoded, pending, restored, roots, a.now))
	require(t, installRenewal(encoded, pending, restored, roots, a.now)) // Lost local completion ACK is idempotent.
	if _, err = restored.PendingRenewal(); !errors.Is(err, deviceidentity.ErrAbsent) {
		t.Fatal("completed renewal still pending")
	}
	certificate, actualRef, err := restored.Certificate(roots, a.now)
	require(t, err)
	if actualRef != ref || string(certificate.Certificate[0]) != string(issued) {
		t.Fatal("renewal changed identity or installed another DER")
	}
	delay, err = nextRenewal(restored, certificate.Leaf, a.now)
	require(t, err)
	if delay != 20*24*time.Hour {
		t.Fatalf("renewal schedule guessed another leadtime: %v", delay)
	}
}

func rejectRenewalResponses(t *testing.T, a testCA, store *deviceidentity.Store, intent deviceidentity.RenewalIntent, response protocol.RenewalResult) {
	t.Helper()
	roots := fixtureRoots(a)
	for _, variant := range []string{"id", "device", "generation", "epoch", "der", "unknown"} {
		t.Run(variant, func(t *testing.T) {
			wrong := response
			switch variant {
			case "id":
				wrong.RenewalID = "00000000000000000000000000000000"
			case "device":
				wrong.DeviceID = "other"
			case "generation":
				wrong.Generation++
			case "epoch":
				wrong.Epoch = "other"
			case "der":
				wrong.CertificateDERBase64 = base64.StdEncoding.EncodeToString([]byte("private-canary"))
			}
			encoded, err := json.Marshal(wrong)
			require(t, err)
			if variant == "unknown" {
				encoded = append(encoded[:len(encoded)-1], []byte(`,"untrusted":true}`)...)
			}
			if err = installRenewal(encoded, intent, store, roots, a.now); !errors.Is(err, ErrRenewal) {
				t.Fatal("unbound renewal response accepted")
			}
			pending, err := store.PendingRenewal()
			require(t, err)
			if pending.ID != intent.ID {
				t.Fatal("rejected response erased durable renewal intent")
			}
		})
	}
}

func fixtureRoots(a testCA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.certificate)
	return pool
}
