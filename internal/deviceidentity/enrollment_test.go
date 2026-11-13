package deviceidentity

import (
	"bytes"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestEnrollmentIntentDurableConflictAndVerifiedCompletion(t *testing.T) {
	a := newAuthority(t)
	path := filepath.Join(t.TempDir(), "identity")
	first := openOwned(t, path)
	csr, err := first.EnsureKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := EnrollmentPlan{GatewayID: "gateway-one", Name: "Mac"}
	intent, err := first.BeginEnrollment(plan, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if intent.RequestID == "" || !bytes.Equal(intent.CSRDER, csr) {
		t.Fatal("request/CSR not persisted")
	}
	intent.CSRDER[0] ^= 1
	restarted := reopenOwned(t, first, path)
	retry, err := restarted.BeginEnrollment(plan, rand.Reader)
	if err != nil || !bytes.Equal(retry.CSRDER, csr) {
		t.Fatal("restart changed immutable intent", err)
	}
	changed := plan
	changed.Name = "other"
	if _, err = restarted.BeginEnrollment(changed, rand.Reader); !errors.Is(err, ErrConflict) {
		t.Fatal("changed request adopted", err)
	}
	issued := a.sign(t, csr, 2, a.ref)
	foreign := newAuthority(t)
	if err = restarted.CompleteEnrollment(retry.RequestID, "principal-one", issued, a.ref, foreign.roots, a.now); !errors.Is(err, ErrInvalid) {
		t.Fatal("foreign trust accepted", err)
	}
	if err = restarted.CompleteEnrollment("wrong", "principal-one", issued, a.ref, a.roots, a.now); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign request accepted", err)
	}
	if err = restarted.CompleteEnrollment(retry.RequestID, "principal-one", issued, a.ref, a.roots, a.now); err != nil {
		t.Fatal(err)
	}
	assertCompletedEnrollment(t, restarted, path, retry, issued, a)
}

func assertCompletedEnrollment(t *testing.T, restarted *Store, path string, retry EnrollmentIntent, issued []byte, a authority) {
	t.Helper()
	done := reopenOwned(t, restarted, path)
	stored, err := done.EnrollmentIntent()
	if err != nil || !stored.Completed || stored.OwnerPrincipal != "principal-one" || stored.RequestID != retry.RequestID {
		t.Fatal("completion owner/receipt not durable", err)
	}
	wrongRef := a.ref
	wrongRef.Generation++
	if err = done.CompleteEnrollment(retry.RequestID, "principal-one", issued, wrongRef, a.roots, a.now); !errors.Is(err, ErrConflict) {
		t.Fatal("receipt accepted mismatched response credential", err)
	}
	if err = done.CompleteEnrollment(retry.RequestID, "principal-two", issued, a.ref, a.roots, a.now); !errors.Is(err, ErrConflict) {
		t.Fatal("owner changed on completion retry", err)
	}
	if err = done.CompleteEnrollment(retry.RequestID, "principal-one", issued, a.ref, a.roots, a.now); err != nil {
		t.Fatal("same receipt not idempotent", err)
	}
}

func TestTokenEnrollmentKeepsOwnerUnknownAndReplacementCAS(t *testing.T) {
	a := newAuthority(t)
	path := filepath.Join(t.TempDir(), "identity")
	store := openOwned(t, path)
	csr, err := store.EnsureKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := EnrollmentPlan{GatewayID: "gateway-one", Name: "Mac", TokenDevice: a.ref.Device, TokenSHA256: domain.Hash([]byte("opaque-token"))}
	intent, err := store.BeginEnrollment(plan, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := a.sign(t, csr, 2, a.ref)
	if err = store.CompleteEnrollment(intent.RequestID, "untrusted-owner", cert, a.ref, a.roots, a.now); !errors.Is(err, ErrConflict) {
		t.Fatal("token forged owner accepted", err)
	}
	if err = store.CompleteEnrollment(intent.RequestID, "", cert, a.ref, a.roots, a.now); err != nil {
		t.Fatal(err)
	}
	plan.Prior = a.ref
	replacement, err := store.BeginEnrollment(plan, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.RequestID == intent.RequestID {
		t.Fatal("replacement reused original operation")
	}
	next := a.ref
	next.Generation++
	issued := a.sign(t, replacement.CSRDER, 3, next)
	if err = store.CompleteEnrollment(replacement.RequestID, "", cert, a.ref, a.roots, a.now); !errors.Is(err, ErrConflict) {
		t.Fatal("nonadvancing replacement accepted", err)
	}
	if err = store.CompleteEnrollment(replacement.RequestID, "", issued, next, a.roots, a.now); err != nil {
		t.Fatal(err)
	}
	final := reopenOwned(t, store, path)
	ref, _, err := final.CredentialMetadata()
	if err != nil || ref != next {
		t.Fatal("replacement not durable", err)
	}
}

func TestEnrollmentRequestAndOwnerSurviveCertificateRenewal(t *testing.T) {
	a := newAuthority(t)
	path := filepath.Join(t.TempDir(), "identity")
	store := openOwned(t, path)
	if _, err := store.EnsureKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	intent, err := store.BeginEnrollment(EnrollmentPlan{GatewayID: "gateway-one", Name: "Mac"}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(intent.CSRDER)
	if err = store.CompleteEnrollment(intent.RequestID, "verified-owner", a.sign(t, original, 2, a.ref), a.ref, a.roots, a.now); err != nil {
		t.Fatal(err)
	}
	renewal, err := store.BeginRenewal(a.ref, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.CompleteRenewal(renewal.ID, a.sign(t, renewal.CSRDER, 3, a.ref), a.roots, a.now); err != nil {
		t.Fatal(err)
	}
	reopened := reopenOwned(t, store, path)
	stored, err := reopened.EnrollmentIntent()
	if err != nil || stored.RequestID != intent.RequestID || !bytes.Equal(stored.CSRDER, original) || stored.OwnerPrincipal != "verified-owner" {
		t.Fatal("renewal changed request replay proof or owner", err)
	}
}
