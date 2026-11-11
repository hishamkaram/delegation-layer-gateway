package deviceidentity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
)

type authority struct {
	ca    *identity.CertificateAuthority
	roots *x509.CertPool
	now   time.Time
	ref   domain.CredentialRef
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, signErr := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if signErr != nil {
		t.Fatal(signErr)
	}
	cert, parseErr := x509.ParseCertificate(der)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	ca, caErr := identity.NewCertificateAuthority(cert, key)
	if caErr != nil {
		t.Fatal(caErr)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return authority{ca: ca, roots: roots, now: now, ref: domain.CredentialRef{Device: "device-one", Epoch: "epoch-one", Generation: 1}}
}

func (a authority) sign(t *testing.T, csr []byte, serial int64, ref domain.CredentialRef) []byte {
	t.Helper()
	info, parseErr := identity.ParseCSR(csr)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	number := big.NewInt(serial)
	intent := domain.IssuanceIntent{ID: "test-issuance", Credential: ref, Mode: domain.Regular, Serial: number.Bytes(), CSRHash: info.CSRHash, PublicKeyHash: info.PublicKeyHash, NotBefore: a.now.Add(-time.Minute), NotAfter: a.now.Add(-time.Minute).Add(domain.CertificateLifetime)}
	der, signErr := a.ca.Sign(t.Context(), intent, csr, number, rand.Reader)
	if signErr != nil {
		t.Fatal(signErr)
	}
	return der
}

func openOwned(t *testing.T, path string) *Store {
	t.Helper()
	store, openErr := Open(path)
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return store
}

func enroll(t *testing.T, store *Store, a authority) []byte {
	t.Helper()
	csr, csrErr := store.EnsureKey(rand.Reader)
	if csrErr != nil {
		t.Fatal(csrErr)
	}
	der := a.sign(t, csr, 2, a.ref)
	if installErr := store.InstallEnrollment(der, a.ref, a.roots, a.now); installErr != nil {
		t.Fatal(installErr)
	}
	return csr
}

func TestRenewalIntentSurvivesRestartAndCompletesAtomically(t *testing.T) {
	a := newAuthority(t)
	path := filepath.Join(t.TempDir(), "identity")
	first := openOwned(t, path)
	initialCSR := enroll(t, first, a)
	intent, beginErr := first.BeginRenewal(a.ref, rand.Reader)
	if beginErr != nil {
		t.Fatal(beginErr)
	}
	assertStableRenewal(t, first, a, initialCSR, intent)
	restarted := reopenOwned(t, first, path)
	pending := assertPendingRenewal(t, restarted, intent)
	issued := a.sign(t, pending.CSRDER, 3, a.ref)
	if completeErr := restarted.CompleteRenewal("wrong", issued, a.roots, a.now); !errors.Is(completeErr, ErrConflict) {
		t.Fatal("mismatched renewal ID completed")
	}
	if completeErr := restarted.CompleteRenewal(pending.ID, issued, a.roots, a.now); completeErr != nil {
		t.Fatal(completeErr)
	}
	if _, pendingErr := restarted.PendingRenewal(); !errors.Is(pendingErr, ErrAbsent) {
		t.Fatal("completed intent remained pending")
	}
	final := reopenOwned(t, restarted, path)
	assertRenewedCertificate(t, final, a)
	if completeErr := final.CompleteRenewal(pending.ID, issued, a.roots, a.now); completeErr != nil {
		t.Fatal("matching completion retry was not idempotent")
	}
}

func TestEnrollmentAndRenewalRejectForeignKeyIdentityAndTrust(t *testing.T) {
	a := newAuthority(t)
	store := openOwned(t, filepath.Join(t.TempDir(), "identity"))
	csr := enroll(t, store, a)
	pending, beginErr := store.BeginRenewal(a.ref, rand.Reader)
	if beginErr != nil {
		t.Fatal(beginErr)
	}
	other := openOwned(t, filepath.Join(t.TempDir(), "other"))
	foreignCSR, foreignErr := other.EnsureKey(rand.Reader)
	if foreignErr != nil {
		t.Fatal(foreignErr)
	}
	wrongRef := a.ref
	wrongRef.Device = "other-device"
	rejected := [][]byte{a.sign(t, foreignCSR, 4, a.ref), a.sign(t, csr, 5, wrongRef)}
	for _, der := range rejected {
		if completeErr := store.CompleteRenewal(pending.ID, der, a.roots, a.now); !errors.Is(completeErr, ErrInvalid) {
			t.Fatal("foreign key/identity completed renewal")
		}
	}
	matching := a.sign(t, pending.CSRDER, 6, a.ref)
	if completeErr := store.CompleteRenewal(pending.ID, matching, x509.NewCertPool(), a.now); !errors.Is(completeErr, ErrInvalid) {
		t.Fatal("untrusted certificate completed renewal")
	}
	if completeErr := store.CompleteRenewal(pending.ID, matching, a.roots, a.now.Add(domain.CertificateLifetime)); !errors.Is(completeErr, ErrInvalid) {
		t.Fatal("expired certificate completed renewal")
	}
	retained, pendingErr := store.PendingRenewal()
	if pendingErr != nil || retained.ID != pending.ID {
		t.Fatal("certificate rejection cleared uncertain intent")
	}
	pair, _, certErr := store.Certificate(a.roots, a.now)
	if certErr != nil || pair.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("rejection changed active pair")
	}
}

func TestReturnedMaterialsCannotMutateStoredIdentity(t *testing.T) {
	a := newAuthority(t)
	store := openOwned(t, filepath.Join(t.TempDir(), "identity"))
	csr := enroll(t, store, a)
	csr[0] ^= 0xff
	again, csrErr := store.EnsureKey(nil)
	if csrErr != nil {
		t.Fatal(csrErr)
	}
	if _, parseErr := identity.ParseCSR(again); parseErr != nil {
		t.Fatal("caller mutated stored CSR")
	}
	pending, beginErr := store.BeginRenewal(a.ref, rand.Reader)
	if beginErr != nil {
		t.Fatal(beginErr)
	}
	pending.CSRDER[0] ^= 0xff
	retained, pendingErr := store.PendingRenewal()
	if pendingErr != nil {
		t.Fatal(pendingErr)
	}
	if _, parseErr := identity.ParseCSR(retained.CSRDER); parseErr != nil {
		t.Fatal("caller mutated stored renewal")
	}
	pair, _, pairErr := store.Certificate(a.roots, a.now)
	if pairErr != nil {
		t.Fatal(pairErr)
	}
	pair.Certificate[0][0] ^= 0xff
	if _, _, certErr := store.Certificate(a.roots, a.now); certErr != nil {
		t.Fatal("caller mutated stored certificate")
	}
}

func TestConcurrentRenewalBeginsShareOneDurableIntent(t *testing.T) {
	a := newAuthority(t)
	store := openOwned(t, filepath.Join(t.TempDir(), "identity"))
	enroll(t, store, a)
	type result struct {
		intent RenewalIntent
		err    error
	}
	results := make(chan result, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			intent, beginErr := store.BeginRenewal(a.ref, rand.Reader)
			results <- result{intent: intent, err: beginErr}
		})
	}
	workers.Wait()
	close(results)
	var first RenewalIntent
	for item := range results {
		if item.err != nil {
			t.Fatal(item.err)
		}
		if first.ID == "" {
			first = item.intent
		}
		if item.intent.ID != first.ID || !bytes.Equal(item.intent.CSRDER, first.CSRDER) {
			t.Fatal("concurrent renewal callers created conflicting durable requests")
		}
	}
	retained, pendingErr := store.PendingRenewal()
	if pendingErr != nil || retained.ID != first.ID {
		t.Fatal("concurrent renewal did not persist canonical intent")
	}
}

func reopenOwned(t *testing.T, store *Store, path string) *Store {
	t.Helper()
	if closeErr := store.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	return openOwned(t, path)
}

func assertStableRenewal(t *testing.T, first *Store, a authority, initialCSR []byte, intent RenewalIntent) {
	t.Helper()
	again, repeatErr := first.BeginRenewal(a.ref, nil)
	if repeatErr != nil || again.ID != intent.ID || !bytes.Equal(again.CSRDER, intent.CSRDER) {
		t.Fatal("renewal retry changed persisted request")
	}
	initialInfo, initialErr := identity.ParseCSR(initialCSR)
	renewInfo, renewErr := identity.ParseCSR(intent.CSRDER)
	if initialErr != nil || renewErr != nil || initialInfo.PublicKeyHash != renewInfo.PublicKeyHash || len(intent.ID) != 32 {
		t.Fatal("renewal rotated key or invalid identity")
	}
}

func assertPendingRenewal(t *testing.T, restarted *Store, intent RenewalIntent) RenewalIntent {
	t.Helper()
	pending, pendingErr := restarted.PendingRenewal()
	if pendingErr != nil || pending.ID != intent.ID || !bytes.Equal(pending.CSRDER, intent.CSRDER) {
		t.Fatal("uncertain renewal was lost on restart")
	}
	return pending
}

func assertRenewedCertificate(t *testing.T, final *Store, a authority) {
	t.Helper()
	pair, ref, certErr := final.Certificate(a.roots, a.now)
	if certErr != nil || ref != a.ref || pair.Leaf.SerialNumber.Int64() != 3 {
		t.Fatal("matching certificate did not survive committed intent clear")
	}
}
