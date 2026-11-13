package deviceidentity

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func expectStored(t *testing.T, store *Store, expected domain.CredentialRef) {
	t.Helper()
	actual, readErr := store.StoredCredentialRef()
	if readErr != nil || actual != expected {
		t.Fatal("local CAS credential changed unexpectedly")
	}
}

func expectNoPending(t *testing.T, store *Store) {
	t.Helper()
	if _, pendingErr := store.PendingRenewal(); !errors.Is(pendingErr, ErrAbsent) {
		t.Fatal("superseded renewal intent was not cleared atomically")
	}
}

func expectConflict(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected local CAS conflict, got %v", err)
	}
}

func TestExplicitReplacementSupersedesPendingAndRetriesAfterRestart(t *testing.T) {
	a := newAuthority(t)
	path := filepath.Join(t.TempDir(), "identity")
	store := openOwned(t, path)
	csr := enroll(t, store, a)
	pending, pendingErr := store.BeginRenewal(a.ref, rand.Reader)
	if pendingErr != nil {
		t.Fatal(pendingErr)
	}
	newer := a.ref
	newer.Generation++
	der := a.sign(t, csr, 3, newer)
	expectConflict(t, store.InstallEnrollment(der, newer, a.roots, a.now))
	if replaceErr := store.ReplaceEnrollment(der, a.ref, newer, a.roots, a.now); replaceErr != nil {
		t.Fatal(replaceErr)
	}
	expectStored(t, store, newer)
	expectNoPending(t, store)
	oldCompletion := a.sign(t, pending.CSRDER, 4, a.ref)
	expectConflict(t, store.CompleteRenewal(pending.ID, oldCompletion, a.roots, a.now))
	restarted := reopenOwned(t, store, path)
	if retryErr := restarted.ReplaceEnrollment(der, a.ref, newer, a.roots, a.now); retryErr != nil {
		t.Fatal("lost local replacement response was not idempotent after restart")
	}
	expectStored(t, restarted, newer)
	expectNoPending(t, restarted)
}

func TestReplacementCASRejectsStalePriorAndPreservesNewRenewal(t *testing.T) {
	a := newAuthority(t)
	store := openOwned(t, filepath.Join(t.TempDir(), "identity"))
	csr := enroll(t, store, a)
	newer := a.ref
	newer.Generation = 2
	der := a.sign(t, csr, 3, newer)
	if replaceErr := store.ReplaceEnrollment(der, a.ref, newer, a.roots, a.now); replaceErr != nil {
		t.Fatal(replaceErr)
	}
	pending, pendingErr := store.BeginRenewal(newer, rand.Reader)
	if pendingErr != nil {
		t.Fatal(pendingErr)
	}
	if retryErr := store.ReplaceEnrollment(der, a.ref, newer, a.roots, a.now); retryErr != nil {
		t.Fatal(retryErr)
	}
	retained, retainedErr := store.PendingRenewal()
	if retainedErr != nil || retained.ID != pending.ID {
		t.Fatal("replacement retry discarded a later renewal")
	}
	third := newer
	third.Generation = 3
	nextDER := a.sign(t, csr, 4, third)
	expectConflict(t, store.ReplaceEnrollment(nextDER, a.ref, third, a.roots, a.now))
	unrelated := a.ref
	unrelated.Epoch = "unrelated-epoch"
	expectConflict(t, store.ReplaceEnrollment(der, unrelated, newer, a.roots, a.now))
	sameGeneration := a.sign(t, csr, 5, newer)
	expectConflict(t, store.ReplaceEnrollment(sameGeneration, newer, newer, a.roots, a.now))
	expectStored(t, store, newer)
}

func TestExplicitNewEpochMayLowerGenerationButNeverSkipCASOrIdentity(t *testing.T) {
	a := newAuthority(t)
	a.ref.Generation = 90
	store := openOwned(t, filepath.Join(t.TempDir(), "identity"))
	csr := enroll(t, store, a)
	newer := a.ref
	newer.Epoch = "epoch-two"
	newer.Generation = 1
	der := a.sign(t, csr, 3, newer)
	wrongExpected := newer
	wrongExpected.Epoch = "epoch-three"
	if replaceErr := store.ReplaceEnrollment(der, a.ref, wrongExpected, a.roots, a.now); !errors.Is(replaceErr, ErrInvalid) {
		t.Fatal("wrong expected epoch bypassed certificate binding")
	}
	if replaceErr := store.ReplaceEnrollment(der, a.ref, newer, a.roots, a.now); replaceErr != nil {
		t.Fatal("explicit restore epoch incorrectly ordered generation counters")
	}
	third := newer
	third.Epoch = "epoch-three"
	expectConflict(t, store.ReplaceEnrollment(a.sign(t, csr, 4, third), a.ref, third, a.roots, a.now))
	foreign := third
	foreign.Device = "foreign-device"
	expectConflict(t, store.ReplaceEnrollment(a.sign(t, csr, 5, foreign), newer, foreign, a.roots, a.now))
	expectStored(t, store, newer)
}

func TestExpiredLocalRecordSupportsExplicitCASButNotAuthentication(t *testing.T) {
	a := newAuthority(t)
	store := openOwned(t, filepath.Join(t.TempDir(), "identity"))
	csr := enroll(t, store, a)
	now := a.now.Add(domain.CertificateLifetime)
	if _, _, certErr := store.Certificate(a.roots, now); !errors.Is(certErr, ErrInvalid) {
		t.Fatal("expired certificate authenticated")
	}
	expectStored(t, store, a.ref)
	fresh := a
	fresh.now = now
	newer := a.ref
	newer.Generation++
	if replaceErr := store.ReplaceEnrollment(fresh.sign(t, csr, 3, newer), a.ref, newer, a.roots, now); replaceErr != nil {
		t.Fatal(replaceErr)
	}
	if _, ref, certErr := store.Certificate(a.roots, now); certErr != nil || ref != newer {
		t.Fatal("explicit fresh certificate failed authentication validation")
	}
}

func TestReplacementDirectorySyncFailureIsUncertainAndWholeOnReopen(t *testing.T) {
	a := newAuthority(t)
	path := filepath.Join(t.TempDir(), "identity")
	store, openErr := Open(path)
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			t.Error(closeErr)
		}
	})
	csr := enroll(t, store, a)
	pending, pendingErr := store.BeginRenewal(a.ref, rand.Reader)
	if pendingErr != nil {
		t.Fatal(pendingErr)
	}
	newer := a.ref
	newer.Generation++
	der := a.sign(t, csr, 3, newer)
	if closeErr := store.directory.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if replaceErr := store.ReplaceEnrollment(der, a.ref, newer, a.roots, a.now); !errors.Is(replaceErr, ErrUncertain) {
		t.Fatal("unsynced replacement returned confirmed success")
	}
	if _, readErr := store.StoredCredentialRef(); !errors.Is(readErr, ErrUncertain) {
		t.Fatal("uncertain writer continued serving local credential state")
	}
	if closeErr := store.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
		t.Fatal(closeErr)
	}
	restarted := openOwned(t, path)
	expectStored(t, restarted, newer)
	expectNoPending(t, restarted)
	expectConflict(t, restarted.CompleteRenewal(pending.ID, a.sign(t, pending.CSRDER, 4, a.ref), a.roots, a.now))
	if retryErr := restarted.ReplaceEnrollment(der, a.ref, newer, a.roots, a.now); retryErr != nil {
		t.Fatal(retryErr)
	}
}
