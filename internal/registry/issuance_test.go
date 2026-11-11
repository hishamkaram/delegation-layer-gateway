package registry

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestDelayedRenewalCompletionCannotRegressActiveValidity(t *testing.T) {
	f := newFixture(t)
	credential, err := f.store.CheckCredential(t.Context(), f.credential, f.now)
	current := must(t, credential, err)
	olderAttempt := renewalFixture(f, current, "older-renewal", 2, f.now.Add(domain.RenewalAfter))
	newerAttempt := renewalFixture(f, current, "newer-renewal", 3, olderAttempt.Now.Add(time.Hour))
	intent, err := f.store.BeginRenewal(t.Context(), olderAttempt)
	older := must(t, intent, err)
	intent, err = f.store.BeginRenewal(t.Context(), newerAttempt)
	newer := must(t, intent, err)
	olderDER := signFixture(t, older, f.key)
	newerDER := signFixture(t, newer, f.key)
	completedAt := newerAttempt.Now.Add(time.Hour)
	_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: newer.ID, CertificateDER: newerDER, Now: completedAt})
	requireOK(t, err)
	receipt, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: older.ID, CertificateDER: olderDER, Now: completedAt})
	oldReceipt := must(t, receipt, err)
	if !bytes.Equal(oldReceipt.CertificateDER, olderDER) || oldReceipt.Intent.ID != older.ID {
		t.Fatal("older completion substituted a different intent's certificate")
	}
	assertActiveRenewal(t, f, newer, completedAt)
	// Lost-ACK replay still identifies the older immutable receipt, even though
	// the newer validity window remains the sole active credential authority.
	olderAttempt.Now = completedAt
	olderAttempt.Issuance = "ignored-retry"
	olderAttempt.Serial = bytes.Repeat([]byte{4}, 16)
	intent, err = f.store.BeginRenewal(t.Context(), olderAttempt)
	if !reflect.DeepEqual(must(t, intent, err), older) {
		t.Fatal("older request replay selected a different issuance intent")
	}
	receipt, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: older.ID, CertificateDER: signFixture(t, older, f.key), Now: completedAt})
	if !bytes.Equal(must(t, receipt, err).CertificateDER, olderDER) {
		t.Fatal("older lost-ACK replay changed its original certificate bytes")
	}
	f.restart(t)
	receipt, err = f.store.GetIssuanceReceipt(t.Context(), older.ID, completedAt)
	if !bytes.Equal(must(t, receipt, err).CertificateDER, olderDER) {
		t.Fatal("restart replaced the older intent's immutable receipt")
	}
	assertActiveRenewal(t, f, newer, older.NotAfter.Add(30*time.Minute))
}

func renewalFixture(f *fixture, current domain.Credential, request domain.RequestID, serial byte, now time.Time) domain.RenewalAttempt {
	return domain.RenewalAttempt{Credential: f.credential, Request: request, CSRHash: domain.Hash([]byte("renewal CSR")), PublicKeyHash: current.PublicKeyHash, Issuance: domain.IssuanceID(request), Serial: bytes.Repeat([]byte{serial}, 16), Now: now}
}

func assertActiveRenewal(t *testing.T, f *fixture, newer domain.IssuanceIntent, now time.Time) {
	t.Helper()
	credential, err := f.store.CheckCredential(t.Context(), f.credential, now)
	active := must(t, credential, err)
	if !active.NotBefore.Equal(newer.NotBefore) || !active.NotAfter.Equal(newer.NotAfter) {
		t.Fatalf("active validity regressed to %s..%s; want %s..%s", active.NotBefore, active.NotAfter, newer.NotBefore, newer.NotAfter)
	}
}
