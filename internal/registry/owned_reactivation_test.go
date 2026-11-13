package registry

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func reactivationFixture(t *testing.T) (*fixture, domain.Actor, domain.SelfEnrollmentAttempt, domain.IssuanceIntent) {
	t.Helper()
	f := newFixture(t)
	actor, input := selfEnrollmentFixture(t, f)
	policy := testOwnerPolicy()
	policy.MaxDevices = 1
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, policy))
	intent, err := f.store.BeginSelfEnrollment(t.Context(), actor, input)
	first := must(t, intent, err)
	_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: first.ID, CertificateDER: signFixture(t, first, f.key), Now: f.now})
	requireOK(t, err)
	return f, actor, input, first
}

func nextOwnedBootstrap(input domain.SelfEnrollmentAttempt, now time.Time) domain.SelfEnrollmentAttempt {
	input.Request = domain.RequestID(strings.Repeat("2", 32))
	input.Name = "Second workstation"
	input.Issuance = "next-owned-bootstrap"
	input.Serial = bytes.Repeat([]byte{2}, 16)
	input.Now = now
	return input
}

func occupyOwnedSlot(t *testing.T, f *fixture, actor domain.Actor, input domain.SelfEnrollmentAttempt, now time.Time) domain.IssuanceIntent {
	t.Helper()
	intent, err := f.store.BeginSelfEnrollment(t.Context(), actor, nextOwnedBootstrap(input, now))
	second := must(t, intent, err)
	_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: second.ID, CertificateDER: signFixture(t, second, f.key), Now: now})
	requireOK(t, err)
	return second
}

func replacement(input domain.SelfEnrollmentAttempt, prior domain.IssuanceIntent, now time.Time) domain.SelfEnrollmentAttempt {
	input.Request = domain.RequestID(strings.Repeat("3", 32))
	input.Issuance = "replace-owned-bootstrap"
	input.Serial = bytes.Repeat([]byte{3}, 16)
	input.ReplaceDevice = prior.Credential.Device
	input.ExpectedGeneration = prior.Credential.Generation
	input.Now = now
	return input
}

func TestOwnedReactivationExpiredDeviceCannotAcquireOccupiedSlot(t *testing.T) {
	for _, mode := range []string{"self-replacement", "private-token"} {
		t.Run(mode, func(t *testing.T) {
			f, actor, input, first := reactivationFixture(t)
			later := first.NotAfter
			second := occupyOwnedSlot(t, f, actor, input, later)
			var err error
			if mode == "self-replacement" {
				_, err = f.store.BeginSelfEnrollment(t.Context(), actor, replacement(input, first, later))
			} else {
				err = f.store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: domain.Hash([]byte("expired-owned-legacy-token")), Device: first.Credential.Device, Mode: domain.Regular, Generation: first.Credential.Generation + 1, CreatedAt: later, ExpiresAt: later.Add(domain.EnrollmentTTL)})
			}
			requireCode(t, err, domain.ResourceLimit)
			_, err = f.store.CheckCredential(t.Context(), second.Credential, later)
			requireOK(t, err)
			_, err = f.store.CheckCredential(t.Context(), first.Credential, later)
			requireCode(t, err, domain.Expired)
		})
	}
}

func ownedRenewal(t *testing.T, f *fixture, first domain.IssuanceIntent) domain.IssuanceIntent {
	t.Helper()
	input := domain.RenewalAttempt{Credential: first.Credential, Request: "delayed-owned-renewal", CSRHash: first.CSRHash, PublicKeyHash: first.PublicKeyHash, Issuance: "delayed-owned-renewal", Serial: bytes.Repeat([]byte{4}, 16), Now: first.NotAfter.Add(-time.Minute)}
	intent, err := f.store.BeginRenewal(t.Context(), input)
	return must(t, intent, err)
}

func TestOwnedReactivationDelayedRenewalRechecksCapacityAfterOldExpiry(t *testing.T) {
	f, actor, input, first := reactivationFixture(t)
	renewal := ownedRenewal(t, f, first)
	later := first.NotAfter
	second := occupyOwnedSlot(t, f, actor, input, later)
	_, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: renewal.ID, CertificateDER: signFixture(t, renewal, f.key), Now: later})
	requireCode(t, err, domain.ResourceLimit)
	var certificate []byte
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT certificate FROM issuance WHERE id=?", renewal.ID).Scan(&certificate))
	if certificate != nil {
		t.Fatal("denied renewal committed a receipt")
	}
	_, err = f.store.CheckCredential(t.Context(), second.Credential, later)
	requireOK(t, err)
	_, err = f.store.CheckCredential(t.Context(), first.Credential, later)
	requireCode(t, err, domain.Expired)
}

func TestOwnedReactivationCountedReplacementAndAvailableRenewalUseOneSlot(t *testing.T) {
	t.Run("counted replacement", func(t *testing.T) {
		f, actor, input, first := reactivationFixture(t)
		next, err := f.store.BeginSelfEnrollment(t.Context(), actor, replacement(input, first, f.now))
		requireOK(t, err)
		_, err = f.store.BeginSelfEnrollment(t.Context(), actor, nextOwnedBootstrap(input, f.now))
		requireCode(t, err, domain.ResourceLimit)
		der := signFixture(t, next, f.key)
		accepted, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: next.ID, CertificateDER: der, Now: f.now})
		requireOK(t, err)
		replayed, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: next.ID, CertificateDER: der, Now: f.now.Add(domain.EnrollmentTTL)})
		requireOK(t, err)
		if !reflect.DeepEqual(accepted, replayed) {
			t.Fatal("committed replacement replay changed")
		}
	})
	t.Run("counted renewal", func(t *testing.T) {
		f, actor, input, first := reactivationFixture(t)
		renewal := ownedRenewal(t, f, first)
		_, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: renewal.ID, CertificateDER: signFixture(t, renewal, f.key), Now: renewal.NotBefore})
		requireOK(t, err)
		_, err = f.store.BeginSelfEnrollment(t.Context(), actor, nextOwnedBootstrap(input, renewal.NotBefore))
		requireCode(t, err, domain.ResourceLimit)
	})
	t.Run("available renewal after expiry", func(t *testing.T) {
		f, _, _, first := reactivationFixture(t)
		renewal := ownedRenewal(t, f, first)
		_, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: renewal.ID, CertificateDER: signFixture(t, renewal, f.key), Now: first.NotAfter})
		requireOK(t, err)
		current, err := f.store.CheckCredential(t.Context(), first.Credential, first.NotAfter)
		requireOK(t, err)
		if !current.NotAfter.Equal(renewal.NotAfter) {
			t.Fatal("available renewal did not activate its newer validity")
		}
	})
}

func TestOwnedReactivationConcurrentRenewalAndBootstrapShareLastSlot(t *testing.T) {
	f, actor, input, first := reactivationFixture(t)
	renewal := ownedRenewal(t, f, first)
	completion := domain.IssuanceCompletion{Intent: renewal.ID, CertificateDER: signFixture(t, renewal, f.key), Now: first.NotAfter}
	next := nextOwnedBootstrap(input, first.NotAfter)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	start := make(chan struct{})
	answers := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	t.Cleanup(func() { cancel(); workers.Wait() })
	go func() {
		defer workers.Done()
		<-start
		_, err := f.store.CompleteIssuance(ctx, completion)
		answers <- err
	}()
	go func() {
		defer workers.Done()
		<-start
		_, err := f.store.BeginSelfEnrollment(ctx, actor, next)
		answers <- err
	}()
	close(start)
	passed := 0
	for range 2 {
		select {
		case err := <-answers:
			if err == nil {
				passed++
			} else {
				requireCode(t, err, domain.ResourceLimit)
			}
		case <-ctx.Done():
			t.Fatal("concurrent quota mutations did not join", ctx.Err())
		}
	}
	if passed != 1 {
		t.Fatalf("%d operations acquired the last slot, want1", passed)
	}
	var renewed, bootstrap int
	requireOK(t, f.store.db.QueryRowContext(ctx, "SELECT certificate IS NOT NULL FROM issuance WHERE id=?", renewal.ID).Scan(&renewed))
	requireOK(t, f.store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM self_enrollments WHERE id=?", next.Request).Scan(&bootstrap))
	if renewed+bootstrap != 1 {
		t.Fatal("concurrent quota decisions did not match their durable activation/reservation")
	}
}
