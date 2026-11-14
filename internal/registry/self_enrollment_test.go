package registry

import (
	"bytes"
	"crypto/x509"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func selfEnrollmentFixture(t *testing.T, f *fixture) (domain.Actor, domain.SelfEnrollmentAttempt) {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	key := must(t, spki, err)
	return domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.DeviceEnroll, domain.DeviceManage}}, domain.SelfEnrollmentAttempt{Request: domain.RequestID(strings.Repeat("1", 32)), Name: "Owned workstation", CSRHash: domain.Hash([]byte("owned CSR")), PublicKeyHash: domain.Hash(key), Issuance: "self-first", Serial: bytes.Repeat([]byte{1}, 16), Now: f.now}
}

func TestSelfEnrollmentIsAllowlistedAndReplayBindsOwnerAndCSR(t *testing.T) {
	f := newFixture(t)
	actor, input := selfEnrollmentFixture(t, f)
	_, err := f.store.BeginSelfEnrollment(t.Context(), actor, input)
	requireCode(t, err, domain.Forbidden)
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, testOwnerPolicy()))
	first, err := f.store.BeginSelfEnrollment(t.Context(), actor, input)
	intent := must(t, first, err)
	if intent.Credential.Device == "device" || intent.Credential.Generation != 1 {
		t.Fatal("self enrollment adopted a legacy device")
	}
	f.restart(t)
	retry := input
	retry.Issuance = "unused-candidate"
	retry.Serial = bytes.Repeat([]byte{2}, 16)
	second, err := f.store.BeginSelfEnrollment(t.Context(), actor, retry)
	if !reflect.DeepEqual(intent, must(t, second, err)) {
		t.Fatal("lost response created another device or issuance")
	}
	retry.CSRHash = domain.Hash([]byte("changed"))
	_, err = f.store.BeginSelfEnrollment(t.Context(), actor, retry)
	requireCode(t, err, domain.Conflict)
	bob, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "bob"})
	other := must(t, bob, err)
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), other.ID, testOwnerPolicy()))
	actor.Principal = other.ID
	_, err = f.store.BeginSelfEnrollment(t.Context(), actor, input)
	requireCode(t, err, domain.Conflict)
	var count int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM device_owners").Scan(&count))
	if count != 1 {
		t.Fatal("replay allocated another owned device")
	}
}

func TestSelfEnrollmentActivationExpiryAndPolicyRevocation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "disabled"}[revoke], func(t *testing.T) {
			f := newFixture(t)
			actor, input := selfEnrollmentFixture(t, f)
			requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, testOwnerPolicy()))
			reserved, err := f.store.BeginSelfEnrollment(t.Context(), actor, input)
			intent := must(t, reserved, err)
			when, code := f.now.Add(domain.EnrollmentTTL), domain.Expired
			if revoke {
				policy := testOwnerPolicy()
				policy.Enabled = false
				requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, policy))
				when, code = f.now, domain.Forbidden
			}
			_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: signFixture(t, intent, f.key), Now: when})
			requireCode(t, err, code)
			var count int
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM credentials WHERE device=?", intent.Credential.Device).Scan(&count))
			if count != 0 {
				t.Fatal("expired or disabled reservation activated")
			}
		})
	}
}

func TestSelfEnrollmentConcurrentReplayQuotaAndExpiredPending(t *testing.T) {
	f := newFixture(t)
	actor, input := selfEnrollmentFixture(t, f)
	policy := testOwnerPolicy()
	policy.MaxDevices = 1
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, policy))
	var group sync.WaitGroup
	answers := make(chan domain.IssuanceIntent, 8)
	errors := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			intent, err := f.store.BeginSelfEnrollment(t.Context(), actor, input)
			if err != nil {
				errors <- err
				return
			}
			answers <- intent
		})
	}
	group.Wait()
	close(answers)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var first domain.IssuanceIntent
	for intent := range answers {
		if first.ID == "" {
			first = intent
		}
		if !reflect.DeepEqual(first, intent) {
			t.Fatal("concurrent replay changed identity")
		}
	}
	second := input
	second.Request = domain.RequestID(strings.Repeat("2", 32))
	second.Issuance = "second"
	_, err := f.store.BeginSelfEnrollment(t.Context(), actor, second)
	requireCode(t, err, domain.ResourceLimit)
	second.Now = f.now.Add(domain.EnrollmentTTL)
	_, err = f.store.BeginSelfEnrollment(t.Context(), actor, second)
	requireOK(t, err)
	input.Now = second.Now
	_, err = f.store.BeginSelfEnrollment(t.Context(), actor, input)
	requireCode(t, err, domain.Expired)
}

func TestExplicitSelfReplacementRequiresManagementAndKeepsDevice(t *testing.T) {
	f := newFixture(t)
	actor, input := selfEnrollmentFixture(t, f)
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, testOwnerPolicy()))
	reserved, err := f.store.BeginSelfEnrollment(t.Context(), actor, input)
	first := must(t, reserved, err)
	_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: first.ID, CertificateDER: signFixture(t, first, f.key), Now: f.now})
	requireOK(t, err)
	replacement := input
	replacement.Request = domain.RequestID(strings.Repeat("2", 32))
	replacement.Issuance = "replace"
	replacement.ReplaceDevice = first.Credential.Device
	replacement.ExpectedGeneration = first.Credential.Generation
	onlyEnroll := actor
	onlyEnroll.Scopes = domain.ScopeSet{domain.DeviceEnroll}
	_, err = f.store.BeginSelfEnrollment(t.Context(), onlyEnroll, replacement)
	requireCode(t, err, domain.Forbidden)
	_, err = f.store.CheckCredential(t.Context(), first.Credential, f.now)
	requireOK(t, err)
	reserved, err = f.store.BeginSelfEnrollment(t.Context(), actor, replacement)
	next := must(t, reserved, err)
	if next.Credential.Device != first.Credential.Device || next.Credential.Generation != first.Credential.Generation+1 {
		t.Fatal("replacement lost device identity")
	}
	_, err = f.store.CheckCredential(t.Context(), first.Credential, f.now)
	requireCode(t, err, domain.Forbidden)
	again, err := f.store.BeginSelfEnrollment(t.Context(), actor, replacement)
	if !reflect.DeepEqual(next, must(t, again, err)) {
		t.Fatal("replacement retry bumped generation twice")
	}
}
