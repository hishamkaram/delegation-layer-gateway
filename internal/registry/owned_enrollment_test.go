package registry

import (
	"bytes"
	"crypto/x509"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func ownedTokenAttempt(t *testing.T, f *fixture, hash domain.Digest, id domain.IssuanceID) domain.EnrollmentAttempt {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	requireOK(t, err)
	return domain.EnrollmentAttempt{TokenHash: hash, CSRHash: domain.Hash([]byte("owned token CSR")), PublicKeyHash: domain.Hash(spki), Issuance: id, Serial: bytes.Repeat([]byte{1}, 16), Now: f.now}
}

func TestOwnedTokenRequiresPrivateAdminEligibilityAndCreatesFreshDevice(t *testing.T) {
	f := newFixture(t)
	hash := domain.Hash([]byte("owned first token"))
	_, err := f.store.CreateOwnedEnrollment(t.Context(), f.actor.Principal, "Workstation", hash, f.now)
	requireCode(t, err, domain.Forbidden)
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, testOwnerPolicy()))
	unprivileged, err := Open(t.Context(), f.path, Options{Gateway: f.gateway})
	requireOK(t, err)
	_, createErr := unprivileged.CreateOwnedEnrollment(t.Context(), f.actor.Principal, "Workstation", hash, f.now)
	requireCode(t, createErr, domain.Forbidden)
	requireOK(t, unprivileged.Close())
	device, err := f.store.CreateOwnedEnrollment(t.Context(), f.actor.Principal, "Workstation", hash, f.now)
	requireOK(t, err)
	if device.ID == "device" || device.ID == "" || device.CredentialGeneration != 0 {
		t.Fatal("bootstrap adopted existing device or activated before CSR")
	}
	var owner domain.PrincipalID
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT principal FROM device_owners WHERE device=?", device.ID).Scan(&owner))
	if owner != f.actor.Principal {
		t.Fatal("bootstrap owner was not atomic")
	}
	var legacyOwner int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM device_owners WHERE device='device'").Scan(&legacyOwner))
	if legacyOwner != 0 {
		t.Fatal("same display name adopted legacy device")
	}
	f.restart(t)
	intent, err := f.store.BeginEnrollment(t.Context(), ownedTokenAttempt(t, f, hash, "owned-first"))
	requireOK(t, err)
	if intent.Credential.Device != device.ID || intent.Mode != domain.Regular || intent.Credential.Generation != 1 {
		t.Fatal("token lost its one-device regular credential binding")
	}
}

func TestOwnedTokenAndSelfServiceSharePendingQuota(t *testing.T) {
	for _, first := range []string{"token", "self"} {
		t.Run(first, func(t *testing.T) {
			f := newFixture(t)
			actor, self := selfEnrollmentFixture(t, f)
			policy := testOwnerPolicy()
			policy.MaxDevices = 1
			requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, policy))
			hash := domain.Hash([]byte("pending owned token"))
			if first == "token" {
				_, err := f.store.CreateOwnedEnrollment(t.Context(), actor.Principal, "token", hash, f.now)
				requireOK(t, err)
				_, err = f.store.BeginSelfEnrollment(t.Context(), actor, self)
				requireCode(t, err, domain.ResourceLimit)
				self.Now = f.now.Add(domain.EnrollmentTTL)
				_, err = f.store.BeginSelfEnrollment(t.Context(), actor, self)
				requireOK(t, err)
			} else {
				_, err := f.store.BeginSelfEnrollment(t.Context(), actor, self)
				requireOK(t, err)
				_, err = f.store.CreateOwnedEnrollment(t.Context(), actor.Principal, "token", hash, f.now)
				requireCode(t, err, domain.ResourceLimit)
				_, err = f.store.CreateOwnedEnrollment(t.Context(), actor.Principal, "token", hash, f.now.Add(domain.EnrollmentTTL))
				requireOK(t, err)
			}
		})
	}
}

func TestOwnedTokenActivationDeadlineCannotBypassQuotaAndCompletedReplaySurvives(t *testing.T) {
	t.Run("reserved but expired", func(t *testing.T) {
		f := newFixture(t)
		actor, self := selfEnrollmentFixture(t, f)
		policy := testOwnerPolicy()
		policy.MaxDevices = 1
		requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, policy))
		hash := domain.Hash([]byte("expired owned token"))
		device, err := f.store.CreateOwnedEnrollment(t.Context(), actor.Principal, "token", hash, f.now)
		requireOK(t, err)
		attempt := ownedTokenAttempt(t, f, hash, "owned-expired")
		intent, err := f.store.BeginEnrollment(t.Context(), attempt)
		requireOK(t, err)
		later := f.now.Add(domain.EnrollmentTTL)
		self.Now = later
		_, err = f.store.BeginSelfEnrollment(t.Context(), actor, self)
		requireOK(t, err)
		_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: signFixture(t, intent, f.key), Now: later})
		requireCode(t, err, domain.Expired)
		var credentials int
		requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM credentials WHERE device=?", device.ID).Scan(&credentials))
		if credentials != 0 {
			t.Fatal("expired pending token activated after quota reuse")
		}
	})
	t.Run("completed replay", func(t *testing.T) {
		f := newFixture(t)
		policy := testOwnerPolicy()
		policy.MaxDevices = 1
		requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
		hash := domain.Hash([]byte("completed owned token"))
		_, err := f.store.CreateOwnedEnrollment(t.Context(), f.actor.Principal, "token", hash, f.now)
		requireOK(t, err)
		input := ownedTokenAttempt(t, f, hash, "owned-complete")
		intent, err := f.store.BeginEnrollment(t.Context(), input)
		requireOK(t, err)
		issued := signFixture(t, intent, f.key)
		first, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: issued, Now: f.now})
		requireOK(t, err)
		f.restart(t)
		input.Now = f.now.Add(domain.EnrollmentTTL)
		input.Issuance = "unused-after-expiry"
		input.Serial = bytes.Repeat([]byte{2}, 16)
		replay, err := f.store.BeginEnrollment(t.Context(), input)
		requireOK(t, err)
		if replay.ID != intent.ID {
			t.Fatal("completed receipt expiry created another issuance")
		}
		second, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: issued, Now: input.Now})
		requireOK(t, err)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("completed receipt changed after bootstrap expiry")
		}
		_, err = f.store.CreateOwnedEnrollment(t.Context(), f.actor.Principal, "another", domain.Hash([]byte(strings.Repeat("x", 32))), input.Now)
		requireCode(t, err, domain.ResourceLimit)
	})
}

func TestOwnedTokenLookupIsReadOnlyForUnknownExternalIdentity(t *testing.T) {
	f := newFixture(t)
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, testOwnerPolicy()))
	var before, after int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM principals").Scan(&before))
	_, err := f.store.LookupOwnerPrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "not-materialized"})
	requireCode(t, err, domain.Forbidden)
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM principals").Scan(&after))
	if before != after {
		t.Fatal("owned token lookup materialized an unknown subject")
	}
	known, err := f.store.LookupOwnerPrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "alice"})
	requireOK(t, err)
	if known.ID != f.actor.Principal {
		t.Fatal("eligible exact subject lookup changed principal")
	}
}
