package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func selfOwner(t *testing.T, store *registry.Store) domain.Actor {
	t.Helper()
	principal, err := store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	policy := domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 2}
	if err = store.PutOwnerPolicy(t.Context(), principal.ID, policy); err != nil {
		t.Fatal(err)
	}
	return domain.Actor{Principal: principal.ID, Scopes: domain.ScopeSet{domain.DeviceEnroll, domain.DeviceManage}}
}

func TestSelfEnrollmentUsesDurableCSRBoundReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "registry.db")
	store, err := registry.Create(t.Context(), path, registry.CreateOptions{Admin: testAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	actor := selfOwner(t, store)
	gateway, err := store.Identity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ca := certificateAuthority(t, now)
	service, err := NewSelf(store, ca, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	csr := requestCSR(t)
	request := domain.RequestID(strings.Repeat("1", 32))
	first, err := service.SelfEnroll(t.Context(), actor, request, "Owned workstation", csr, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = registry.Open(t.Context(), path, registry.Options{Gateway: gateway, Admin: testAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	service, err = NewSelf(store, ca, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	again, err := service.SelfEnroll(t.Context(), actor, request, "Owned workstation", csr, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, first, again)
	if _, err = service.SelfEnroll(t.Context(), actor, request, "Owned workstation", requestCSR(t), "", 0); err == nil {
		t.Fatal("replay accepted a different CSR")
	}
	if err = store.SetPrincipalRevoked(t.Context(), actor.Principal, true); err != nil {
		t.Fatal(err)
	}
	if _, err = service.SelfEnroll(t.Context(), actor, request, "Owned workstation", csr, "", 0); err == nil {
		t.Fatal("revoked principal retrieved an existing certificate")
	}
}

func assertSameCertificate(t *testing.T, first, again domain.CertificateReceipt) {
	t.Helper()
	if again.Intent.ID != first.Intent.ID || !bytes.Equal(again.CertificateDER, first.CertificateDER) || again.Intent.Credential != first.Intent.Credential {
		t.Fatal("lost response changed issued identity")
	}
}

func TestSelfReplacementRequiresBothScopesAndKeepsDeviceIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store, err := registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.db"), registry.CreateOptions{Admin: testAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	actor := selfOwner(t, store)
	service, err := NewSelf(store, certificateAuthority(t, now), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	csr := requestCSR(t)
	first, err := service.SelfEnroll(t.Context(), actor, domain.RequestID(strings.Repeat("1", 32)), "Owned workstation", csr, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	replacement := domain.RequestID(strings.Repeat("2", 32))
	enrollOnly := actor
	enrollOnly.Scopes = domain.ScopeSet{domain.DeviceEnroll}
	if _, err = service.SelfEnroll(t.Context(), enrollOnly, replacement, "Owned workstation", csr, first.Intent.Credential.Device, 1); err == nil {
		t.Fatal("enrollment-only authority replaced an active credential")
	}
	next, err := service.SelfEnroll(t.Context(), actor, replacement, "Owned workstation", csr, first.Intent.Credential.Device, 1)
	if err != nil || next.Intent.Credential.Device != first.Intent.Credential.Device || next.Intent.Credential.Generation != 2 {
		t.Fatalf("replacement did not retain the device: %v", err)
	}
	again, err := service.SelfEnroll(t.Context(), actor, replacement, "Owned workstation", csr, first.Intent.Credential.Device, 1)
	if err != nil || again.Intent.Credential != next.Intent.Credential || !bytes.Equal(again.CertificateDER, next.CertificateDER) {
		t.Fatalf("replacement retry bumped generation again: %v", err)
	}
	if _, err = store.CheckCredential(t.Context(), first.Intent.Credential, now); err == nil {
		t.Fatal("old credential remained authorized after replacement")
	}
}

type pausedSigner struct {
	ready chan<- domain.IssuanceIntent
	gate  <-chan struct{}
	inner Signer
}

func (s pausedSigner) Sign(ctx context.Context, intent domain.IssuanceIntent, csr []byte, serial *big.Int, random io.Reader) ([]byte, error) {
	s.ready <- intent
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.gate:
		return s.inner.Sign(ctx, intent, csr, serial, random)
	}
}

func TestSelfEnrollmentExpiryDuringSigningCannotActivate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store, err := registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.db"), registry.CreateOptions{Admin: testAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	actor := selfOwner(t, store)
	ready := make(chan domain.IssuanceIntent, 1)
	gate := make(chan struct{})
	service, err := NewSelf(store, pausedSigner{ready: ready, gate: gate, inner: certificateAuthority(t, now)}, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	csr := requestCSR(t)
	var issueErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, issueErr = service.SelfEnroll(ctx, actor, domain.RequestID(strings.Repeat("1", 32)), "Owned workstation", csr, "", 0)
	}()
	t.Cleanup(func() { cancel(); <-done })
	var intent domain.IssuanceIntent
	select {
	case intent = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("signer did not receive the reserved intent")
	}
	now = now.Add(domain.EnrollmentTTL)
	close(gate)
	<-done
	var refusal *domain.Error
	if !errors.As(issueErr, &refusal) || refusal.Code != domain.Expired {
		t.Fatalf("expired signing activated a certificate: %v", issueErr)
	}
	if _, err = store.CheckCredential(t.Context(), intent.Credential, now); err == nil {
		t.Fatal("expired issuance became an active credential")
	}
}
