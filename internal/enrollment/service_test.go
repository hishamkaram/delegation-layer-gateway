package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

type testAdmin struct{}

func (testAdmin) AuthorizeAdmin(context.Context) error { return nil }

func certificateAuthority(t *testing.T, now time.Time) *devicecert.CertificateAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := devicecert.NewCertificateAuthority(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func requestCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func registerTestDevice(t *testing.T, store *registry.Store, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	if _, err := store.RegisterDevice(ctx, domain.DeviceRegistration{ID: "device", Name: "test device"}); err != nil {
		t.Fatal(err)
	}
	token, hash, err := NewToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.CreateEnrollment(ctx, domain.EnrollmentGrant{TokenHash: hash, Device: "device", Mode: domain.Regular, Generation: 1, CreatedAt: now, ExpiresAt: now.Add(domain.EnrollmentTTL)}); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestEnrollmentLostResponseCrashAndRevocation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "registry.db")
	store, err := registry.Create(ctx, path, registry.CreateOptions{Admin: testAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	generatedID, identityErr := store.Identity(ctx)
	if identityErr != nil {
		t.Fatal(identityErr)
	}
	options := registry.Options{Gateway: generatedID, Admin: testAdmin{}}
	token := registerTestDevice(t, store, now)
	csr := requestCSR(t)
	ca := certificateAuthority(t, now)
	service, err := New(store, ca, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Redeem(ctx, token, csr)
	if err != nil {
		t.Fatal(err)
	}
	// Lose the response and restart the store/service. A repeated redemption
	// must return the exact persisted certificate, not a new credential.
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = registry.Open(ctx, path, options)
	if err != nil {
		t.Fatal(err)
	}
	service, err = New(store, ca, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Redeem(ctx, token, csr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.CertificateDER, second.CertificateDER) || first.Intent.ID != second.Intent.ID {
		t.Fatal("lost response created another credential")
	}
	if _, err = service.Redeem(ctx, token, requestCSR(t)); err == nil {
		t.Fatal("token accepted another key")
	}
	if err = store.SetDeviceRevoked(ctx, "device", true); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Redeem(ctx, token, csr); err == nil {
		t.Fatal("revoked device recovered credential")
	}
}

func TestInvalidTokenAndCSRNeverReachIssuance(t *testing.T) {
	// An unavailable store intentionally detects any attempted persistence.
	service, err := New(deniedStore{}, certificateAuthority(t, time.Now()), rand.Reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Redeem(context.Background(), "short", nil); err == nil {
		t.Fatal("invalid token accepted")
	}
	token, _, err := NewToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Redeem(context.Background(), token, []byte("invalid CSR")); err == nil || errors.Is(err, errStoreTouched) {
		t.Fatal("invalid CSR reached issuance")
	}
}

var errStoreTouched = errors.New("test store touched")

type deniedStore struct{}

func (deniedStore) BeginEnrollment(context.Context, domain.EnrollmentAttempt) (domain.IssuanceIntent, error) {
	return domain.IssuanceIntent{}, errStoreTouched
}

func (deniedStore) BeginRenewal(context.Context, domain.RenewalAttempt) (domain.IssuanceIntent, error) {
	return domain.IssuanceIntent{}, errStoreTouched
}

func (deniedStore) CompleteIssuance(context.Context, domain.IssuanceCompletion) (domain.CertificateReceipt, error) {
	return domain.CertificateReceipt{}, errStoreTouched
}
