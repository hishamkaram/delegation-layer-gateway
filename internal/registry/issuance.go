package registry

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func (s *Store) CreateEnrollment(ctx context.Context, input domain.EnrollmentGrant) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validateEnrollmentGrant(input); err != nil {
		return err
	}
	return s.createEnrollment(ctx, input)
}

func validateEnrollmentGrant(input domain.EnrollmentGrant) error {
	if err := input.TokenHash.Validate(); err != nil {
		return err
	}
	if err := domain.CredentialToken(string(input.Device)); err != nil {
		return err
	}
	if err := input.Mode.Validate(); err != nil {
		return err
	}
	if input.Generation == 0 || input.Generation > math.MaxInt64 || input.CreatedAt.IsZero() || !input.ExpiresAt.Equal(input.CreatedAt.Add(domain.EnrollmentTTL)) {
		return domain.ErrInvalid
	}
	return nil
}

func (s *Store) createEnrollment(ctx context.Context, input domain.EnrollmentGrant) error {
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		device, err := readDevice(ctx, tx, input.Device)
		if err != nil {
			return struct{}{}, err
		}
		if device.Revoked || input.Generation != device.CredentialGeneration+1 {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		var blocked bool
		if err = tx.QueryRowContext(ctx, "SELECT blocked FROM settings WHERE id=1").Scan(&blocked); err != nil {
			return struct{}{}, err
		}
		if blocked && input.Mode != domain.RecoveryOnly {
			if err = allowRegularRecoveryEnrollment(ctx, tx, input.Device, input.CreatedAt); err != nil {
				return struct{}{}, err
			}
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO enrollment(token,device,mode,generation,created,expires) VALUES(?,?,?,?,?,?)", input.TokenHash[:], input.Device, input.Mode, input.Generation, input.CreatedAt.UTC().Format(timestampLayout), input.ExpiresAt.UTC().Format(timestampLayout))
		return struct{}{}, err
	})
	return err
}

func validateIssuanceAttempt(id domain.IssuanceID, serial []byte, csr, key domain.Digest, now time.Time) error {
	if err := domain.Token(string(id)); err != nil {
		return err
	}
	if err := csr.Validate(); err != nil {
		return err
	}
	if err := key.Validate(); err != nil {
		return err
	}
	if now.IsZero() || len(serial) != 16 || serial[0] == 0 || serial[0]&0x80 != 0 {
		return domain.ErrInvalid
	}
	return nil
}

func readIntent(ctx context.Context, tx *sql.Tx, id domain.IssuanceID) (domain.IssuanceIntent, []byte, error) {
	var data, certificate []byte
	err := tx.QueryRowContext(ctx, "SELECT intent,certificate FROM issuance WHERE id=?", id).Scan(&data, &certificate)
	if err != nil {
		return domain.IssuanceIntent{}, nil, notFound(err)
	}
	intent, err := decode[domain.IssuanceIntent](data)
	if err != nil {
		return intent, nil, err
	}
	if intent.ID != id || !intent.NotAfter.Equal(intent.NotBefore.Add(domain.CertificateLifetime)) || intent.NotBefore.Nanosecond() != 0 {
		return intent, nil, domain.Reject(domain.EvidenceInvalid)
	}
	if err = validateIssuanceAttempt(intent.ID, intent.Serial, intent.CSRHash, intent.PublicKeyHash, intent.NotBefore); err != nil {
		return intent, nil, err
	}
	if err = intent.Credential.Validate(); err != nil {
		return intent, nil, err
	}
	if err = intent.Mode.Validate(); err != nil {
		return intent, nil, err
	}
	return intent, certificate, err
}

func newIntent(id domain.IssuanceID, serial []byte, ref domain.CredentialRef, mode domain.CredentialMode, csr, key domain.Digest, now time.Time) domain.IssuanceIntent {
	start := now.UTC().Truncate(time.Second)
	return domain.IssuanceIntent{ID: id, Serial: bytes.Clone(serial), Credential: ref, Mode: mode, CSRHash: csr, PublicKeyHash: key, NotBefore: start, NotAfter: start.Add(domain.CertificateLifetime)}
}

func persistIntent(ctx context.Context, tx *sql.Tx, replay string, intent domain.IssuanceIntent) (domain.IssuanceIntent, error) {
	data, err := encode(intent)
	if err != nil {
		return domain.IssuanceIntent{}, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO issuance(id,replay,intent) VALUES(?,?,?)", intent.ID, replay, data)
	return intent, err
}

func (s *Store) BeginEnrollment(ctx context.Context, input domain.EnrollmentAttempt) (domain.IssuanceIntent, error) {
	if err := input.TokenHash.Validate(); err != nil {
		return domain.IssuanceIntent{}, err
	}
	if err := validateIssuanceAttempt(input.Issuance, input.Serial, input.CSRHash, input.PublicKeyHash, input.Now); err != nil {
		return domain.IssuanceIntent{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.IssuanceIntent, error) {
		var deviceID domain.DeviceID
		var mode domain.CredentialMode
		var generation uint64
		var expires string
		var existing domain.IssuanceID
		err := tx.QueryRowContext(ctx, "SELECT device,mode,generation,expires,issuance FROM enrollment WHERE token=?", input.TokenHash[:]).Scan(&deviceID, &mode, &generation, &expires, &existing)
		if err != nil {
			return domain.IssuanceIntent{}, notFound(err)
		}
		expiry, err := time.Parse(time.RFC3339Nano, expires)
		if err != nil {
			return domain.IssuanceIntent{}, err
		}
		if existing == "" && !input.Now.Before(expiry) {
			return domain.IssuanceIntent{}, domain.Reject(domain.Expired)
		}
		return reserveEnrollment(ctx, tx, input, deviceID, mode, generation, existing)
	})
}

func reserveEnrollment(ctx context.Context, tx *sql.Tx, input domain.EnrollmentAttempt, id domain.DeviceID, mode domain.CredentialMode, generation uint64, existing domain.IssuanceID) (domain.IssuanceIntent, error) {
	device, err := readDevice(ctx, tx, id)
	if err != nil {
		return domain.IssuanceIntent{}, err
	}
	if device.Revoked || device.CredentialGeneration > generation {
		return domain.IssuanceIntent{}, domain.Reject(domain.Forbidden)
	}
	if existing != "" {
		return matchingIntent(ctx, tx, existing, input.CSRHash, input.PublicKeyHash)
	}
	if generation != device.CredentialGeneration+1 {
		return domain.IssuanceIntent{}, domain.Reject(domain.Conflict)
	}
	var epoch domain.CredentialEpoch
	var blocked bool
	if err = tx.QueryRowContext(ctx, "SELECT epoch,blocked FROM settings WHERE id=1").Scan(&epoch, &blocked); err != nil {
		return domain.IssuanceIntent{}, err
	}
	if blocked && mode != domain.RecoveryOnly {
		if err = allowRegularRecoveryEnrollment(ctx, tx, id, input.Now); err != nil {
			return domain.IssuanceIntent{}, err
		}
	}
	intent := newIntent(input.Issuance, input.Serial, domain.CredentialRef{Device: id, Epoch: epoch, Generation: generation}, mode, input.CSRHash, input.PublicKeyHash, input.Now)
	if _, err = persistIntent(ctx, tx, "enroll:"+hex.EncodeToString(input.TokenHash[:]), intent); err != nil {
		return intent, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE devices SET credential_generation=? WHERE id=?", generation, id); err != nil {
		return intent, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM credentials WHERE device=?", id); err != nil {
		return intent, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE enrollment SET issuance=? WHERE token=?", input.Issuance, input.TokenHash[:])
	return intent, err
}

func matchingIntent(ctx context.Context, tx *sql.Tx, id domain.IssuanceID, csr, key domain.Digest) (domain.IssuanceIntent, error) {
	intent, _, err := readIntent(ctx, tx, id)
	if err != nil {
		return intent, err
	}
	if intent.CSRHash != csr || intent.PublicKeyHash != key {
		return intent, domain.Reject(domain.Conflict)
	}
	return intent, nil
}

func (s *Store) BeginRenewal(ctx context.Context, input domain.RenewalAttempt) (domain.IssuanceIntent, error) {
	if err := input.Credential.Validate(); err != nil {
		return domain.IssuanceIntent{}, err
	}
	if err := domain.Token(string(input.Request)); err != nil {
		return domain.IssuanceIntent{}, err
	}
	if err := validateIssuanceAttempt(input.Issuance, input.Serial, input.CSRHash, input.PublicKeyHash, input.Now); err != nil {
		return domain.IssuanceIntent{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.IssuanceIntent, error) {
		cred, err := credential(ctx, tx, input.Credential, input.Now)
		if err != nil {
			return domain.IssuanceIntent{}, err
		}
		if cred.PublicKeyHash != input.PublicKeyHash {
			return domain.IssuanceIntent{}, domain.Reject(domain.Conflict)
		}
		replayBytes, err := encode(struct {
			Ref     domain.CredentialRef
			Request domain.RequestID
		}{input.Credential, input.Request})
		if err != nil {
			return domain.IssuanceIntent{}, err
		}
		replay := "renew:" + hex.EncodeToString(replayBytes)
		return reserveRenewal(ctx, tx, input, cred, replay)
	})
}

func reserveRenewal(ctx context.Context, tx *sql.Tx, input domain.RenewalAttempt, cred domain.Credential, replay string) (domain.IssuanceIntent, error) {
	var id domain.IssuanceID
	err := tx.QueryRowContext(ctx, "SELECT id FROM issuance WHERE replay=?", replay).Scan(&id)
	if err == nil {
		intent, _, readErr := readIntent(ctx, tx, id)
		if readErr != nil {
			return intent, readErr
		}
		if intent.CSRHash != input.CSRHash || intent.PublicKeyHash != input.PublicKeyHash {
			return intent, domain.Reject(domain.Conflict)
		}
		return intent, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.IssuanceIntent{}, err
	}
	if input.Now.Before(cred.NotBefore.Add(domain.RenewalAfter)) {
		return domain.IssuanceIntent{}, domain.Reject(domain.Forbidden)
	}
	intent := newIntent(input.Issuance, input.Serial, input.Credential, cred.Mode, input.CSRHash, input.PublicKeyHash, input.Now)
	return persistIntent(ctx, tx, replay, intent)
}

func validateCertificate(intent domain.IssuanceIntent, der []byte) error {
	if len(der) == 0 || len(der) > 16<<10 {
		return domain.ErrInvalid
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("certificate receipt: %w", err)
	}
	if certificate.SerialNumber.Cmp(new(big.Int).SetBytes(intent.Serial)) != 0 || !certificate.NotBefore.Equal(intent.NotBefore) || !certificate.NotAfter.Equal(intent.NotAfter) || domain.Hash(certificate.RawSubjectPublicKeyInfo) != intent.PublicKeyHash {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return validateCertificateNames(intent, certificate)
}

func validateCertificateNames(intent domain.IssuanceIntent, certificate *x509.Certificate) error {
	if certificate.IsCA || len(certificate.URIs) != 2 || len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 {
		return domain.Reject(domain.EvidenceInvalid)
	}
	deviceURI := "spiffe://delegation-layer/device/" + string(intent.Credential.Device)
	credentialURI := "urn:delegation-layer:credential:" + string(intent.Credential.Epoch) + ":" + strconv.FormatUint(intent.Credential.Generation, 10)
	if certificate.URIs[0].String() != deviceURI || certificate.URIs[1].String() != credentialURI {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func (s *Store) CompleteIssuance(ctx context.Context, input domain.IssuanceCompletion) (domain.CertificateReceipt, error) {
	if err := domain.Token(string(input.Intent)); err != nil {
		return domain.CertificateReceipt{}, err
	}
	if input.Now.IsZero() {
		return domain.CertificateReceipt{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.CertificateReceipt, error) {
		intent, certificate, err := readIntent(ctx, tx, input.Intent)
		if err != nil {
			return domain.CertificateReceipt{}, err
		}
		if err = validateCertificate(intent, input.CertificateDER); err != nil {
			return domain.CertificateReceipt{}, err
		}
		if len(certificate) > 0 {
			return issuanceReceipt(ctx, tx, intent, certificate, input.Now)
		}
		if _, err = issuanceReceipt(ctx, tx, intent, input.CertificateDER, input.Now); err != nil {
			return domain.CertificateReceipt{}, err
		}
		return activateIssuance(ctx, tx, intent, input.CertificateDER)
	})
}

func issuanceReceipt(ctx context.Context, tx *sql.Tx, intent domain.IssuanceIntent, certificate []byte, now time.Time) (domain.CertificateReceipt, error) {
	if err := validateCertificate(intent, certificate); err != nil {
		return domain.CertificateReceipt{}, err
	}
	device, err := readDevice(ctx, tx, intent.Credential.Device)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	var epoch domain.CredentialEpoch
	if err = tx.QueryRowContext(ctx, "SELECT epoch FROM settings WHERE id=1").Scan(&epoch); err != nil {
		return domain.CertificateReceipt{}, err
	}
	if device.Revoked || epoch != intent.Credential.Epoch || device.CredentialGeneration != intent.Credential.Generation {
		return domain.CertificateReceipt{}, domain.Reject(domain.Forbidden)
	}
	if now.Before(intent.NotBefore) || !now.Before(intent.NotAfter) {
		return domain.CertificateReceipt{}, domain.Reject(domain.Expired)
	}
	return domain.CertificateReceipt{Intent: intent, CertificateDER: certificate}, nil
}

func activateIssuance(ctx context.Context, tx *sql.Tx, intent domain.IssuanceIntent, certificate []byte) (domain.CertificateReceipt, error) {
	credential := domain.Credential{Ref: intent.Credential, Mode: intent.Mode, PublicKeyHash: intent.PublicKeyHash, NotBefore: intent.NotBefore, NotAfter: intent.NotAfter}
	data, err := encode(credential)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	advance, err := credentialValidityAdvances(ctx, tx, credential)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE issuance SET certificate=? WHERE id=?", certificate, intent.ID)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	// Every intent keeps its own immutable receipt. Only a later validity window
	// may replace the same generation's active credential summary.
	if !advance {
		return domain.CertificateReceipt{Intent: intent, CertificateDER: bytes.Clone(certificate)}, nil
	}
	_, err = tx.ExecContext(ctx, "UPDATE devices SET credential_generation=? WHERE id=?", intent.Credential.Generation, intent.Credential.Device)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO credentials(device,epoch,generation,value) VALUES(?,?,?,?) ON CONFLICT(device) DO UPDATE SET epoch=excluded.epoch,generation=excluded.generation,value=excluded.value", intent.Credential.Device, intent.Credential.Epoch, intent.Credential.Generation, data)
	return domain.CertificateReceipt{Intent: intent, CertificateDER: bytes.Clone(certificate)}, err
}

func credentialValidityAdvances(ctx context.Context, tx *sql.Tx, candidate domain.Credential) (bool, error) {
	var data []byte
	err := tx.QueryRowContext(ctx, "SELECT value FROM credentials WHERE device=?", candidate.Ref.Device).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	current, err := decode[domain.Credential](data)
	if err != nil {
		return false, err
	}
	if current.Ref != candidate.Ref || current.Mode != candidate.Mode || current.PublicKeyHash != candidate.PublicKeyHash || !current.NotAfter.After(current.NotBefore) {
		return false, domain.Reject(domain.EvidenceInvalid)
	}
	return candidate.NotAfter.After(current.NotAfter), nil
}

// GetIssuanceReceipt is administrative. Public enrollment/renewal retries must
// prove their token or credential via BeginEnrollment/BeginRenewal first.
func (s *Store) GetIssuanceReceipt(ctx context.Context, id domain.IssuanceID, now time.Time) (domain.CertificateReceipt, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.CertificateReceipt{}, err
	}
	if err := domain.Token(string(id)); err != nil {
		return domain.CertificateReceipt{}, err
	}
	if now.IsZero() {
		return domain.CertificateReceipt{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.CertificateReceipt, error) {
		intent, certificate, err := readIntent(ctx, tx, id)
		if err != nil {
			return domain.CertificateReceipt{}, err
		}
		if len(certificate) == 0 {
			return domain.CertificateReceipt{}, domain.Reject(domain.Pending)
		}
		return issuanceReceipt(ctx, tx, intent, certificate, now)
	})
}
