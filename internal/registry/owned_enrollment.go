package registry

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// LookupOwnerPrincipal is private, read-only selection of an already eligible
// identity. Token creation cannot materialize a different issuer/subject.
func (s *Store) LookupOwnerPrincipal(ctx context.Context, subject domain.ExternalSubject) (domain.Principal, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.Principal{}, err
	}
	if err := subject.Validate(); err != nil {
		return domain.Principal{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.Principal, error) {
		principal := domain.Principal{Subject: subject}
		err := tx.QueryRowContext(ctx, "SELECT id,revoked FROM principals WHERE issuer=? AND subject=?", subject.Issuer, subject.Subject).Scan(&principal.ID, &principal.Revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Principal{}, domain.Reject(domain.Forbidden)
		}
		if err != nil {
			return domain.Principal{}, err
		}
		_, err = ownerPolicy(ctx, tx, principal.ID)
		return principal, err
	})
}

// CreateOwnedEnrollment is private first-device bootstrap. Registry alone
// generates the new identity and commits ownership with its one-device token
// grant. It cannot adopt an existing device or grant a user eligibility.
func (s *Store) CreateOwnedEnrollment(ctx context.Context, owner domain.PrincipalID, name string, tokenHash domain.Digest, now time.Time) (domain.Device, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.Device{}, err
	}
	if domain.Token(string(owner)) != nil || domain.ValidateDeviceName(name) != nil || tokenHash.Validate() != nil || now.IsZero() {
		return domain.Device{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.Device, error) {
		if err := admissionsOpen(ctx, tx); err != nil {
			return domain.Device{}, err
		}
		policy, err := ownerPolicy(ctx, tx, owner)
		if err != nil {
			return domain.Device{}, err
		}
		device, err := mintOwnedDevice(ctx, tx, owner, name, policy, now)
		if err != nil {
			return domain.Device{}, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO enrollment(token,device,mode,generation,created,expires) VALUES(?,?,'regular',1,?,?)", tokenHash[:], device.ID, now.UTC().Format(timestampLayout), now.Add(domain.EnrollmentTTL).UTC().Format(timestampLayout))
		return device, err
	})
}
