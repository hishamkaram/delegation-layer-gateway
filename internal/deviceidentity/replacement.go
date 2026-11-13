package deviceidentity

import (
	"bytes"
	"crypto/x509"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
)

// replacementRecord is only a local CAS retry receipt. It is not evidence that
// an older renewal completed or that the registry accepted an older credential.
type replacementRecord struct {
	Prior             credentialRecord `json:"prior"`
	CertificateSHA256 domain.Digest    `json:"certificate_sha256"`
}

// StoredCredentialRef reads the local record for explicit operator replacement,
// including expired/revoked records. It must never authenticate a connection;
// Certificate(roots, now) and the Gateway registry own those validity checks.
func (s *Store) StoredCredentialRef() (domain.CredentialRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr := s.check(); checkErr != nil {
		return domain.CredentialRef{}, checkErr
	}
	return s.state.credential()
}

func (r record) credential() (domain.CredentialRef, error) {
	if len(r.CertificateDER) == 0 {
		return domain.CredentialRef{}, ErrAbsent
	}
	leaf, parseErr := x509.ParseCertificate(r.CertificateDER)
	if parseErr != nil {
		return domain.CredentialRef{}, ErrInvalid
	}
	ref, refErr := identity.CredentialFromCertificate(leaf)
	if refErr != nil {
		return domain.CredentialRef{}, ErrInvalid
	}
	return ref, nil
}

// ReplaceEnrollment is an explicit operator CAS, never a Run/renewal fallback.
// Its caller must first authenticate a new TLS enrollment response/new token.
// Epochs are opaque: same-epoch replacement advances generation; a different
// epoch is accepted only through this explicit path without ordering its number.
func (s *Store) ReplaceEnrollment(der []byte, expectedPrior, expectedNew domain.CredentialRef, roots *x509.CertPool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr := s.check(); checkErr != nil {
		return checkErr
	}
	if expectedPrior.Validate() != nil || expectedNew.Validate() != nil || !replacementAllowed(expectedPrior, expectedNew) {
		return ErrConflict
	}
	current, currentErr := s.state.credential()
	if currentErr != nil {
		return currentErr
	}
	key, keyErr := s.state.key()
	if keyErr != nil {
		return keyErr
	}
	if _, verifyErr := verifyCertificate(der, key, expectedNew, roots, now); verifyErr != nil {
		return verifyErr
	}
	if current == expectedNew && bytes.Equal(s.state.CertificateDER, der) {
		receipt := s.state.Replacement
		if receipt != nil && receipt.Prior.value() == expectedPrior && receipt.CertificateSHA256 == domain.Hash(der) {
			return nil
		}
		return ErrConflict
	}
	if current != expectedPrior {
		return ErrConflict
	}
	next := s.state
	next.CertificateDER = bytes.Clone(der)
	next.Renewal = nil
	next.CompletedRenewalID = ""
	next.Replacement = &replacementRecord{Prior: storedCredential(expectedPrior), CertificateSHA256: domain.Hash(der)}
	return s.commit(next)
}

func replacementAllowed(prior, next domain.CredentialRef) bool {
	if prior.Device != next.Device {
		return false
	}
	return prior.Epoch != next.Epoch || next.Generation > prior.Generation
}

func (r record) validReplacement(current domain.CredentialRef) error {
	receipt := r.Replacement
	if receipt == nil {
		return nil
	}
	prior := receipt.Prior.value()
	if prior.Validate() != nil || !replacementAllowed(prior, current) || receipt.CertificateSHA256 != domain.Hash(r.CertificateDER) {
		return ErrInvalid
	}
	return nil
}
