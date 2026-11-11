package deviceidentity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
)

type RenewalIntent struct {
	ID         string
	Credential domain.CredentialRef
	CSRDER     []byte
}

type record struct {
	Replacement        *replacementRecord `json:"replacement,omitempty"`
	Version            int                `json:"version"`
	KeyDER             []byte             `json:"key_der"`
	CSRDER             []byte             `json:"csr_der"`
	CertificateDER     []byte             `json:"certificate_der,omitempty"`
	Renewal            *renewalRecord     `json:"renewal,omitempty"`
	CompletedRenewalID string             `json:"completed_renewal_id,omitempty"`
}

type renewalRecord struct {
	ID         string           `json:"id"`
	Credential credentialRecord `json:"credential"`
	CSRDER     []byte           `json:"csr_der"`
}

type credentialRecord struct {
	Device     domain.DeviceID        `json:"device"`
	Epoch      domain.CredentialEpoch `json:"epoch"`
	Generation uint64                 `json:"generation"`
}

func storedCredential(ref domain.CredentialRef) credentialRecord {
	return credentialRecord{Device: ref.Device, Epoch: ref.Epoch, Generation: ref.Generation}
}

func (r credentialRecord) value() domain.CredentialRef {
	return domain.CredentialRef{Device: r.Device, Epoch: r.Epoch, Generation: r.Generation}
}

func (r record) key() (*ecdsa.PrivateKey, error) {
	parsed, parseErr := x509.ParsePKCS8PrivateKey(r.KeyDER)
	if parseErr != nil {
		return nil, ErrInvalid
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrInvalid
	}
	return key, nil
}

func (r record) valid() error {
	if r.Version != 1 || len(r.KeyDER) > 1024 || len(r.CertificateDER) > 64<<10 {
		return ErrInvalid
	}
	key, keyErr := r.key()
	if keyErr != nil {
		return keyErr
	}
	if csrMatches(r.CSRDER, key) != nil {
		return ErrInvalid
	}
	if r.CompletedRenewalID != "" && !renewalID(r.CompletedRenewalID) {
		return ErrInvalid
	}
	if len(r.CertificateDER) == 0 {
		if r.Renewal != nil || r.CompletedRenewalID != "" || r.Replacement != nil {
			return ErrInvalid
		}
		return nil
	}
	return r.validCertificate(key)
}

func (r record) validCertificate(key *ecdsa.PrivateKey) error {
	leaf, parseErr := x509.ParseCertificate(r.CertificateDER)
	if parseErr != nil || !keyMatches(leaf, key) {
		return ErrInvalid
	}
	ref, refErr := identity.CredentialFromCertificate(leaf)
	if refErr != nil {
		return ErrInvalid
	}
	if replacementErr := r.validReplacement(ref); replacementErr != nil {
		return replacementErr
	}
	if r.Renewal != nil {
		if !renewalID(r.Renewal.ID) || r.Renewal.Credential.value() != ref || csrMatches(r.Renewal.CSRDER, key) != nil {
			return ErrInvalid
		}
	}
	return nil
}

func csrMatches(csr []byte, key *ecdsa.PrivateKey) error {
	info, parseErr := identity.ParseCSR(csr)
	if parseErr != nil {
		return ErrInvalid
	}
	public, marshalErr := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if marshalErr != nil || info.PublicKeyHash != domain.Hash(public) {
		return ErrInvalid
	}
	return nil
}

func keyMatches(leaf *x509.Certificate, key *ecdsa.PrivateKey) bool {
	if leaf == nil {
		return false
	}
	public, marshalErr := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return marshalErr == nil && bytes.Equal(public, leaf.RawSubjectPublicKeyInfo)
}

func renewalID(value string) bool {
	decoded, decodeErr := hex.DecodeString(value)
	return decodeErr == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}

func (s *Store) EnsureKey(random io.Reader) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr := s.check(); checkErr != nil {
		return nil, checkErr
	}
	if len(s.state.KeyDER) != 0 {
		return bytes.Clone(s.state.CSRDER), nil
	}
	if random == nil {
		return nil, ErrInvalid
	}
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), random)
	if keyErr != nil {
		return nil, failed(ErrInvalid, keyErr)
	}
	encoded, marshalErr := x509.MarshalPKCS8PrivateKey(key)
	if marshalErr != nil {
		return nil, failed(ErrInvalid, marshalErr)
	}
	csr, csrErr := x509.CreateCertificateRequest(random, &x509.CertificateRequest{}, key)
	if csrErr != nil {
		return nil, failed(ErrInvalid, csrErr)
	}
	next := record{Version: 1, KeyDER: encoded, CSRDER: csr}
	if commitErr := s.commit(next); commitErr != nil {
		return nil, commitErr
	}
	return bytes.Clone(csr), nil
}

func verifyCertificate(der []byte, key *ecdsa.PrivateKey, expected domain.CredentialRef, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if roots == nil || now.IsZero() || expected.Validate() != nil || len(der) == 0 || len(der) > 64<<10 {
		return nil, ErrInvalid
	}
	leaf, parseErr := x509.ParseCertificate(der)
	if parseErr != nil || !keyMatches(leaf, key) {
		return nil, ErrInvalid
	}
	ref, refErr := identity.CredentialFromCertificate(leaf)
	if refErr != nil || ref != expected || leaf.NotAfter.Sub(leaf.NotBefore) != domain.CertificateLifetime || leaf.SerialNumber.Sign() <= 0 || len(leaf.SerialNumber.Bytes()) > 20 {
		return nil, ErrInvalid
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if verifyErr != nil {
		return nil, failed(ErrInvalid, verifyErr)
	}
	return leaf, nil
}

func (s *Store) Certificate(roots *x509.CertPool, now time.Time) (tls.Certificate, domain.CredentialRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr := s.check(); checkErr != nil {
		return tls.Certificate{}, domain.CredentialRef{}, checkErr
	}
	if len(s.state.CertificateDER) == 0 {
		return tls.Certificate{}, domain.CredentialRef{}, ErrAbsent
	}
	key, keyErr := s.state.key()
	if keyErr != nil {
		return tls.Certificate{}, domain.CredentialRef{}, keyErr
	}
	parsed, parseErr := x509.ParseCertificate(s.state.CertificateDER)
	if parseErr != nil {
		return tls.Certificate{}, domain.CredentialRef{}, ErrInvalid
	}
	ref, refErr := identity.CredentialFromCertificate(parsed)
	if refErr != nil {
		return tls.Certificate{}, domain.CredentialRef{}, ErrInvalid
	}
	leaf, verifyErr := verifyCertificate(s.state.CertificateDER, key, ref, roots, now)
	if verifyErr != nil {
		return tls.Certificate{}, domain.CredentialRef{}, verifyErr
	}
	certificate := tls.Certificate{Certificate: [][]byte{bytes.Clone(s.state.CertificateDER)}, PrivateKey: key, Leaf: leaf}
	return certificate, ref, nil
}

func (s *Store) InstallEnrollment(der []byte, expected domain.CredentialRef, roots *x509.CertPool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr := s.check(); checkErr != nil {
		return checkErr
	}
	if s.state.Renewal != nil {
		return ErrConflict
	}
	key, keyErr := s.state.key()
	if keyErr != nil {
		return keyErr
	}
	if _, verifyErr := verifyCertificate(der, key, expected, roots, now); verifyErr != nil {
		return verifyErr
	}
	if len(s.state.CertificateDER) != 0 {
		if bytes.Equal(s.state.CertificateDER, der) {
			return nil
		}
		return ErrConflict
	}
	next := s.state
	next.CertificateDER = bytes.Clone(der)
	return s.commit(next)
}

func (s *Store) BeginRenewal(expected domain.CredentialRef, random io.Reader) (RenewalIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr := s.check(); checkErr != nil {
		return RenewalIntent{}, checkErr
	}
	if len(s.state.CertificateDER) == 0 {
		return RenewalIntent{}, ErrAbsent
	}
	leaf, parseErr := x509.ParseCertificate(s.state.CertificateDER)
	if parseErr != nil {
		return RenewalIntent{}, ErrInvalid
	}
	ref, refErr := identity.CredentialFromCertificate(leaf)
	if refErr != nil || ref != expected {
		return RenewalIntent{}, ErrConflict
	}
	if s.state.Renewal != nil {
		return s.pending(), nil
	}
	if random == nil {
		return RenewalIntent{}, ErrInvalid
	}
	key, keyErr := s.state.key()
	if keyErr != nil {
		return RenewalIntent{}, keyErr
	}
	id := make([]byte, 16)
	if _, readErr := io.ReadFull(random, id); readErr != nil {
		return RenewalIntent{}, failed(ErrInvalid, readErr)
	}
	csr, csrErr := x509.CreateCertificateRequest(random, &x509.CertificateRequest{}, key)
	if csrErr != nil {
		return RenewalIntent{}, failed(ErrInvalid, csrErr)
	}
	next := s.state
	next.Renewal = &renewalRecord{ID: hex.EncodeToString(id), Credential: storedCredential(expected), CSRDER: csr}
	if commitErr := s.commit(next); commitErr != nil {
		return RenewalIntent{}, commitErr
	}
	return s.pending(), nil
}

func (s *Store) pending() RenewalIntent {
	if s.state.Renewal == nil {
		return RenewalIntent{}
	}
	r := s.state.Renewal
	return RenewalIntent{ID: r.ID, Credential: r.Credential.value(), CSRDER: bytes.Clone(r.CSRDER)}
}

func (s *Store) PendingRenewal() (RenewalIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr := s.check(); checkErr != nil {
		return RenewalIntent{}, checkErr
	}
	if s.state.Renewal == nil {
		return RenewalIntent{}, ErrAbsent
	}
	return s.pending(), nil
}

func (s *Store) CompleteRenewal(id string, der []byte, roots *x509.CertPool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr := s.check(); checkErr != nil {
		return checkErr
	}
	if s.state.Renewal == nil {
		if renewalID(id) && id == s.state.CompletedRenewalID && bytes.Equal(der, s.state.CertificateDER) {
			return nil
		}
		return ErrConflict
	}
	pending := s.state.Renewal
	if id != pending.ID {
		return ErrConflict
	}
	key, keyErr := s.state.key()
	if keyErr != nil {
		return keyErr
	}
	if _, verifyErr := verifyCertificate(der, key, pending.Credential.value(), roots, now); verifyErr != nil {
		return verifyErr
	}
	next := s.state
	next.CertificateDER = bytes.Clone(der)
	next.CSRDER = bytes.Clone(pending.CSRDER)
	next.Renewal = nil
	next.CompletedRenewalID = id
	next.Replacement = nil
	return s.commit(next)
}
