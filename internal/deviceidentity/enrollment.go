package deviceidentity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// EnrollmentPlan binds a durable request to one Gateway and exact caller intent.
// Token enrollment has a known Device; self enrollment allocates it remotely.
type EnrollmentPlan struct {
	GatewayID   string
	Name        string
	TokenDevice domain.DeviceID
	TokenSHA256 domain.Digest
	Prior       domain.CredentialRef
}
type EnrollmentIntent struct {
	Plan           EnrollmentPlan
	RequestID      string
	CSRDER         []byte
	Completed      bool
	OwnerPrincipal string
}
type enrollmentRecord struct {
	GatewayID   string            `json:"gateway_id"`
	Name        string            `json:"name"`
	TokenDevice domain.DeviceID   `json:"token_device,omitempty"`
	TokenSHA256 domain.Digest     `json:"token_sha256,omitempty"`
	Prior       *credentialRecord `json:"prior,omitempty"`
	RequestID   string            `json:"request_id"`
	CSRDER      []byte            `json:"csr_der"`
	Completed   bool              `json:"completed"`
}

func (r *enrollmentRecord) plan() EnrollmentPlan {
	p := EnrollmentPlan{GatewayID: r.GatewayID, Name: r.Name, TokenDevice: r.TokenDevice, TokenSHA256: r.TokenSHA256}
	if r.Prior != nil {
		p.Prior = r.Prior.value()
	}
	return p
}

func (p EnrollmentPlan) Validate() error {
	if domain.Token(p.GatewayID) != nil || domain.ValidateDeviceName(p.Name) != nil || strings.TrimSpace(p.Name) != p.Name {
		return ErrInvalid
	}
	if p.TokenDevice != "" {
		if domain.Token(string(p.TokenDevice)) != nil || p.TokenSHA256.Validate() != nil {
			return ErrInvalid
		}
	} else if p.TokenSHA256 != (domain.Digest{}) {
		return ErrInvalid
	}
	if p.Prior == (domain.CredentialRef{}) {
		return nil
	}
	if p.Prior.Validate() != nil || (p.TokenDevice != "" && p.TokenDevice != p.Prior.Device) {
		return ErrInvalid
	}
	return nil
}

func (r record) validEnrollment(key *ecdsa.PrivateKey) error {
	e := r.Enrollment
	if e == nil {
		return nil
	}
	if e.plan().Validate() != nil || !renewalID(e.RequestID) || csrMatches(e.CSRDER, key) != nil {
		return ErrInvalid
	}
	if r.OwnerPrincipal != "" && domain.Token(r.OwnerPrincipal) != nil {
		return ErrInvalid
	}
	if !e.Completed {
		return nil
	}
	if len(r.CertificateDER) == 0 || !e.acceptsOwner(r.OwnerPrincipal) {
		return ErrInvalid
	}
	ref, err := r.credential()
	if err != nil || !e.acceptsDevice(ref.Device) {
		return ErrInvalid
	}

	return nil
}

func (e *enrollmentRecord) acceptsOwner(owner string) bool {
	if e.TokenDevice == "" {
		return domain.Token(owner) == nil
	}
	return owner == ""
}

func (e *enrollmentRecord) acceptsDevice(device domain.DeviceID) bool {
	if e.TokenDevice != "" && device != e.TokenDevice {
		return false
	}
	return e.Prior == nil || device == e.Prior.Device
}

func (s *Store) enrollmentIntent() EnrollmentIntent {
	r := s.state.Enrollment
	if r == nil {
		return EnrollmentIntent{}
	}
	return EnrollmentIntent{Plan: r.plan(), RequestID: r.RequestID, CSRDER: bytes.Clone(r.CSRDER), Completed: r.Completed, OwnerPrincipal: s.state.OwnerPrincipal}
}

func (s *Store) EnrollmentIntent() (EnrollmentIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return EnrollmentIntent{}, err
	}
	if s.state.Enrollment == nil {
		return EnrollmentIntent{}, ErrAbsent
	}
	return s.enrollmentIntent(), nil
}

// BeginEnrollment commits the immutable request before any network redemption.
// Pending retries must have the exact same plan; replacement needs explicit CAS.
func (s *Store) BeginEnrollment(plan EnrollmentPlan, random io.Reader) (EnrollmentIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return EnrollmentIntent{}, err
	}
	if plan.Validate() != nil || random == nil || len(s.state.CSRDER) == 0 {
		return EnrollmentIntent{}, ErrInvalid
	}
	reuse, err := s.state.checkEnrollmentPlan(plan)
	if err != nil {
		return EnrollmentIntent{}, err
	}
	if reuse {
		return s.enrollmentIntent(), nil
	}

	id := make([]byte, 16)
	if _, err = io.ReadFull(random, id); err != nil {
		return EnrollmentIntent{}, failed(ErrInvalid, err)
	}
	next := s.state
	next.Version = 2
	next.Enrollment = &enrollmentRecord{GatewayID: plan.GatewayID, Name: plan.Name, TokenDevice: plan.TokenDevice, TokenSHA256: plan.TokenSHA256, RequestID: hex.EncodeToString(id), CSRDER: bytes.Clone(s.state.CSRDER)}
	if plan.Prior != (domain.CredentialRef{}) {
		prior := storedCredential(plan.Prior)
		next.Enrollment.Prior = &prior
	}
	if err = s.commit(next); err != nil {
		return EnrollmentIntent{}, err
	}
	return s.enrollmentIntent(), nil
}

func (r record) checkEnrollmentPlan(plan EnrollmentPlan) (bool, error) {
	if old := r.Enrollment; old != nil {
		if old.GatewayID != plan.GatewayID || old.Name != plan.Name {
			return false, ErrConflict
		}
		if !old.Completed {
			if old.plan() != plan {
				return false, ErrConflict
			}
			return true, nil
		}
	}
	current, err := r.credential()
	if plan.Prior == (domain.CredentialRef{}) {
		if err == nil {
			return false, ErrConflict
		}
		if !errors.Is(err, ErrAbsent) {
			return false, err
		}
		return false, nil
	}
	if err != nil || current != plan.Prior {
		return false, ErrConflict
	}
	return false, nil
}

// CompleteEnrollment verifies and atomically installs the certificate, verified
// owner and retry receipt. Token enrollment deliberately retains unknown owner.
func (s *Store) CompleteEnrollment(id, owner string, der []byte, expected domain.CredentialRef, roots *x509.CertPool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return err
	}
	e := s.state.Enrollment
	if e == nil || e.RequestID != id || expected.Validate() != nil || !e.acceptsOwner(owner) || !e.acceptsDevice(expected.Device) {
		return ErrConflict
	}
	if e.Completed {
		return s.state.matchCompletedEnrollment(owner, der, expected)
	}
	if e.TokenDevice == "" && s.state.OwnerPrincipal != "" && owner != s.state.OwnerPrincipal {
		return ErrConflict
	}

	key, err := s.state.key()
	if err != nil {
		return err
	}
	if _, err = verifyCertificate(der, key, expected, roots, now); err != nil {
		return err
	}
	next := s.state
	next.Replacement, err = s.state.enrollmentReplacement(der, expected)
	if err != nil {
		return err
	}

	next.CertificateDER = bytes.Clone(der)
	next.Renewal = nil
	next.CompletedRenewalID = ""
	completed := *e
	completed.Completed = true
	next.OwnerPrincipal = owner
	next.Enrollment = &completed
	return s.commit(next)
}

func (r record) matchCompletedEnrollment(owner string, der []byte, expected domain.CredentialRef) error {
	current, err := r.credential()
	if err == nil && current == expected && r.OwnerPrincipal == owner && bytes.Equal(der, r.CertificateDER) {
		return nil
	}
	return ErrConflict
}

func (r record) enrollmentReplacement(der []byte, expected domain.CredentialRef) (*replacementRecord, error) {
	prior := r.Enrollment.Prior
	if prior == nil {
		if len(r.CertificateDER) != 0 {
			return nil, ErrConflict
		}
		return nil, nil
	}
	current, err := r.credential()
	if err != nil || current != prior.value() || !replacementAllowed(prior.value(), expected) {
		return nil, ErrConflict
	}
	return &replacementRecord{Prior: *prior, CertificateSHA256: domain.Hash(der)}, nil
}

// CredentialMetadata is a local observation; it never authenticates a session.
func (s *Store) CredentialMetadata() (domain.CredentialRef, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return domain.CredentialRef{}, time.Time{}, err
	}
	ref, err := s.state.credential()
	if err != nil {
		return domain.CredentialRef{}, time.Time{}, err
	}
	cert, err := x509.ParseCertificate(s.state.CertificateDER)
	if err != nil {
		return domain.CredentialRef{}, time.Time{}, ErrInvalid
	}
	return ref, cert.NotAfter, nil
}
