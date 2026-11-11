// Package enrollment composes strict CSR validation, durable issuance intents
// and certificate signing. Registry alone owns redemption and active identity.
package enrollment

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
)

type Store interface {
	BeginEnrollment(context.Context, domain.EnrollmentAttempt) (domain.IssuanceIntent, error)
	BeginRenewal(context.Context, domain.RenewalAttempt) (domain.IssuanceIntent, error)
	CompleteIssuance(context.Context, domain.IssuanceCompletion) (domain.CertificateReceipt, error)
}
type Signer interface {
	Sign(context.Context, domain.IssuanceIntent, []byte, *big.Int, io.Reader) ([]byte, error)
}
type Service struct {
	store  Store
	signer Signer
	random io.Reader
	now    func() time.Time
}

func New(store Store, signer Signer, random io.Reader, now func() time.Time) (*Service, error) {
	if store == nil || signer == nil || random == nil || now == nil {
		return nil, domain.ErrInvalid
	}
	return &Service{store: store, signer: signer, random: random, now: now}, nil
}

// Redeem binds one token to the exact CSR. Repeated requests pass the same proof
// through the registry, which returns the first persisted intent and receipt.
func (s *Service) Redeem(ctx context.Context, token string, csrDER []byte) (domain.CertificateReceipt, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return domain.CertificateReceipt{}, domain.Reject(domain.Forbidden)
	}
	csr, err := identity.ParseCSR(csrDER)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	id, serial, err := s.candidate(ctx)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	intent, err := s.store.BeginEnrollment(ctx, domain.EnrollmentAttempt{TokenHash: domain.Hash(decoded), CSRHash: csr.CSRHash, PublicKeyHash: csr.PublicKeyHash, Issuance: id, Serial: serial, Now: s.now()})
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	return s.complete(ctx, intent, csrDER)
}

// Renew receives a credential already checked on the authenticated device
// connection. Registry rechecks current epoch, revocation and renewal age.
func (s *Service) Renew(ctx context.Context, credential domain.CredentialRef, request domain.RequestID, csrDER []byte) (domain.CertificateReceipt, error) {
	if credential.Validate() != nil || domain.Token(string(request)) != nil {
		return domain.CertificateReceipt{}, domain.ErrInvalid
	}
	csr, err := identity.ParseCSR(csrDER)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	id, serial, err := s.candidate(ctx)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	intent, err := s.store.BeginRenewal(ctx, domain.RenewalAttempt{Credential: credential, Request: request, CSRHash: csr.CSRHash, PublicKeyHash: csr.PublicKeyHash, Issuance: id, Serial: serial, Now: s.now()})
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	return s.complete(ctx, intent, csrDER)
}

func (s *Service) candidate(ctx context.Context) (domain.IssuanceID, []byte, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	var entropy [32]byte
	if _, err := io.ReadFull(s.random, entropy[:]); err != nil {
		return "", nil, fmt.Errorf("issuance entropy unavailable: %w", err)
	}
	serial := append([]byte(nil), entropy[16:]...)
	serial[0] = (serial[0] & 0x7f) | 1
	return domain.IssuanceID(hex.EncodeToString(entropy[:16])), serial, nil
}

func (s *Service) complete(ctx context.Context, intent domain.IssuanceIntent, csrDER []byte) (domain.CertificateReceipt, error) {
	certificate, err := s.signer.Sign(ctx, intent, csrDER, new(big.Int).SetBytes(intent.Serial), s.random)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	return s.store.CompleteIssuance(ctx, domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: certificate, Now: s.now()})
}

// NewToken is called only through the local administrative service. The raw
// token is returned once for controlled stdin/file delivery; only its hash is
// persisted. The caller must never include it in logs or process arguments.
func NewToken(random io.Reader) (string, domain.Digest, error) {
	if random == nil {
		return "", domain.Digest{}, domain.ErrInvalid
	}
	var secret [32]byte
	if _, err := io.ReadFull(random, secret[:]); err != nil {
		return "", domain.Digest{}, errors.New("enrollment entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(secret[:]), domain.Hash(secret[:]), nil
}
