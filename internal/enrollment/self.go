package enrollment

import (
	"context"
	"io"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// SelfStore accepts only a verified actor and owns reservation, eligibility,
// replay and activation. It cannot manufacture private administrative authority.
type SelfStore interface {
	BeginSelfEnrollment(context.Context, domain.Actor, domain.SelfEnrollmentAttempt) (domain.IssuanceIntent, error)
	CompleteIssuance(context.Context, domain.IssuanceCompletion) (domain.CertificateReceipt, error)
}

type SelfService struct {
	store SelfStore
	*issuer
}

func NewSelf(store SelfStore, signer Signer, random io.Reader, now func() time.Time) (*SelfService, error) {
	if store == nil || signer == nil || random == nil || now == nil {
		return nil, domain.ErrInvalid
	}
	return &SelfService{store: store, issuer: &issuer{store: store, signer: signer, random: random, now: now}}, nil
}

// SelfEnroll derives hashes from the exact validated CSR and reserves with the
// caller's immutable request identity. It never mints a bearer enrollment token.
func (s *SelfService) SelfEnroll(ctx context.Context, actor domain.Actor, request domain.RequestID, name string, csrDER []byte, replace domain.DeviceID, expectedGeneration uint64) (domain.CertificateReceipt, error) {
	if ctx == nil || actor.Validate() != nil || domain.TaskID(request).Validate() != nil || domain.ValidateDeviceName(name) != nil {
		return domain.CertificateReceipt{}, domain.ErrInvalid
	}
	if !actor.Scopes.Has(domain.DeviceEnroll) || (replace != "" && !actor.Scopes.Has(domain.DeviceManage)) {
		return domain.CertificateReceipt{}, domain.Reject(domain.Forbidden)
	}
	csr, err := devicecert.ParseCSR(csrDER)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	id, serial, err := s.candidate(ctx)
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	intent, err := s.store.BeginSelfEnrollment(ctx, actor, domain.SelfEnrollmentAttempt{
		Request: request, Name: name, ReplaceDevice: replace, ExpectedGeneration: expectedGeneration,
		CSRHash: csr.CSRHash, PublicKeyHash: csr.PublicKeyHash, Issuance: id, Serial: serial, Now: s.now(),
	})
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	return s.complete(ctx, intent, csrDER)
}
