package adminapi

import (
	"context"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
)

type OwnedEnrollments interface {
	LookupOwnerPrincipal(context.Context, domain.ExternalSubject) (domain.Principal, error)
	CreateOwnedEnrollment(context.Context, domain.PrincipalID, string, domain.Digest, time.Time) (domain.Device, error)
}

type OwnedEnrollmentInput struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Name    string `json:"name"`
}

func (i OwnedEnrollmentInput) Validate() error {
	if (domain.ExternalSubject{Issuer: i.Issuer, Subject: i.Subject}).Validate() != nil {
		return domain.ErrInvalid
	}
	return domain.ValidateDeviceName(i.Name)
}

func (h *Handler) createOwnedEnrollment(ctx context.Context, input OwnedEnrollmentInput) (Enrollment, error) {
	if err := input.Validate(); err != nil {
		return Enrollment{}, err
	}
	if h.options.OwnedEnrollments == nil {
		return Enrollment{}, domain.Reject(domain.NotFound)
	}
	principal, err := h.options.OwnedEnrollments.LookupOwnerPrincipal(ctx, domain.ExternalSubject{Issuer: input.Issuer, Subject: input.Subject})
	if err != nil {
		return Enrollment{}, err
	}
	select {
	case h.entropy <- struct{}{}:
		defer func() { <-h.entropy }()
	case <-ctx.Done():
		return Enrollment{}, ctx.Err()
	}
	token, hash, err := enrollment.NewToken(h.options.Random)
	if err != nil {
		return Enrollment{}, err
	}
	now := h.options.Now()
	device, err := h.options.OwnedEnrollments.CreateOwnedEnrollment(ctx, principal.ID, input.Name, hash, now)
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{Token: token, DeviceID: string(device.ID), ExpiresAt: now.Add(domain.EnrollmentTTL)}, nil
}
