package adminapi

import (
	"context"
	"net/http"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// OwnerPolicies is private eligibility administration, never an OAuth scope or
// a public enrollment capability. Registry remains the only mutable authority.
type OwnerPolicies interface {
	PutOwnerPolicy(context.Context, domain.PrincipalID, domain.OwnerPolicy) error
	ReadOwnerPolicy(context.Context, domain.PrincipalID) (domain.OwnerPolicy, error)
	DisableOwnerPolicy(context.Context, domain.PrincipalID) error
}

type OwnerPolicyInput struct {
	Issuer           string              `json:"issuer"`
	Subject          string              `json:"subject"`
	Scopes           domain.ScopeSet     `json:"scopes"`
	Providers        []domain.ProviderID `json:"providers"`
	Permissions      []domain.Permission `json:"permissions"`
	MaxBudgetSeconds uint32              `json:"max_budget_seconds"`
	MaxDevices       uint32              `json:"max_devices"`
}

func (i OwnerPolicyInput) Policy() domain.OwnerPolicy {
	return domain.OwnerPolicy{Enabled: true, Scopes: i.Scopes, Ceiling: domain.DispatchCeiling{Providers: i.Providers, Permissions: i.Permissions, MaxBudgetSeconds: i.MaxBudgetSeconds}, MaxDevices: i.MaxDevices}
}

func (i OwnerPolicyInput) Validate() error {
	if (domain.ExternalSubject{Issuer: i.Issuer, Subject: i.Subject}).Validate() != nil {
		return domain.ErrInvalid
	}
	return i.Policy().Validate()
}

type OwnerPolicyView struct {
	PrincipalID string           `json:"principal_id"`
	Enabled     bool             `json:"enabled"`
	Policy      OwnerPolicyInput `json:"policy"`
}

func (v OwnerPolicyView) Validate() error {
	if domain.Token(v.PrincipalID) != nil {
		return domain.ErrInvalid
	}
	return v.Policy.Validate()
}

func (h *Handler) ownerPolicyRoute(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/v1/users/allow":
		serve(w, r, http.MethodPost, h.allowOwner)
	case "/v1/users/show":
		serve(w, r, http.MethodPost, h.showOwner)
	case "/v1/users/disable":
		serve(w, r, http.MethodPost, h.disableOwner)
	default:
		return false
	}
	return true
}

func (h *Handler) ownerPrincipal(ctx context.Context, input ResolvePrincipalInput) (domain.Principal, error) {
	if h.options.OwnerPolicies == nil {
		return domain.Principal{}, domain.Reject(domain.NotFound)
	}
	return h.options.Store.ResolvePrincipal(ctx, domain.ExternalSubject{Issuer: input.Issuer, Subject: input.Subject})
}

func (h *Handler) allowOwner(ctx context.Context, input OwnerPolicyInput) (OwnerPolicyView, error) {
	if err := input.Validate(); err != nil {
		return OwnerPolicyView{}, err
	}
	principal, err := h.ownerPrincipal(ctx, ResolvePrincipalInput{Issuer: input.Issuer, Subject: input.Subject})
	if err != nil {
		return OwnerPolicyView{}, err
	}
	if err = h.options.OwnerPolicies.PutOwnerPolicy(ctx, principal.ID, input.Policy()); err != nil {
		return OwnerPolicyView{}, err
	}
	return OwnerPolicyView{PrincipalID: string(principal.ID), Enabled: true, Policy: input}, nil
}

func (h *Handler) showOwner(ctx context.Context, input ResolvePrincipalInput) (OwnerPolicyView, error) {
	principal, err := h.ownerPrincipal(ctx, input)
	if err != nil {
		return OwnerPolicyView{}, err
	}
	policy, err := h.options.OwnerPolicies.ReadOwnerPolicy(ctx, principal.ID)
	if err != nil {
		return OwnerPolicyView{}, err
	}
	return OwnerPolicyView{PrincipalID: string(principal.ID), Enabled: policy.Enabled, Policy: OwnerPolicyInput{Issuer: input.Issuer, Subject: input.Subject, Scopes: policy.Scopes, Providers: policy.Ceiling.Providers, Permissions: policy.Ceiling.Permissions, MaxBudgetSeconds: policy.Ceiling.MaxBudgetSeconds, MaxDevices: policy.MaxDevices}}, nil
}

func (h *Handler) disableOwner(ctx context.Context, input ResolvePrincipalInput) (Mutation, error) {
	principal, err := h.ownerPrincipal(ctx, input)
	if err != nil {
		return Mutation{}, err
	}
	err = h.options.OwnerPolicies.DisableOwnerPolicy(ctx, principal.ID)
	return Mutation{Committed: err == nil}, err
}
