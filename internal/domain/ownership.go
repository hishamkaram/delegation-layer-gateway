package domain

// OwnerPolicy is Registry authority for newly self-enrolled devices. It never
// becomes a per-project grant, and cannot authorize another device's owner.
type OwnerPolicy struct {
	Enabled    bool
	Scopes     ScopeSet
	Ceiling    DispatchCeiling
	MaxDevices uint32
}

func (p OwnerPolicy) Validate() error {
	if p.MaxDevices == 0 || p.MaxDevices > 100 || len(p.Scopes) == 0 || p.Scopes.Validate() != nil {
		return ErrInvalid
	}
	for _, scope := range p.Scopes {
		if !scope.IsTask() {
			return ErrInvalid
		}
	}
	return p.Ceiling.Validate()
}

// OwnerGrant projects current owner authority into the common authorization
// result. No copy is stored: a policy change applies on the next authorization.
func OwnerGrant(owner PrincipalID, p OwnerPolicy, request AuthorizationRequest) (Grant, error) {
	if p.Validate() != nil || !p.Enabled || request.Validate() != nil || owner != request.Actor.Principal || !p.Scopes.Has(request.Scope) {
		return Grant{}, Reject(NotFound)
	}
	return Grant{Key: GrantKey{Principal: owner, Destination: request.Destination}, Scopes: append(ScopeSet(nil), p.Scopes...), Ceiling: DispatchCeiling{Providers: append([]ProviderID(nil), p.Ceiling.Providers...), Permissions: append([]Permission(nil), p.Ceiling.Permissions...), MaxBudgetSeconds: p.Ceiling.MaxBudgetSeconds}}, nil
}
