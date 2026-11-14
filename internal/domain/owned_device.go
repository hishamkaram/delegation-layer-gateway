package domain

// OwnedDeviceAuthorization contains a fresh policy projection, not a retained
// execution grant. Each subsequent send/response must recheck its authority.
type OwnedDeviceAuthorization struct {
	Principal PrincipalID
	Device    Device
	Policy    OwnerPolicy
}

type OwnedDeviceRequest struct {
	Actor  Actor
	Device DeviceID
	Scope  Scope
}

func (r OwnedDeviceRequest) Validate() error {
	if r.Actor.Validate() != nil || CredentialToken(string(r.Device)) != nil || !r.Scope.IsTask() {
		return ErrInvalid
	}
	if !r.Actor.Scopes.Has(r.Scope) {
		return Reject(NotFound)
	}
	return nil
}
