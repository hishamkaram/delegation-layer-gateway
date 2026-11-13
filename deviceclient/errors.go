package deviceclient

import "errors"

var (
	ErrConfiguration       = errors.New("gateway_connection_invalid_configuration")
	ErrProfile             = errors.New("gateway_profile_invalid")
	ErrCapacity            = errors.New("resource_limit")
	ErrBusy                = errors.New("gateway_profile_in_use")
	ErrPersistence         = errors.New("gateway_profile_persistence_failed")
	ErrDiscovery           = errors.New("gateway_discovery_invalid")
	ErrUnsupported         = errors.New("gateway_unsupported")
	ErrTrustChanged        = errors.New("gateway_trust_changed")
	ErrTransport           = errors.New("gateway_connection_transport_failed")
	ErrDenied              = errors.New("gateway_connection_denied")
	ErrConflict            = errors.New("gateway_connection_conflict")
	ErrEnrollment          = errors.New("gateway_enrollment_invalid")
	ErrReplacementRequired = errors.New("gateway_credential_replacement_required")
)

type failure struct{ kind, cause error }

func (e failure) Error() string    { return e.kind.Error() }
func (e failure) String() string   { return e.Error() }
func (e failure) GoString() string { return e.Error() }
func (e failure) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}
func failed(kind, cause error) error { return failure{kind: kind, cause: cause} }
