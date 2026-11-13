// Package identity verifies external identities and signs reserved credentials.
// Registry owns principal mapping, revocation, issuance receipts and activation.
package identity

type ErrorCode string

const (
	InvalidConfiguration ErrorCode = "identity_invalid_configuration"
	InvalidToken         ErrorCode = "identity_invalid_token"
	KeysUnavailable      ErrorCode = "identity_keys_unavailable"
	PrincipalUnavailable ErrorCode = "identity_principal_unavailable"
	PrincipalRevoked     ErrorCode = "identity_principal_revoked"
	InvalidCertificate   ErrorCode = "identity_invalid_certificate"
	SigningFailed        ErrorCode = "identity_signing_failed"
)

// Error exposes only a fixed classification. Causes remain available to the
// caller through errors.Is/As, never through public formatting or serialization.
type Error struct {
	Code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.Code) }
func (e *Error) Unwrap() error { return e.cause }

func reject(code ErrorCode, cause error) error { return &Error{Code: code, cause: cause} }
