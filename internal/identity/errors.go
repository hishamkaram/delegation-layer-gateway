// Package identity verifies external OAuth identities.
package identity

import "github.com/hishamkaram/delegation-layer-gateway/internal/identityerror"

type (
	ErrorCode = identityerror.ErrorCode
	Error     = identityerror.Error
)

const (
	InvalidConfiguration = identityerror.InvalidConfiguration
	InvalidToken         = identityerror.InvalidToken
	KeysUnavailable      = identityerror.KeysUnavailable
	PrincipalUnavailable = identityerror.PrincipalUnavailable
	PrincipalRevoked     = identityerror.PrincipalRevoked
	InvalidCertificate   = identityerror.InvalidCertificate
	SigningFailed        = identityerror.SigningFailed
)

func reject(code ErrorCode, cause error) error { return identityerror.New(code, cause) }
