package devicecert

import "github.com/hishamkaram/delegation-layer-gateway/internal/identityerror"

type (
	ErrorCode = identityerror.ErrorCode
	Error     = identityerror.Error
)

const (
	InvalidConfiguration = identityerror.InvalidConfiguration
	InvalidCertificate   = identityerror.InvalidCertificate
	SigningFailed        = identityerror.SigningFailed
)

func reject(code ErrorCode, cause error) error { return identityerror.New(code, cause) }
