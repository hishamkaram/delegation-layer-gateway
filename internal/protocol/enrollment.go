package protocol

import "github.com/hishamkaram/delegation-layer-gateway/internal/domain"

const MaxEnrollmentBodyBytes = 32 << 10

// EnrollmentRequest is the bounded public credential-redemption wire payload.
type EnrollmentRequest struct {
	Token        string `json:"token"`
	CSRDERBase64 string `json:"csr_der_base64"`
	RequireOwned bool   `json:"require_owned,omitempty"`
}

// EnrollmentResponse carries the reserved credential and its certificate.
// It grants no task authority and contains no private key.
type EnrollmentResponse struct {
	DeviceID             string                `json:"device_id"`
	Epoch                string                `json:"epoch"`
	Generation           uint64                `json:"generation"`
	Mode                 domain.CredentialMode `json:"mode"`
	CertificateDERBase64 string                `json:"certificate_der_base64"`
}
