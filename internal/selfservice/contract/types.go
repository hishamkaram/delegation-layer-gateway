// Package contract defines public connection and self-service wire data.
// It contains no authentication, HTTP server or Registry implementation.
package contract

import "github.com/hishamkaram/delegation-layer-gateway/internal/protocol"

const (
	DescriptorPath = "/.well-known/delegation-gateway"
	EnrollmentPath = "/v1/self/enroll"
	RevocationPath = "/v1/self/devices/revoke"
	MaxBodyBytes   = 64 << 10
)

// Descriptor advertises only configured public connection information. The
// composing server must advertise capabilities only after activating them.
type Descriptor struct {
	SchemaVersion         int      `json:"schema_version"`
	GatewayID             string   `json:"gateway_id"`
	PublicURL             string   `json:"public_url"`
	Issuer                string   `json:"issuer"`
	NativeClientID        string   `json:"native_client_id"`
	Audience              string   `json:"audience"`
	EnrollmentURL         string   `json:"enrollment_url"`
	SelfEnrollmentURL     string   `json:"self_enrollment_url"`
	RevokeURL             string   `json:"revoke_url"`
	DeviceWSSURL          string   `json:"device_wss_url"`
	DeviceCAPEM           string   `json:"device_ca_pem"`
	SupportedWireVersions []int    `json:"supported_wire_versions"`
	Capabilities          []string `json:"capabilities"`
}

type EnrollmentRequest struct {
	RequestID          string `json:"request_id"`
	Name               string `json:"name"`
	CSRDERBase64       string `json:"csr_der_base64"`
	ReplaceDeviceID    string `json:"replace_device_id,omitempty"`
	ExpectedGeneration uint64 `json:"expected_generation,omitempty"`
}

// EnrollmentResponse preserves the existing flat certificate response fields.
// OwnerPrincipal is the verified opaque principal, never a submitted owner.
type EnrollmentResponse struct {
	protocol.EnrollmentResponse
	RequestID      string `json:"request_id"`
	OwnerPrincipal string `json:"owner_principal"`
}

type RevocationRequest struct {
	DeviceID string `json:"device_id"`
}

// Revoked means authorization was invalidated; it proves neither network
// cleanup nor Native task termination.
type RevocationResponse struct {
	DeviceID string `json:"device_id"`
	Revoked  bool   `json:"revoked"`
}

type Failure struct {
	Error string `json:"error"`
}
