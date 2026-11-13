package protocol

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Gateway sends the first Hello with its assigned nonzero generation. Connector
// acknowledges the exact hello identity before advertising dated capabilities.
type HelloBody struct {
	GatewayID string `json:"gateway_id"`
	DeviceID  string `json:"device_id"`
}

func (h HelloBody) Validate() error {
	if !identifier(h.GatewayID) || !identifier(h.DeviceID) {
		return ErrInvalid
	}
	return nil
}

type ProviderCapability struct {
	Provider         string   `json:"provider"`
	Models           []string `json:"models"`
	Efforts          []string `json:"efforts"`
	Permissions      []string `json:"permissions"`
	MaxBudgetSeconds uint32   `json:"max_budget_seconds"`
	Authentication   string   `json:"authentication"`
}
type ProjectCapability struct {
	Alias               string               `json:"alias"`
	Context             ContextBinding       `json:"context"`
	AdmissionGeneration string               `json:"admission_generation"`
	AdmissionOpen       bool                 `json:"admission_open"`
	ContractVersion     int                  `json:"contract_version"`
	Features            []string             `json:"features"`
	Providers           []ProviderCapability `json:"providers"`
	Ready               bool                 `json:"ready"`
}
type CapabilityReport struct {
	ObservedAt time.Time           `json:"observed_at"`
	Projects   []ProjectCapability `json:"projects"`
}

func (r CapabilityReport) Validate() error {
	if r.ObservedAt.IsZero() || len(r.Projects) > 100 {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	for _, project := range r.Projects {
		if seen[project.Alias] || project.Validate() != nil {
			return ErrInvalid
		}
		seen[project.Alias] = true
	}
	return nil
}

func (p ProjectCapability) Validate() error {
	if !identifier(p.Alias) || len(p.Features) > 100 || len(p.Providers) > 100 {
		return ErrInvalid
	}
	if !p.validContext() || (p.AdmissionGeneration != "" && !identifier(p.AdmissionGeneration)) {
		return ErrInvalid
	}
	for _, feature := range p.Features {
		if !identifier(feature) {
			return ErrInvalid
		}
	}
	if p.Ready && !p.executionReady(NativeFeaturesCompatible(p.Features)) {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	for _, provider := range p.Providers {
		if seen[provider.Provider] || provider.Validate() != nil {
			return ErrInvalid
		}
		seen[provider.Provider] = true
	}
	return nil
}

func (p ProjectCapability) validContext() bool {
	if p.Context.Root == "" && p.Context.Project == "" {
		return !p.Ready
	}
	return guardToken(p.Context.Root) && guardToken(p.Context.Project)
}

func (p ProjectCapability) executionReady(compatible bool) bool {
	return p.ContractVersion == NativeContractVersion && compatible && p.AdmissionOpen && identifier(p.AdmissionGeneration) && guardToken(p.Context.Root) && guardToken(p.Context.Project)
}

func (p ProviderCapability) Validate() error {
	if !identifier(p.Provider) || len(p.Models) > 100 || len(p.Efforts) > 100 || len(p.Permissions) > 3 || p.MaxBudgetSeconds == 0 {
		return ErrInvalid
	}
	for _, values := range [][]string{p.Models, p.Efforts} {
		for _, value := range values {
			if !selectionToken(value) {
				return ErrInvalid
			}
		}
	}
	for _, permission := range p.Permissions {
		if permission != "read-only" && permission != "workspace-write" && permission != "danger-full-access" {
			return ErrInvalid
		}
	}
	switch p.Authentication {
	case "unknown", "verified", "unavailable":
		return nil
	default:
		return ErrInvalid
	}
}

// Reply's operation selects a concrete body type at the application boundary.
// Transport validates correlation and framing; the consumer validates that body
// before it can affect an authoritative observation or be returned to a client.
type Reply struct {
	Operation Operation       `json:"operation"`
	Error     *Failure        `json:"error,omitempty"`
	Body      json.RawMessage `json:"body,omitempty"`
}
type Failure struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

func (f Failure) Validate() error {
	switch f.Code {
	case "unauthenticated", "forbidden", "not_found", "device_offline", "device_not_ready", "conflict", "expired", "pending", "admission_unknown", "permanently_refused", "context_mismatch", "incompatible_delegate", "resource_limit", "result_unavailable", "evidence_invalid", "timeout", "result_verification_timeout", "protocol_error":
		return nil
	default:
		return ErrInvalid
	}
}

func (r Reply) Validate() error {
	return r.ValidateVersion(WireVersion2)
}

func (r Reply) ValidateVersion(version int) error {
	if r.Operation.ValidateVersion(version) != nil {
		return ErrInvalid
	}
	if r.Error != nil {
		if len(r.Body) != 0 {
			return ErrInvalid
		}
		return r.Error.Validate()
	}
	if len(r.Body) == 0 || string(r.Body) == "null" {
		return ErrInvalid
	}
	return nil
}

type Renewal struct {
	DeviceID             string `json:"device_id"`
	RenewalID            string `json:"renewal_id"`
	CredentialGeneration uint64 `json:"credential_generation"`
	CSRDERBase64         string `json:"csr_der_base64"`
}

func (r Renewal) CSR() ([]byte, error) {
	if !identifier(r.DeviceID) || !lowerHex(r.RenewalID, 32) || r.CredentialGeneration == 0 || len(r.CSRDERBase64) > base64.StdEncoding.EncodedLen(16<<10) {
		return nil, ErrInvalid
	}
	data, err := base64.StdEncoding.Strict().DecodeString(r.CSRDERBase64)
	if err != nil || len(data) == 0 || len(data) > 16<<10 {
		return nil, ErrInvalid
	}
	return data, nil
}

type RenewalResult struct {
	DeviceID             string   `json:"device_id"`
	RenewalID            string   `json:"renewal_id"`
	Epoch                string   `json:"epoch,omitempty"`
	Generation           uint64   `json:"generation,omitempty"`
	CertificateDERBase64 string   `json:"certificate_der_base64,omitempty"`
	Error                *Failure `json:"error,omitempty"`
}

func (r RenewalResult) Validate() error {
	if !identifier(r.DeviceID) || !lowerHex(r.RenewalID, 32) {
		return ErrInvalid
	}
	if r.Error != nil {
		if r.Epoch != "" || r.Generation != 0 || r.CertificateDERBase64 != "" {
			return ErrInvalid
		}
		return r.Error.Validate()
	}
	if !identifier(r.Epoch) || r.Generation == 0 || len(r.CertificateDERBase64) > base64.StdEncoding.EncodedLen(16<<10) {
		return ErrInvalid
	}
	data, err := base64.StdEncoding.Strict().DecodeString(r.CertificateDERBase64)
	if err != nil || len(data) == 0 || len(data) > 16<<10 {
		return ErrInvalid
	}
	return nil
}

type (
	InspectRequest struct {
		GatewayID string `json:"gateway_id"`
		RootOnly  bool   `json:"root_only,omitempty"`
	}
	OriginBarrierRequest struct {
		GatewayID          string `json:"gateway_id"`
		RecoveryID         string `json:"recovery_id"`
		ExpectedGeneration string `json:"expected_generation"`
		Generation         string `json:"generation"`
		ExpectedRoot       string `json:"expected_root"`
	}
)

type OriginInventoryRequest struct {
	GatewayID    string `json:"gateway_id"`
	Generation   string `json:"generation"`
	Cursor       string `json:"cursor,omitempty"`
	Limit        int    `json:"limit"`
	ExpectedRoot string `json:"expected_root"`
}
type OriginReopenRequest struct {
	GatewayID           string `json:"gateway_id"`
	RecoveryID          string `json:"recovery_id"`
	Generation          string `json:"generation"`
	CompletenessReceipt string `json:"completeness_receipt"`
	ExpectedRoot        string `json:"expected_root"`
}

// OriginStateReport is a validated response for a namespace barrier or reopen.
// It contains no local root path or CLI context token.
type OriginStateReport struct {
	GatewayID     string `json:"gateway_id"`
	RecoveryID    string `json:"recovery_id"`
	Generation    string `json:"generation"`
	AdmissionOpen bool   `json:"admission_open"`
}

func (r OriginStateReport) Validate() error {
	if !identifier(r.GatewayID) || !identifier(r.RecoveryID) || !identifier(r.Generation) {
		return ErrInvalid
	}
	return nil
}

// RootCapability attests only a Delegate root and its requested Gateway namespace.
// It contains no project identity, provider dates or execution-readiness claim.
type RootCapability struct {
	Root             string             `json:"root"`
	ContractVersion  int                `json:"contract_version"`
	Features         []string           `json:"features"`
	OriginRegistered bool               `json:"origin_registered"`
	Origin           *OriginStateReport `json:"origin,omitempty"`
}

func (r RootCapability) Validate() error {
	if !guardToken(r.Root) || r.ContractVersion != NativeContractVersion || len(r.Features) > 100 || r.OriginRegistered != (r.Origin != nil) {
		return ErrInvalid
	}
	for _, feature := range r.Features {
		if !identifier(feature) {
			return ErrInvalid
		}
	}
	if !NativeFeaturesCompatible(r.Features) {
		return ErrInvalid
	}
	if r.Origin != nil {
		return r.Origin.Validate()
	}
	return nil
}
