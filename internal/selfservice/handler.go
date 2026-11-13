// Package selfservice exposes narrowly authorized owner enrollment and
// revocation. Registry remains the only eligibility and credential authority.
package selfservice

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

type Authenticator interface {
	AuthenticateToken(context.Context, string) (identity.VerifiedToken, error)
}

type Enroller interface {
	SelfEnroll(context.Context, domain.Actor, domain.RequestID, string, []byte, domain.DeviceID, uint64) (domain.CertificateReceipt, error)
}

type Revoker interface {
	RevokeOwned(context.Context, domain.Actor, domain.DeviceID) error
}

type Options struct {
	Descriptor           contract.Descriptor
	Authenticator        Authenticator
	Enroller             Enroller
	Revoker              Revoker
	Now                  func() time.Time
	ConcurrentRequests   int
	TrustLoopbackProxyIP bool
}

type handler struct {
	authenticator        Authenticator
	enroller             Enroller
	revoker              Revoker
	now                  func() time.Time
	metadata             []byte
	ips                  *httpguard.RateLimits
	metadataIPs          *httpguard.RateLimits
	principals           *httpguard.RateLimits
	trustLoopbackProxyIP bool
}

const requestTimeout = 30 * time.Second

// New owns a self-service HTTP concurrency budget, independent of task routing
// permits. The composing listener retains TLS socket and read/write ownership.
func New(input Options) (http.Handler, error) {
	if input.Descriptor.Validate() != nil || input.Authenticator == nil || input.Enroller == nil || input.Revoker == nil || input.Now == nil {
		return nil, domain.ErrInvalid
	}
	if input.ConcurrentRequests == 0 {
		input.ConcurrentRequests = 8
	}
	input.Descriptor.SupportedWireVersions = slices.Clone(input.Descriptor.SupportedWireVersions)
	input.Descriptor.Capabilities = slices.Clone(input.Descriptor.Capabilities)
	metadata, err := protocol.Encode(input.Descriptor, contract.MaxBodyBytes)
	if err != nil {
		return nil, domain.ErrInvalid
	}
	guard, err := httpguard.New(httpguard.Options{PublicOrigin: input.Descriptor.PublicURL, ConcurrentRequests: input.ConcurrentRequests, Timeout: requestTimeout, MaxBodyBytes: contract.MaxBodyBytes})
	if err != nil {
		return nil, err
	}
	ips, err := httpguard.NewRateLimits(1, 10, 4096, 2*time.Minute, input.Now)
	if err != nil {
		return nil, err
	}
	principals, err := httpguard.NewRateLimits(1, 5, 4096, 2*time.Minute, input.Now)
	if err != nil {
		return nil, err
	}
	metadataIPs, err := httpguard.NewRateLimits(1, 10, 4096, 2*time.Minute, input.Now)
	if err != nil {
		return nil, err
	}
	h := &handler{authenticator: input.Authenticator, enroller: input.Enroller, revoker: input.Revoker, now: input.Now, metadata: metadata, ips: ips, metadataIPs: metadataIPs, principals: principals, trustLoopbackProxyIP: input.TrustLoopbackProxyIP}
	return guard.Wrap(h), nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !h.allowIP(r) {
		w.Header().Set("Retry-After", "1")
		writeFailure(w, http.StatusTooManyRequests, "resource_limit")
		return
	}
	switch r.URL.Path {
	case contract.DescriptorPath:
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, h.metadata)
	case contract.EnrollmentPath, contract.RevocationPath:
		h.management(w, r)
	default:
		writeFailure(w, http.StatusNotFound, "not_found")
	}
}

func (h *handler) allowIP(r *http.Request) bool {
	host, err := httpguard.ClientIP(r, h.trustLoopbackProxyIP)
	if err != nil {
		return false
	}
	if r.URL.Path == contract.DescriptorPath {
		return h.metadataIPs.Allow(host)
	}
	return h.ips.Allow(host)
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeFailure(w, http.StatusMethodNotAllowed, "method_not_allowed")
	return false
}

func (h *handler) management(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		writeFailure(w, http.StatusUnsupportedMediaType, "invalid_content_type")
		return
	}
	verified, err := h.authenticate(r)
	if err != nil {
		writeAuthenticationFailure(w, err)
		return
	}
	if !h.principals.Allow(string(verified.Actor.Principal)) {
		w.Header().Set("Retry-After", "1")
		writeFailure(w, http.StatusTooManyRequests, "resource_limit")
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), verified.ExpiresAt)
	defer cancel()
	r = r.WithContext(ctx)
	if r.URL.Path == contract.EnrollmentPath {
		h.enroll(w, r, verified)
		return
	}
	h.revoke(w, r, verified)
}

func (h *handler) authenticate(r *http.Request) (identity.VerifiedToken, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > identity.MaxTokenBytes+7 {
		return identity.VerifiedToken{}, domain.ErrInvalid
	}
	parts := strings.Split(values[0], " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !bearerToken(parts[1]) {
		return identity.VerifiedToken{}, domain.ErrInvalid
	}
	verified, err := h.authenticator.AuthenticateToken(r.Context(), parts[1])
	if err != nil {
		return identity.VerifiedToken{}, err
	}
	if verified.Actor.Validate() != nil || !verified.ExpiresAt.After(h.now()) {
		return identity.VerifiedToken{}, domain.ErrInvalid
	}
	return verified, nil
}

func writeAuthenticationFailure(w http.ResponseWriter, err error) {
	var unavailable *identity.Error
	if errors.As(err, &unavailable) && (unavailable.Code == identity.KeysUnavailable || unavailable.Code == identity.PrincipalUnavailable) {
		w.Header().Set("Retry-After", "1")
		writeFailure(w, http.StatusServiceUnavailable, "authentication_unavailable")
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeFailure(w, http.StatusUnauthorized, "unauthenticated")
}

func bearerToken(value string) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && !strings.ContainsRune("-._~+/=", character) {
			return false
		}
	}
	return true
}

func (h *handler) enroll(w http.ResponseWriter, r *http.Request, verified identity.VerifiedToken) {
	if !verified.Actor.Scopes.Has(domain.DeviceEnroll) {
		writeFailure(w, http.StatusForbidden, "forbidden")
		return
	}
	request, err := readEnrollmentRequest(w, r)
	if err != nil {
		writeFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if request.ReplaceDeviceID != "" && !verified.Actor.Scopes.Has(domain.DeviceManage) {
		writeFailure(w, http.StatusForbidden, "forbidden")
		return
	}
	csr, err := decodeCSR(request.CSRDERBase64)
	if err != nil {
		writeFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	receipt, err := h.enroller.SelfEnroll(r.Context(), verified.Actor, domain.RequestID(request.RequestID), request.Name, csr, domain.DeviceID(request.ReplaceDeviceID), request.ExpectedGeneration)
	if err != nil {
		writeDomainFailure(w, err)
		return
	}
	if !h.canRespond(w, r, verified) {
		return
	}
	if receipt.Intent.Credential.Validate() != nil || receipt.Intent.Mode != domain.Regular || len(receipt.CertificateDER) == 0 {
		writeFailure(w, http.StatusServiceUnavailable, "enrollment_unavailable")
		return
	}
	response := contract.EnrollmentResponse{
		EnrollmentResponse: protocol.EnrollmentResponse{DeviceID: string(receipt.Intent.Credential.Device), Epoch: string(receipt.Intent.Credential.Epoch), Generation: receipt.Intent.Credential.Generation, Mode: receipt.Intent.Mode, CertificateDERBase64: base64.StdEncoding.EncodeToString(receipt.CertificateDER)},
		RequestID:          request.RequestID, OwnerPrincipal: string(verified.Actor.Principal),
	}
	encoded, err := protocol.Encode(response, contract.MaxBodyBytes)
	if err != nil {
		writeFailure(w, http.StatusServiceUnavailable, "enrollment_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, encoded)
}

func readEnrollmentRequest(w http.ResponseWriter, r *http.Request) (contract.EnrollmentRequest, error) {
	var request contract.EnrollmentRequest
	if decodeBody(w, r, &request) != nil || domain.TaskID(request.RequestID).Validate() != nil || domain.ValidateDeviceName(request.Name) != nil || !validReplacement(request) {
		return contract.EnrollmentRequest{}, domain.ErrInvalid
	}
	return request, nil
}

func decodeCSR(encoded string) ([]byte, error) {
	csr, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(csr) == 0 || len(csr) > devicecert.MaxCSRBytes || base64.StdEncoding.EncodeToString(csr) != encoded {
		return nil, domain.ErrInvalid
	}
	return csr, nil
}

func validReplacement(request contract.EnrollmentRequest) bool {
	if request.ReplaceDeviceID == "" {
		return request.ExpectedGeneration == 0
	}
	return domain.CredentialToken(request.ReplaceDeviceID) == nil && request.ExpectedGeneration != 0
}

func (h *handler) revoke(w http.ResponseWriter, r *http.Request, verified identity.VerifiedToken) {
	if !verified.Actor.Scopes.Has(domain.DeviceManage) {
		writeFailure(w, http.StatusForbidden, "forbidden")
		return
	}
	var request contract.RevocationRequest
	if decodeBody(w, r, &request) != nil || domain.CredentialToken(request.DeviceID) != nil {
		writeFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.revoker.RevokeOwned(r.Context(), verified.Actor, domain.DeviceID(request.DeviceID)); err != nil {
		writeDomainFailure(w, err)
		return
	}
	if !h.canRespond(w, r, verified) {
		return
	}
	encoded, err := protocol.Encode(contract.RevocationResponse{DeviceID: request.DeviceID, Revoked: true}, contract.MaxBodyBytes)
	if err != nil {
		writeFailure(w, http.StatusServiceUnavailable, "enrollment_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, encoded)
}

func decodeBody[T any](w http.ResponseWriter, r *http.Request, output *T) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, contract.MaxBodyBytes))
	if err != nil {
		return domain.ErrInvalid
	}
	return protocol.DecodeStrict(body, output, contract.MaxBodyBytes)
}

func (h *handler) canRespond(w http.ResponseWriter, r *http.Request, verified identity.VerifiedToken) bool {
	if !h.now().Before(verified.ExpiresAt) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeFailure(w, http.StatusUnauthorized, "unauthenticated")
		return false
	}
	if r.Context().Err() != nil {
		writeFailure(w, http.StatusServiceUnavailable, "timeout")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		return // No response retry is possible; the durable request remains replayable.
	}
}

func writeFailure(w http.ResponseWriter, status int, code string) {
	// Codes are caller-selected constants, never input or underlying diagnostics.
	body, err := protocol.Encode(contract.Failure{Error: code}, contract.MaxBodyBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, []byte(`{"error":"enrollment_unavailable"}`))
		return
	}
	writeJSON(w, status, body)
}

func writeDomainFailure(w http.ResponseWriter, err error) {
	var refusal *domain.Error
	if errors.As(err, &refusal) {
		switch refusal.Code {
		case domain.Conflict:
			writeFailure(w, http.StatusConflict, "conflict")
		case domain.Expired:
			writeFailure(w, http.StatusGone, "expired")
		case domain.ResourceLimit:
			w.Header().Set("Retry-After", "1")
			writeFailure(w, http.StatusTooManyRequests, "resource_limit")
		case domain.Invalid:
			writeFailure(w, http.StatusBadRequest, "invalid_request")
		case domain.Forbidden, domain.NotFound:
			writeFailure(w, http.StatusForbidden, "forbidden")
		case domain.Pending, domain.EvidenceInvalid:
			writeFailure(w, http.StatusServiceUnavailable, "enrollment_unavailable")
		default:
			writeFailure(w, http.StatusServiceUnavailable, "enrollment_unavailable")
		}
		return
	}
	var invalidCSR *devicecert.Error
	if errors.Is(err, domain.ErrInvalid) || (errors.As(err, &invalidCSR) && invalidCSR.Code == devicecert.InvalidCertificate) {
		writeFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	writeFailure(w, http.StatusServiceUnavailable, "enrollment_unavailable")
}
