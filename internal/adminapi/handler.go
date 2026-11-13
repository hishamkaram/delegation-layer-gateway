package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const MaxBodyBytes = 64 << 10

type Handler struct {
	options Options
	entropy chan struct{}
}

func NewHandler(options Options) (*Handler, error) {
	if options.Store == nil || options.Authority == nil || options.Authority.marker == nil || options.Disconnector == nil || options.Random == nil || options.Now == nil {
		return nil, domain.ErrInvalid
	}
	return &Handler{options: options, entropy: make(chan struct{}, 1)}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if err := h.options.Authority.AuthorizeAdmin(request.Context()); err != nil {
		writeFailure(writer, http.StatusForbidden, "forbidden", false)
		return
	}
	proof, ok := request.Context().Value(privateKey{}).(privateProof)
	if !ok || !proof.gate.begin() {
		writeFailure(writer, http.StatusServiceUnavailable, "resource_limit", false)
		return
	}
	defer proof.gate.end()
	if request.URL.RawQuery != "" || request.URL.ForceQuery || request.Header.Get("Origin") != "" {
		writeFailure(writer, http.StatusBadRequest, "invalid_request", false)
		return
	}
	if request.Header.Get("Content-Encoding") != "" {
		writeFailure(writer, http.StatusUnsupportedMediaType, "invalid_request", false)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	if h.metadata(writer, request) {
		return
	}
	media, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeFailure(writer, http.StatusUnsupportedMediaType, "invalid_request", false)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, MaxBodyBytes)
	h.route(writer, request)
}

func (h *Handler) route(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/devices/enrollment-tokens" {
		serve(w, r, http.MethodPost, h.createOwnedEnrollment)
		return
	}
	if h.ownerPolicyRoute(w, r) {
		return
	}
	if h.recoveryRoute(w, r) {
		return
	}
	switch r.URL.Path {
	case "/v1/roots/initialize":
		serve(w, r, http.MethodPost, h.initializeRoot)
	case "/v1/roots/progress":
		serve(w, r, http.MethodPost, h.rootProgress)
	case "/v1/roots/abandon":
		serve(w, r, http.MethodPost, h.abandonRoot)
	case "/v1/devices":
		serve(w, r, http.MethodPost, h.registerDevice)
	case "/v1/projects":
		serve(w, r, http.MethodPost, h.registerProject)
	case "/v1/principals/resolve":
		serve(w, r, http.MethodPost, h.resolvePrincipal)
	case "/v1/principals/revocation":
		serve(w, r, http.MethodPost, h.revokePrincipal)
	case "/v1/devices/revocation":
		serve(w, r, http.MethodPost, h.revokeDevice)
	case "/v1/enrollment-tokens":
		serve(w, r, http.MethodPost, h.createEnrollment)
	case "/v1/grants":
		if r.Method == http.MethodDelete {
			serve(w, r, http.MethodDelete, h.revokeGrant)
		} else {
			serve(w, r, http.MethodPut, h.putGrant)
		}
	default:
		writeFailure(w, http.StatusNotFound, "not_found", false)
	}
}

func serve[In, Out any](writer http.ResponseWriter, request *http.Request, method string, call func(context.Context, In) (Out, error)) {
	if request.Method != method {
		writer.Header().Set("Allow", method)
		writeFailure(writer, http.StatusMethodNotAllowed, "method_not_allowed", false)
		return
	}
	data, err := io.ReadAll(request.Body)
	if err != nil {
		writeFailure(writer, http.StatusBadRequest, "invalid_request", false)
		return
	}
	var input In
	if protocol.DecodeStrict(data, &input, MaxBodyBytes) != nil {
		writeFailure(writer, http.StatusBadRequest, "invalid_request", false)
		return
	}
	output, err := call(request.Context(), input)
	if err != nil {
		status, code, committed := classify(err)
		writeFailure(writer, status, code, committed)
		return
	}
	writeJSON(writer, http.StatusOK, output)
}

func writeJSON[T any](writer http.ResponseWriter, status int, value T) {
	data, err := json.Marshal(value)
	if err != nil {
		writeFailure(writer, http.StatusInternalServerError, "internal_error", false)
		return
	}
	writer.WriteHeader(status)
	if _, err = writer.Write(data); err != nil {
		return
	} // The peer can no longer receive the response.
}

func writeFailure(writer http.ResponseWriter, status int, code string, committed bool) {
	writeJSON(writer, status, Failure{Code: code, Committed: committed})
}

func classify(err error) (int, string, bool) {
	var local *Error
	if errors.As(err, &local) && local.Code == "disconnect_unconfirmed" {
		return http.StatusServiceUnavailable, local.Code, true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, "timeout", false
	}
	if errors.Is(err, domain.ErrInvalid) || errors.Is(err, protocol.ErrInvalid) {
		return http.StatusBadRequest, "invalid_request", false
	}
	var failure *domain.Error
	if errors.As(err, &failure) {
		return domainFailure(failure.Code)
	}
	var remote *gateway.RemoteError
	if errors.As(err, &remote) && remote != nil && remote.Failure.Validate() == nil {
		return remoteFailure(remote.Failure.Code)
	}
	return http.StatusInternalServerError, "internal_error", false
}

// Only validated protocol codes cross this boundary. Retryability never
// establishes authority, durable commitment or the HTTP failure category.
func remoteFailure(code string) (int, string, bool) {
	switch code {
	case "unauthenticated":
		return http.StatusUnauthorized, code, false
	case "forbidden":
		return http.StatusForbidden, code, false
	case "not_found":
		return http.StatusNotFound, code, false
	case "timeout", "result_verification_timeout":
		return http.StatusGatewayTimeout, code, false
	case "device_offline", "device_not_ready", "resource_limit":
		return http.StatusServiceUnavailable, code, false
	case "conflict", "pending", "context_mismatch", "admission_unknown", "permanently_refused":
		return http.StatusConflict, code, false
	case "expired":
		return http.StatusGone, code, false
	case "incompatible_delegate", "protocol_error", "evidence_invalid", "result_unavailable":
		return http.StatusBadGateway, code, false
	default:
		return http.StatusInternalServerError, "internal_error", false
	}
}

func domainFailure(code domain.ErrorCode) (int, string, bool) {
	switch code {
	case domain.Invalid:
		return http.StatusBadRequest, "invalid_request", false
	case domain.Forbidden:
		return http.StatusForbidden, "forbidden", false
	case domain.NotFound:
		return http.StatusNotFound, "not_found", false
	case domain.Conflict, domain.Pending:
		return http.StatusConflict, string(code), false
	case domain.Expired:
		return http.StatusGone, "expired", false
	case domain.ResourceLimit:
		return http.StatusServiceUnavailable, "resource_limit", false
	case domain.EvidenceInvalid:
		return http.StatusInternalServerError, "evidence_invalid", false
	default:
		return http.StatusInternalServerError, "internal_error", false
	}
}

func (h *Handler) registerDevice(ctx context.Context, input RegisterDeviceInput) (Device, error) {
	device, err := h.options.Store.RegisterDevice(ctx, domain.DeviceRegistration{ID: domain.DeviceID(input.DeviceID), Name: input.Name})
	return Device{DeviceID: string(device.ID), Name: device.Name, Revoked: device.Revoked, CredentialGeneration: device.CredentialGeneration}, err
}

func (h *Handler) registerProject(ctx context.Context, input RegisterProjectInput) (Mutation, error) {
	project := domain.ProjectRegistration{Destination: domain.Destination{Device: domain.DeviceID(input.DeviceID), Project: domain.ProjectAlias(input.ProjectAlias)}, Context: domain.ContextBinding{Root: domain.RootGuard(input.RootGuard), Project: domain.ProjectGuard(input.ProjectGuard)}}
	if err := project.Validate(); err != nil {
		return Mutation{}, err
	}
	err := h.options.Store.RegisterProject(ctx, project)
	return Mutation{Committed: err == nil}, err
}

func (h *Handler) resolvePrincipal(ctx context.Context, input ResolvePrincipalInput) (Principal, error) {
	principal, err := h.options.Store.ResolvePrincipal(ctx, domain.ExternalSubject{Issuer: input.Issuer, Subject: input.Subject})
	return Principal{PrincipalID: string(principal.ID), Revoked: principal.Revoked}, err
}

func key(input GrantKey) domain.GrantKey {
	return domain.GrantKey{Principal: domain.PrincipalID(input.PrincipalID), Destination: domain.Destination{Device: domain.DeviceID(input.DeviceID), Project: domain.ProjectAlias(input.ProjectAlias)}}
}

func (h *Handler) putGrant(ctx context.Context, input PutGrantInput) (Mutation, error) {
	if len(input.Providers) > 100 || len(input.Permissions) > 3 {
		return Mutation{}, domain.ErrInvalid
	}
	grant := domain.Grant{Key: key(GrantKey{PrincipalID: input.PrincipalID, DeviceID: input.DeviceID, ProjectAlias: input.ProjectAlias}), Scopes: input.Scopes, Ceiling: domain.DispatchCeiling{Providers: input.Providers, Permissions: input.Permissions, MaxBudgetSeconds: input.MaxBudgetSeconds}}
	if err := grant.Validate(); err != nil {
		return Mutation{}, err
	}
	if len(input.Providers) != 0 || len(input.Permissions) != 0 || input.MaxBudgetSeconds != 0 {
		if err := grant.Ceiling.Validate(); err != nil {
			return Mutation{}, err
		}
	}
	err := h.options.Store.PutGrant(ctx, grant)
	return Mutation{Committed: err == nil}, err
}

func (h *Handler) revokeGrant(ctx context.Context, input GrantKey) (Mutation, error) {
	err := h.options.Store.RevokeGrant(ctx, key(input))
	return Mutation{Committed: err == nil}, err
}

func (h *Handler) revokePrincipal(ctx context.Context, input PrincipalRevocationInput) (Mutation, error) {
	if input.Revoked == nil {
		return Mutation{}, domain.ErrInvalid
	}
	err := h.options.Store.SetPrincipalRevoked(ctx, domain.PrincipalID(input.PrincipalID), *input.Revoked)
	return Mutation{Committed: err == nil}, err
}

func (h *Handler) revokeDevice(ctx context.Context, input DeviceRevocationInput) (Mutation, error) {
	if input.Revoked == nil {
		return Mutation{}, domain.ErrInvalid
	}
	id := domain.DeviceID(input.DeviceID)
	if err := h.options.Store.SetDeviceRevoked(ctx, id, *input.Revoked); err != nil {
		return Mutation{}, err
	}
	if *input.Revoked {
		if err := h.options.Disconnector.Disconnect(ctx, id); err != nil {
			return Mutation{Committed: true}, fail("disconnect_unconfirmed", err)
		}
	}
	return Mutation{Committed: true}, nil
}

func (h *Handler) createEnrollment(ctx context.Context, input EnrollmentInput) (Enrollment, error) {
	if domain.CredentialToken(input.DeviceID) != nil || input.Mode.Validate() != nil || input.Generation == 0 {
		return Enrollment{}, domain.ErrInvalid
	}
	select {
	case h.entropy <- struct{}{}:
		defer func() { <-h.entropy }()
	case <-ctx.Done():
		return Enrollment{}, ctx.Err()
	}
	token, hash, err := enrollment.NewToken(h.options.Random)
	if err != nil {
		return Enrollment{}, err
	}
	now := h.options.Now()
	expires := now.Add(domain.EnrollmentTTL)
	if err = h.options.Store.CreateEnrollment(ctx, domain.EnrollmentGrant{TokenHash: hash, Device: domain.DeviceID(input.DeviceID), Mode: input.Mode, Generation: input.Generation, CreatedAt: now, ExpiresAt: expires}); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{Token: token, DeviceID: input.DeviceID, ExpiresAt: expires}, nil
}
