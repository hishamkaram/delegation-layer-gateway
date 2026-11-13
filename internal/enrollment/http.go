package enrollment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const MaxEnrollmentBodyBytes = protocol.MaxEnrollmentBodyBytes

type Redeemer interface {
	Redeem(context.Context, string, []byte) (domain.CertificateReceipt, error)
}

type OwnedRedeemer interface {
	RedeemOwned(context.Context, string, []byte) (domain.CertificateReceipt, error)
}

type (
	EnrollmentRequest  = protocol.EnrollmentRequest
	EnrollmentResponse = protocol.EnrollmentResponse
)

// HTTPHandler must be mounted behind the configured HTTPS origin/body/request
// guard. Proxy client addresses are rate-limit keys only and require explicit
// loopback-proxy trust; they never authenticate an enrollment.
func HTTPHandler(service Redeemer, now func() time.Time, trustLoopbackProxyIP bool) (http.Handler, error) {
	if service == nil || now == nil {
		return nil, domain.ErrInvalid
	}
	limits, err := httpguard.NewRateLimits(1, 5, 4096, 2*time.Minute, now)
	if err != nil {
		return nil, err
	}
	return &redemptionHTTP{service: service, limits: limits, trustLoopbackProxyIP: trustLoopbackProxyIP}, nil
}

type redemptionHTTP struct {
	service              Redeemer
	limits               *httpguard.RateLimits
	trustLoopbackProxyIP bool
}

func (h *redemptionHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}
	host, splitErr := httpguard.ClientIP(r, h.trustLoopbackProxyIP)
	if splitErr != nil || !h.limits.Allow(host) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "resource_limit", http.StatusTooManyRequests)
		return
	}
	body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxEnrollmentBodyBytes))
	var request EnrollmentRequest
	if readErr != nil || protocol.DecodeStrict(body, &request, MaxEnrollmentBodyBytes) != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	csr, decodeErr := base64.StdEncoding.Strict().DecodeString(request.CSRDERBase64)
	if decodeErr != nil || len(csr) == 0 || len(csr) > devicecert.MaxCSRBytes {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	receipt, redeemErr := h.redeem(r.Context(), request, csr)
	if redeemErr != nil {
		enrollmentError(w, redeemErr)
		return
	}
	response := EnrollmentResponse{DeviceID: string(receipt.Intent.Credential.Device), Epoch: string(receipt.Intent.Credential.Epoch), Generation: receipt.Intent.Credential.Generation, Mode: receipt.Intent.Mode, CertificateDERBase64: base64.StdEncoding.EncodeToString(receipt.CertificateDER)}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

func (h *redemptionHTTP) redeem(ctx context.Context, request EnrollmentRequest, csr []byte) (domain.CertificateReceipt, error) {
	if request.RequireOwned {
		owned, ok := h.service.(OwnedRedeemer)
		if !ok {
			return domain.CertificateReceipt{}, domain.Reject(domain.Forbidden)
		}
		return owned.RedeemOwned(ctx, request.Token, csr)
	}
	return h.service.Redeem(ctx, request.Token, csr)
}

func enrollmentError(w http.ResponseWriter, err error) {
	var failure *domain.Error
	var certificateFailure *devicecert.Error
	if errors.As(err, &failure) || errors.As(err, &certificateFailure) || errors.Is(err, domain.ErrInvalid) {
		http.Error(w, "enrollment_denied", http.StatusForbidden)
		return
	}
	http.Error(w, "enrollment_unavailable", http.StatusServiceUnavailable)
}
