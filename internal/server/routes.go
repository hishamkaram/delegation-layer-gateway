package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/mcpadapter"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

func (r *Runtime) observe(next http.Handler, start, end observability.Code) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		r.recorder.Record(observability.Event{Code: start})
		defer r.recorder.Record(observability.Event{Code: end})
		next.ServeHTTP(w, request)
	})
}

func (r *Runtime) publicRoutes(adapter *mcpadapter.Adapter, enroller, self http.Handler) http.Handler {
	mcp := r.observe(adapter.Handler(), observability.MCPRequestStarted, observability.MCPRequestCompleted)
	metadata := r.observe(adapter.Metadata(), observability.MetadataRequestStarted, observability.MetadataRequestCompleted)
	enroll := r.observe(enroller, observability.EnrollmentRequestStarted, observability.EnrollmentRequestCompleted)
	var descriptor, selfEnroll http.Handler
	if self != nil {
		descriptor = r.observe(self, observability.MetadataRequestStarted, observability.MetadataRequestCompleted)
		selfEnroll = r.observe(self, observability.EnrollmentRequestStarted, observability.EnrollmentRequestCompleted)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/mcp":
			mcp.ServeHTTP(w, request)
		case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp":
			metadata.ServeHTTP(w, request)
		case "/v1/enroll":
			enroll.ServeHTTP(w, request)
		case contract.DescriptorPath:
			if descriptor == nil {
				http.NotFound(w, request)
				return
			}
			descriptor.ServeHTTP(w, request)
		case contract.EnrollmentPath:
			if selfEnroll == nil {
				http.NotFound(w, request)
				return
			}
			selfEnroll.ServeHTTP(w, request)
		case contract.RevocationPath:
			if self == nil {
				http.NotFound(w, request)
				return
			}
			self.ServeHTTP(w, request)
		default:
			http.NotFound(w, request)
		}
	})
}

func (r *Runtime) deviceHandler(authority string) http.Handler {
	session := r.observe(r.hub, observability.DeviceRequestStarted, observability.DeviceRequestCompleted)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !deviceRequestAllowed(request, authority) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		request.Body = http.MaxBytesReader(w, request.Body, 16<<10)
		session.ServeHTTP(w, request)
	})
}

func deviceRequestAllowed(request *http.Request, authority string) bool {
	if request.TLS == nil || !strings.EqualFold(request.Host, authority) || request.URL.Path != "/device" || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || len(request.Header.Values("Origin")) != 0 {
		return false
	}
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
		if len(request.Header.Values(header)) != 0 {
			return false
		}
	}
	return true
}

type auditedAuthenticator struct {
	next     *identity.Authenticator
	recorder *observability.Recorder
}

func (a auditedAuthenticator) AuthenticateToken(ctx context.Context, token string) (identity.VerifiedToken, error) {
	result, err := a.next.AuthenticateToken(ctx, token)
	if err != nil {
		a.recorder.Record(observability.Event{Code: observability.AuthenticationDenied})
	}
	return result, err
}

type auditedEnrollment struct {
	next     *enrollment.Service
	recorder *observability.Recorder
}

func (a auditedEnrollment) Redeem(ctx context.Context, token string, csr []byte) (domain.CertificateReceipt, error) {
	receipt, err := a.next.Redeem(ctx, token, csr)
	if err == nil {
		a.recorder.Record(observability.Event{Code: observability.EnrollmentIssued, Device: receipt.Intent.Credential.Device})
	}
	return receipt, err
}
