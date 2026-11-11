package adminapi

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestRemoteFailuresKeepClosedHTTPMeaning(t *testing.T) {
	cases := []struct {
		code   string
		status int
	}{
		{"unauthenticated", http.StatusUnauthorized},
		{"forbidden", http.StatusForbidden},
		{"not_found", http.StatusNotFound},
		{"timeout", http.StatusGatewayTimeout},
		{"result_verification_timeout", http.StatusGatewayTimeout},
		{"device_offline", http.StatusServiceUnavailable},
		{"device_not_ready", http.StatusServiceUnavailable},
		{"resource_limit", http.StatusServiceUnavailable},
		{"conflict", http.StatusConflict},
		{"pending", http.StatusConflict},
		{"context_mismatch", http.StatusConflict},
		{"admission_unknown", http.StatusConflict},
		{"permanently_refused", http.StatusConflict},
		{"expired", http.StatusGone},
		{"incompatible_delegate", http.StatusBadGateway},
		{"protocol_error", http.StatusBadGateway},
		{"evidence_invalid", http.StatusBadGateway},
		{"result_unavailable", http.StatusBadGateway},
	}
	for _, tc := range cases {
		for _, retryable := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/retryable=%t", tc.code, retryable), func(t *testing.T) {
				remote := &gateway.RemoteError{Failure: protocol.Failure{Code: tc.code, Retryable: retryable}}
				status, code, committed := classify(fmt.Errorf("private-message-canary: %w", remote))
				if status != tc.status || code != tc.code || committed {
					t.Fatalf("closed failure changed meaning: status=%d code=%q committed=%t", status, code, committed)
				}
			})
		}
	}
}
