package adminapi_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestRefreshProjectReportsSafeRemoteFailuresOverPrivateUnix(t *testing.T) {
	cases := []struct {
		name    string
		failure error
		status  int
		code    string
	}{
		{"offline", fmt.Errorf("private-message-canary: %w", &gateway.RemoteError{Failure: protocol.Failure{Code: "device_offline", Retryable: true}}), http.StatusServiceUnavailable, "device_offline"},
		{"malformed", &gateway.RemoteError{Failure: protocol.Failure{Code: "private-message-canary", Retryable: true}}, http.StatusInternalServerError, "internal_error"},
		{"nil", (*gateway.RemoteError)(nil), http.StatusInternalServerError, "internal_error"},
		{"untyped", errors.New("private-message-canary"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.stop()
			inspector := projectInspectorFunc(func(context.Context, domain.Destination, domain.ContextBinding) (protocol.ProjectCapability, domain.Transmission, error) {
				return protocol.ProjectCapability{}, domain.Transmission{}, tc.failure
			})
			var err error
			f.handler, err = adminapi.NewHandler(adminapi.Options{Store: f.store, Authority: f.authority, Disconnector: disconnectFunc(func(context.Context, domain.DeviceID) error { return nil }), Random: rand.Reader, Now: func() time.Time { return f.now }, Projects: inspector})
			check(t, err)
			f.start(t)
			body := `{"device_id":"device","project_alias":"project","root_guard":"` + guard("root") + `","project_guard":"` + guard("project") + `"}`
			status, data := f.request(t, http.MethodPost, "/v1/projects/refresh", body)
			var failure adminapi.Failure
			check(t, json.Unmarshal(data, &failure))
			if status != tc.status || failure.Code != tc.code || failure.Committed || strings.Contains(string(data), "private-message-canary") {
				t.Fatalf("unsafe or unhelpful private failure: status=%d code=%q committed=%t", status, failure.Code, failure.Committed)
			}
		})
	}
}
