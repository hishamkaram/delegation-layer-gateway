package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestHTTP2OriginRejectionCountsWithoutWritingAudit(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	before := routingAuditRecords(t, f) // Startup performs its own admitted probe.
	base, ok := f.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("fixture transport is not configurable")
	}
	transport := base.Clone()
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP2(true) // Negotiate only H2; do not assume ALPN policy.
	t.Cleanup(transport.CloseIdleConnections)
	client := *f.client
	client.Transport = transport
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.cfg.PublicURL+"/.well-known/oauth-protected-resource", nil)
	require(t, err)
	request.Header.Set("Origin", "https://foreign.invalid")
	response, err := client.Do(request)
	require(t, err)
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
	require(t, errors.Join(readErr, response.Body.Close()))
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusForbidden || !strings.Contains(string(data), "forbidden") {
		t.Fatalf("origin boundary: HTTP%d status%d", response.ProtoMajor, response.StatusCode)
	}
	if events := routingAuditRecords(t, f); !slices.Equal(before, events) {
		t.Fatalf("pre-admission request reached audited handler: %+v", events)
	}
	writer := httptest.NewRecorder()
	f.runtime.metrics.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "http://unix/metrics", nil))
	if !strings.Contains(writer.Body.String(), `gateway_boundary_rejections_total{reason="origin"} 1`) {
		t.Fatal("real H2 origin rejection lost its exact aggregate counter")
	}
	if health := f.runtime.Health(); health.AuditFailures != 0 || health.MetricFailures != 0 {
		t.Fatalf("counter-only rejection fabricated sink failures: %+v", health)
	}
}
