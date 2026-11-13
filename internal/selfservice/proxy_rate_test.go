package selfservice

import (
	"net/http"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

func TestHTTPSProxyBucketsIsolateClientsAndMetadataFromRevocation(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceManage}, func(o *Options) { o.TrustLoopbackProxyIP = true })
	proxy := func(ip string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("X-Real-IP", ip) }
	}
	for attempt := range 11 {
		status, _, _ := request(t, f, http.MethodGet, contract.DescriptorPath, nil, proxy("192.0.2.10"))
		want := http.StatusOK
		if attempt == 10 {
			want = http.StatusTooManyRequests
		}
		if status != want {
			t.Fatalf("metadata attempt %d returned %d, want %d", attempt, status, want)
		}
	}
	status, _, _ := request(t, f, http.MethodGet, contract.DescriptorPath, nil, proxy("198.51.100.20"))
	if status != http.StatusOK {
		t.Fatal("one proxy client exhausted another client's metadata budget")
	}
	status, _, _ = request(t, f, http.MethodPost, contract.RevocationPath, []byte(`{"device_id":"device"}`), proxy("192.0.2.10"))
	if status != http.StatusOK || f.calls.Load() != 1 {
		t.Fatal("metadata exhaustion blocked authenticated owner revocation")
	}
}
