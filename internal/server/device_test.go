package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func (f *fixture) enrollDevice(t *testing.T) (*deviceidentity.Store, tls.Certificate) {
	t.Helper()
	f.adminCall(t, "/v1/devices", adminapi.RegisterDeviceInput{DeviceID: "device", Name: "Workstation"}, nil)
	var token adminapi.Enrollment
	f.adminCall(t, "/v1/enrollment-tokens", adminapi.EnrollmentInput{DeviceID: "device", Mode: domain.Regular, Generation: 1}, &token)
	store, err := deviceidentity.Open(filepath.Join(t.TempDir(), "identity"))
	owned := checked(t, store, err)
	t.Cleanup(func() { require(t, owned.Close()) })
	csr, err := owned.EnsureKey(rand.Reader)
	require(t, err)
	status, data := f.request(t, f.client, http.MethodPost, f.cfg.PublicURL+"/v1/enroll", jsonBytes(t, enrollment.EnrollmentRequest{Token: token.Token, CSRDERBase64: base64.StdEncoding.EncodeToString(csr)}), "")
	if status != 200 {
		t.Fatalf("enrollment failed: %d %s", status, data)
	}
	var response enrollment.EnrollmentResponse
	require(t, json.Unmarshal(data, &response))
	der, err := base64.StdEncoding.DecodeString(response.CertificateDERBase64)
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(f.deviceCA.certificate)
	ref := domain.CredentialRef{Device: domain.DeviceID(response.DeviceID), Epoch: domain.CredentialEpoch(response.Epoch), Generation: response.Generation}
	require(t, owned.InstallEnrollment(der, ref, roots, time.Now()))
	certificate, _, err := owned.Certificate(roots, time.Now())
	require(t, err)
	return owned, certificate
}

func (f *fixture) deviceURL(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(f.runtime.Addresses().Device)
	require(t, err)
	return "https://localhost:" + port + "/device"
}

func (f *fixture) deviceHTTP(t *testing.T, certificate *tls.Certificate) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(f.publicCA.certificate)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	owned := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig}
	t.Cleanup(owned.CloseIdleConnections)
	return &http.Client{Transport: owned, Timeout: 10 * time.Second}
}

func TestRuntimeEnrollmentMutualTLSHostAndRevocation(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	_, certificate := f.enrollDevice(t)
	endpoint := f.deviceURL(t)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
	require(t, err)
	if response, requestErr := f.deviceHTTP(t, nil).Do(request); requestErr == nil {
		require(t, response.Body.Close())
		t.Fatal("device listener accepted absent client certificate")
	}
	authenticated := f.deviceHTTP(t, &certificate)
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Host = "attacker.example" }, func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") }, func(r *http.Request) { r.Header.Set("Origin", f.cfg.PublicURL) }} {
		req, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
		require(t, requestErr)
		change(req)
		response, responseErr := authenticated.Do(req)
		require(t, responseErr)
		require(t, response.Body.Close())
		if response.StatusCode != 403 {
			t.Fatal("device accepted substituted Host/forwarding/origin")
		}
	}
	report := protocol.CapabilityReport{ObservedAt: time.Now()}
	connected := diagnosticDeviceDial(t, transport.ClientConfig{URL: strings.Replace(endpoint, "https://", "wss://", 1), GatewayID: f.runtime.gatewayID, Certificate: certificate.Leaf, Capabilities: report, Routing: &emptyCensus{boot: strings.Repeat("a", 32)}}, authenticated)
	t.Cleanup(func() { require(t, connected.Close()) })
	snapshot, err := f.runtime.hub.Snapshot("device")
	if got := checked(t, snapshot, err); !got.Online || !got.RoutingReady || got.CredentialMode != domain.Regular {
		t.Fatal("actual enrolled mutualTLS device did not authenticate/reconcile")
	}
	revoked := true
	f.adminCall(t, "/v1/devices/revocation", adminapi.DeviceRevocationInput{DeviceID: "device", Revoked: &revoked}, nil)
	if _, err = f.runtime.hub.Snapshot("device"); err == nil {
		t.Fatal("durable device revocation retained current WSS socket")
	}
	_, err = transport.Dial(t.Context(), transport.ClientConfig{URL: strings.Replace(endpoint, "https://", "wss://", 1), GatewayID: f.runtime.gatewayID, Certificate: certificate.Leaf, Capabilities: report, Routing: &emptyCensus{boot: strings.Repeat("b", 32)}}, authenticated, time.Now)
	if err == nil {
		t.Fatal("revoked certificate reconnected")
	}
}

type emptyCensus struct{ boot string }

func (c *emptyCensus) Inventory(_ context.Context, generation domain.ConnectionGeneration) (protocol.ControlInventory, error) {
	return protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: c.boot, BarrierID: strings.Repeat("c", 32), Generation: protocol.Generation{BootEpoch: string(generation.BootEpoch), Counter: generation.Counter}, Complete: true}, nil
}

func (c *emptyCensus) Acknowledge(_ context.Context, ack protocol.ControlInventoryAck) error {
	if ack.Validate() != nil || ack.ProcessBoot != c.boot {
		return errors.New("invalid fixture routing ACK")
	}
	return nil
}

// dialEvidence records phase classes only: no URL, headers, body, key or raw error.
type dialEvidence struct {
	mu                          sync.Mutex
	base                        http.RoundTripper
	tlsStarted, tlsDone, reused bool
	status                      int
	httpElapsed                 time.Duration
	httpErrors                  []string
}

func (d *dialEvidence) RoundTrip(request *http.Request) (*http.Response, error) {
	started := time.Now()
	response, roundErr := d.base.RoundTrip(request)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.httpElapsed = time.Since(started)
	d.httpErrors = dialErrorTypes(roundErr)
	if response != nil {
		d.status = response.StatusCode
	}
	return response, roundErr
}

func dialErrorTypes(err error) []string {
	if err == nil {
		return nil
	}
	result := []string{fmt.Sprintf("%T", err)}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		for _, cause := range joined.Unwrap() {
			result = append(result, dialErrorTypes(cause)...)
		}
		return result
	}
	var single interface{ Unwrap() error }
	if errors.As(err, &single) {
		result = append(result, dialErrorTypes(single.Unwrap())...)
	}

	return result
}

func diagnosticDeviceDial(t *testing.T, config transport.ClientConfig, client *http.Client) *transport.Client {
	t.Helper()
	evidence := &dialEvidence{base: client.Transport}
	owned := *client
	owned.Transport = evidence
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { evidence.mu.Lock(); evidence.tlsStarted = true; evidence.mu.Unlock() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { evidence.mu.Lock(); evidence.tlsDone = true; evidence.mu.Unlock() },
		GotConn: func(info httptrace.GotConnInfo) {
			evidence.mu.Lock()
			evidence.reused = info.Reused
			evidence.mu.Unlock()
		},
	}
	ctx := httptrace.WithClientTrace(t.Context(), trace)
	started := time.Now()
	connected, dialErr := transport.Dial(ctx, config, &owned, time.Now)
	evidence.mu.Lock()
	defer evidence.mu.Unlock()
	if dialErr != nil {
		t.Fatalf("device dial failed: elapsed=%s http_elapsed=%s status=%d tls_started=%t tls_done=%t reused=%t deadline=%t canceled=%t protocol=%t context_deadline=%t error_types=%v http_error_types=%v", time.Since(started), evidence.httpElapsed, evidence.status, evidence.tlsStarted, evidence.tlsDone, evidence.reused, errors.Is(dialErr, context.DeadlineExceeded), errors.Is(dialErr, context.Canceled), errors.Is(dialErr, transport.ErrProtocol), errors.Is(ctx.Err(), context.DeadlineExceeded), dialErrorTypes(dialErr), evidence.httpErrors)
	}
	t.Logf("device dial phases: elapsed=%s http_elapsed=%s status=%d tls_started=%t tls_done=%t reused=%t", time.Since(started), evidence.httpElapsed, evidence.status, evidence.tlsStarted, evidence.tlsDone, evidence.reused)
	return connected
}
