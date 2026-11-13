package selfservice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

type authFunc func(context.Context, string) (identity.VerifiedToken, error)

func (f authFunc) AuthenticateToken(ctx context.Context, token string) (identity.VerifiedToken, error) {
	return f(ctx, token)
}

type enrollFunc func(context.Context, domain.Actor, domain.RequestID, string, []byte, domain.DeviceID, uint64) (domain.CertificateReceipt, error)

func (f enrollFunc) SelfEnroll(ctx context.Context, actor domain.Actor, request domain.RequestID, name string, csr []byte, replace domain.DeviceID, generation uint64) (domain.CertificateReceipt, error) {
	return f(ctx, actor, request, name, csr, replace, generation)
}

type revokeFunc func(context.Context, domain.Actor, domain.DeviceID) error

func (f revokeFunc) RevokeOwned(ctx context.Context, actor domain.Actor, device domain.DeviceID) error {
	return f(ctx, actor, device)
}

type handlerSlot struct{ next http.Handler }

type fixture struct {
	server     *httptest.Server
	handler    http.Handler
	descriptor contract.Descriptor
	calls      atomic.Int32
	options    Options
}

func newFixture(t *testing.T, scopes domain.ScopeSet, configure func(*Options)) *fixture {
	t.Helper()
	var target atomic.Pointer[handlerSlot]
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := target.Load()
		if current == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		current.next.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	f := &fixture{server: server}
	now := time.Now()
	actor := domain.Actor{Principal: "principal", Scopes: scopes}
	options := Options{
		Descriptor: descriptor(t, server.URL), Now: func() time.Time { return now },
		Authenticator: authFunc(func(_ context.Context, token string) (identity.VerifiedToken, error) {
			if token != "good-token" {
				return identity.VerifiedToken{}, errors.New("PRIVATE_SECRET")
			}
			return identity.VerifiedToken{Actor: actor, ExpiresAt: now.Add(time.Minute)}, nil
		}),
		Enroller: enrollFunc(func(_ context.Context, _ domain.Actor, _ domain.RequestID, _ string, _ []byte, _ domain.DeviceID, _ uint64) (domain.CertificateReceipt, error) {
			f.calls.Add(1)
			return domain.CertificateReceipt{Intent: domain.IssuanceIntent{Credential: domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}, Mode: domain.Regular}, CertificateDER: []byte("CERTIFICATE")}, nil
		}),
		Revoker: revokeFunc(func(_ context.Context, _ domain.Actor, _ domain.DeviceID) error { f.calls.Add(1); return nil }),
	}
	if configure != nil {
		configure(&options)
	}
	h, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.handler, f.descriptor, f.options = h, options.Descriptor, options
	target.Store(&handlerSlot{next: h})
	return f
}

func descriptor(t *testing.T, origin string) contract.Descriptor {
	t.Helper()
	return contract.Descriptor{
		SchemaVersion: 1, GatewayID: "gateway", PublicURL: origin, Issuer: "https://issuer.example/", NativeClientID: "native-client", Audience: origin + "/mcp",
		EnrollmentURL: origin + "/v1/enroll", SelfEnrollmentURL: origin + contract.EnrollmentPath, RevokeURL: origin + contract.RevocationPath,
		DeviceWSSURL: "wss://127.0.0.1:8443/device", DeviceCAPEM: publicCA(t), SupportedWireVersions: []int{1}, Capabilities: []string{"self-enrollment-v1"},
	}
}

func publicCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func encodedRequest(t *testing.T, request contract.EnrollmentRequest) []byte {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func validRequest() contract.EnrollmentRequest {
	return contract.EnrollmentRequest{RequestID: strings.Repeat("1", 32), Name: "Owned workstation", CSRDERBase64: base64.StdEncoding.EncodeToString([]byte("CSR"))}
}

func request(t *testing.T, f *fixture, method, path string, body []byte, modify func(*http.Request)) (int, http.Header, []byte) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer good-token")
	if modify != nil {
		modify(r)
	}
	response, err := f.server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(response.Body, contract.MaxBodyBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, data
}

func TestHTTPSDescriptorIsPublicAndDoesNotAdvertiseUnimplementedV2(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, nil)
	status, headers, body := request(t, f, http.MethodGet, contract.DescriptorPath, nil, func(r *http.Request) { r.Header.Del("Authorization") })
	var got contract.Descriptor
	if status != http.StatusOK || protocol.DecodeStrict(body, &got, contract.MaxBodyBytes) != nil || got.Validate() != nil || len(got.SupportedWireVersions) != 1 || got.SupportedWireVersions[0] != 1 {
		t.Fatal("public descriptor changed or advertised unsupported wire behavior")
	}
	if headers.Get("Cache-Control") != "no-store" || headers.Get("X-Content-Type-Options") != "nosniff" || f.calls.Load() != 0 {
		t.Fatal("metadata bypassed bounded admission or invoked management")
	}
}

func TestHTTPSManagementScopeAndVerifiedOwner(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, nil)
	status, _, body := request(t, f, http.MethodPost, contract.EnrollmentPath, encodedRequest(t, validRequest()), nil)
	var response contract.EnrollmentResponse
	if status != http.StatusOK || protocol.DecodeStrict(body, &response, contract.MaxBodyBytes) != nil || response.OwnerPrincipal != "principal" || response.RequestID != strings.Repeat("1", 32) || response.DeviceID != "device" || response.Generation != 1 {
		t.Fatal("enrollment omitted stable identities or trusted a submitted owner")
	}
	status, _, _ = request(t, f, http.MethodPost, contract.RevocationPath, []byte(`{"device_id":"device"}`), nil)
	if status != http.StatusForbidden || f.calls.Load() != 1 {
		t.Fatal("enrollment scope gained device-management authority")
	}
	readOnly := newFixture(t, domain.ScopeSet{domain.InventoryRead}, nil)
	status, _, _ = request(t, readOnly, http.MethodPost, contract.EnrollmentPath, encodedRequest(t, validRequest()), nil)
	if status != http.StatusForbidden || readOnly.calls.Load() != 0 {
		t.Fatal("task scope gained enrollment authority")
	}
}

func TestReplacementRequiresBothScopesBeforeUseCase(t *testing.T) {
	for _, scopes := range []domain.ScopeSet{{domain.DeviceEnroll}, {domain.DeviceManage}, {domain.DeviceEnroll, domain.DeviceManage}} {
		f := newFixture(t, scopes, nil)
		input := validRequest()
		input.ReplaceDeviceID, input.ExpectedGeneration = "device", 1
		status, _, _ := request(t, f, http.MethodPost, contract.EnrollmentPath, encodedRequest(t, input), nil)
		want := http.StatusForbidden
		if len(scopes) == 2 {
			want = http.StatusOK
		}
		if status != want {
			t.Fatalf("replacement scope isolation failed: %d", status)
		}
		if want != http.StatusOK && f.calls.Load() != 0 {
			t.Fatal("denied replacement reached issuance")
		}
	}
}

func TestHTTPSStrictBodiesAndBearerHeaders(t *testing.T) {
	for _, test := range []struct {
		name   string
		body   []byte
		modify func(*http.Request)
		status int
	}{
		{"duplicate", []byte(`{"request_id":"PRIVATE_SECRET","request_id":"duplicate"}`), nil, 400},
		{"owner input", []byte(`{"owner_principal":"PRIVATE_SECRET"}`), nil, 400},
		{"oversized", bytes.Repeat([]byte("x"), contract.MaxBodyBytes+1), nil, 400},
		{"query", nil, func(r *http.Request) { r.URL.RawQuery = "token=PRIVATE_SECRET" }, 400},
		{"empty query", nil, func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"encoded path", nil, func(r *http.Request) { r.URL.RawPath = "/v1/self/%65nroll" }, 400},
		{"wrong content", nil, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"multiple content", nil, func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 415},
		{"missing auth", nil, func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"multiple auth", nil, func(r *http.Request) { r.Header.Add("Authorization", "Bearer PRIVATE_SECRET") }, 401},
		{"combined auth", nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer good-token,PRIVATE_SECRET") }, 401},
		{"wrong scheme", nil, func(r *http.Request) { r.Header.Set("Authorization", "Basic PRIVATE_SECRET") }, 401},
		{"invalid bearer", nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer PRIVATE_SECRET") }, 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, nil)
			body := test.body
			if body == nil {
				body = encodedRequest(t, validRequest())
			}
			status, _, response := request(t, f, http.MethodPost, contract.EnrollmentPath, body, test.modify)
			if status != test.status || bytes.Contains(response, []byte("PRIVATE_SECRET")) || f.calls.Load() != 0 {
				t.Fatalf("ambiguous request reached management or leaked data: status=%d", status)
			}
		})
	}
}

func TestRevocationReceiptDoesNotClaimSocketOrTaskClosure(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceManage}, nil)
	status, _, body := request(t, f, http.MethodPost, contract.RevocationPath, []byte(`{"device_id":"device"}`), nil)
	if status != http.StatusOK || string(body) != `{"device_id":"device","revoked":true}` || f.calls.Load() != 1 {
		t.Fatal("revocation receipt changed or manufactured execution closure")
	}
}

func TestTokenDeadlineBoundsUseCaseAndExpiredResponseIsWithheld(t *testing.T) {
	now := time.Now()
	expires := now.Add(15 * time.Second)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	var deadlineChecked atomic.Bool
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, func(options *Options) {
		options.Now = func() time.Time { return time.Unix(0, clock.Load()) }
		options.Authenticator = authFunc(func(_ context.Context, _ string) (identity.VerifiedToken, error) {
			return identity.VerifiedToken{Actor: domain.Actor{Principal: "principal", Scopes: domain.ScopeSet{domain.DeviceEnroll}}, ExpiresAt: expires}, nil
		})
		original := options.Enroller
		options.Enroller = enrollFunc(func(ctx context.Context, actor domain.Actor, id domain.RequestID, name string, csr []byte, device domain.DeviceID, generation uint64) (domain.CertificateReceipt, error) {
			deadline, ok := ctx.Deadline()
			deadlineChecked.Store(ok && deadline.Equal(expires))
			clock.Store(expires.UnixNano())
			return original.SelfEnroll(ctx, actor, id, name, csr, device, generation)
		})
	})
	status, headers, body := request(t, f, http.MethodPost, contract.EnrollmentPath, encodedRequest(t, validRequest()), nil)
	if !deadlineChecked.Load() || status != http.StatusUnauthorized || headers.Get("WWW-Authenticate") == "" || bytes.Contains(body, []byte("CERTIFICATE")) {
		t.Fatal("JWT expiry did not bound response exposure")
	}
}

func TestUnavailableErrorsAreSanitized(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, func(options *Options) {
		options.Enroller = enrollFunc(func(context.Context, domain.Actor, domain.RequestID, string, []byte, domain.DeviceID, uint64) (domain.CertificateReceipt, error) {
			return domain.CertificateReceipt{}, errors.New("PRIVATE_SECRET")
		})
	})
	status, _, body := request(t, f, http.MethodPost, contract.EnrollmentPath, encodedRequest(t, validRequest()), nil)
	if status != http.StatusServiceUnavailable || string(body) != `{"error":"enrollment_unavailable"}` {
		t.Fatal("underlying storage/signer failure was serialized")
	}
}

func TestUnavailableIssuerDoesNotClaimInvalidCredentials(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, func(options *Options) {
		options.Authenticator = authFunc(func(context.Context, string) (identity.VerifiedToken, error) {
			return identity.VerifiedToken{}, &identity.Error{Code: identity.KeysUnavailable}
		})
	})
	status, headers, body := request(t, f, http.MethodPost, contract.EnrollmentPath, encodedRequest(t, validRequest()), nil)
	if status != http.StatusServiceUnavailable || headers.Get("WWW-Authenticate") != "" || string(body) != `{"error":"authentication_unavailable"}` || f.calls.Load() != 0 {
		t.Fatal("issuer failure was reported as invalid credentials or reached enrollment")
	}
}

func TestCancellationDoesNotReleaseManagementCapacityBeforeReturn(t *testing.T) {
	gate, release := context.WithCancel(t.Context())
	defer release()
	started := make(chan struct{})
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, func(options *Options) {
		options.ConcurrentRequests = 1
		original := options.Enroller
		options.Enroller = enrollFunc(func(ctx context.Context, actor domain.Actor, id domain.RequestID, name string, csr []byte, device domain.DeviceID, generation uint64) (domain.CertificateReceipt, error) {
			close(started)
			<-gate.Done() // The owned use case deliberately outlives client cancellation.
			return original.SelfEnroll(ctx, actor, id, name, csr, device, generation)
		})
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, f.server.URL+contract.EnrollmentPath, bytes.NewReader(encodedRequest(t, validRequest())))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer good-token")
	done := make(chan struct{})
	go func() {
		defer close(done)
		response, requestErr := f.server.Client().Do(r)
		if requestErr != nil {
			if !errors.Is(requestErr, context.Canceled) {
				t.Error(requestErr)
			}
			return
		}
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	t.Cleanup(func() { release(); cancel(); <-done })
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("management did not acquire its capacity")
	}
	cancel()
	<-done
	status, _, _ := request(t, f, http.MethodGet, contract.DescriptorPath, nil, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatal("client cancellation released capacity while management still owned it")
	}
	release()
}

func TestMetadataSnapshotAndMethods(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, nil)
	f.options.Descriptor.Capabilities[0] = "unadvertised"
	status, _, body := request(t, f, http.MethodGet, contract.DescriptorPath, nil, nil)
	if status != http.StatusOK || bytes.Contains(body, []byte("unadvertised")) {
		t.Fatal("caller mutated published metadata after construction")
	}
	status, headers, _ := request(t, f, http.MethodPost, contract.DescriptorPath, nil, nil)
	if status != http.StatusMethodNotAllowed || headers.Get("Allow") != http.MethodGet {
		t.Fatal("descriptor accepted a mutation method")
	}
	status, headers, _ = request(t, f, http.MethodGet, contract.EnrollmentPath, nil, nil)
	if status != http.StatusMethodNotAllowed || headers.Get("Allow") != http.MethodPost {
		t.Fatal("enrollment accepted a read method")
	}
	status, _, _ = request(t, f, http.MethodGet, "/not-a-route", nil, nil)
	if status != http.StatusNotFound || f.calls.Load() != 0 {
		t.Fatal("unknown route reached management")
	}
}

func TestCSRTransportEncodingMustBeCanonical(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, nil)
	input := validRequest()
	input.CSRDERBase64 += "\n"
	status, _, _ := request(t, f, http.MethodPost, contract.EnrollmentPath, encodedRequest(t, input), nil)
	if status != http.StatusBadRequest || f.calls.Load() != 0 {
		t.Fatal("noncanonical CSR transport encoding reached issuance")
	}
}

func TestSocketIPRateLimitIgnoresForwardedClaims(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, nil)
	for attempt := range 11 {
		status, _, _ := request(t, f, http.MethodGet, contract.DescriptorPath, nil, func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", strings.Repeat("1", attempt+1))
		})
		if attempt < 10 && status != http.StatusOK {
			t.Fatal("metadata rate limit rejected before its bounded burst")
		}
		if attempt == 10 && status != http.StatusTooManyRequests {
			t.Fatal("forwarded identity bypassed the real socket bucket")
		}
	}
}

func TestConstructorRejectsPrivateCAAndChangedOrigins(t *testing.T) {
	f := newFixture(t, domain.ScopeSet{domain.DeviceEnroll}, nil)
	for _, change := range []func(*Options){
		func(v *Options) {
			v.Descriptor.DeviceCAPEM = "-----BEGIN PRIVATE KEY-----\nPRIVATE_SECRET\n-----END PRIVATE KEY-----"
		},
		func(v *Options) { v.Descriptor.DeviceCAPEM = "PRIVATE_SECRET\n" + v.Descriptor.DeviceCAPEM },
		func(v *Options) {
			v.Descriptor.DeviceCAPEM = "-----BEGIN CERTIFICATE-----\nPRIVATE_SECRET\n-----END CERTIFICATE-----\n" + v.Descriptor.DeviceCAPEM
		},
		func(v *Options) { v.Descriptor.Audience = "https://other.example/mcp" },
		func(v *Options) { v.Descriptor.DeviceWSSURL = "wss://other.example/device" },
		func(v *Options) { v.Descriptor.SupportedWireVersions = []int{3} },
		func(v *Options) { v.Descriptor.EnrollmentURL += "?token=PRIVATE_SECRET" },
		func(v *Options) { v.ConcurrentRequests = 129 },
	} {
		input := f.options
		change(&input)
		if _, err := New(input); err == nil || strings.Contains(err.Error(), "PRIVATE_SECRET") {
			t.Fatal("invalid descriptor admitted or private configuration reflected")
		}
	}
}
