package mcpadapter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
	"github.com/hishamkaram/delegation-layer-gateway/internal/testsupport"
)

const privateCanary = "PRIVATE_CANARY_TOKEN_AND_LOCAL_PATH_71bb"

type fixtureClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *fixtureClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *fixtureClock) advance() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = c.value.Add(time.Second)
}

type fixtureAdmin struct{}

func (fixtureAdmin) AuthorizeAdmin(context.Context) error { return nil }
func checked[T any](t *testing.T, value T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Token claims are fixture values, not evidence of OAuth/JWT validation. Real
// identity verification belongs to the independently tested identity package.
type fixtureAuthenticator struct {
	alice, bob domain.Actor
	clock      *fixtureClock
}

func (a fixtureAuthenticator) AuthenticateToken(_ context.Context, token string) (identity.VerifiedToken, error) {
	actor := a.alice
	expires := a.clock.now().Add(24 * time.Hour)
	switch token {
	case "alice":
	case "inventory":
		actor.Scopes = domain.ScopeSet{domain.InventoryRead}
	case "read":
		actor.Scopes = domain.ScopeSet{domain.TaskRead}
	case "dispatch":
		actor.Scopes = domain.ScopeSet{domain.TaskDispatch}
	case "management":
		actor.Scopes = domain.ScopeSet{domain.DeviceEnroll, domain.DeviceManage}
	case "bob":
		actor = a.bob
	case "expired":
		expires = time.Now().Add(-24 * time.Hour)
	default:
		return identity.VerifiedToken{}, &identity.Error{Code: identity.InvalidToken}
	}
	return identity.VerifiedToken{Actor: actor, ExpiresAt: expires}, nil
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

type fixtureLink struct {
	store       *registry.Store
	now         func() time.Time
	nextRequest int
	snapshot    gateway.LinkSnapshot
	err         error
	commands    []protocol.Command
}

func (l *fixtureLink) Snapshot(device domain.DeviceID) (gateway.LinkSnapshot, error) {
	if l.err != nil {
		return gateway.LinkSnapshot{}, l.err
	}
	if device != l.snapshot.Credential.Device {
		return gateway.LinkSnapshot{}, &gateway.RemoteError{Failure: protocol.Failure{Code: "device_offline", Retryable: true}}
	}
	return l.snapshot, nil
}

func (l *fixtureLink) Reserve(_ context.Context, device domain.DeviceID, operation domain.OperationID, command protocol.Command) (gateway.Reservation, error) {
	if device != l.snapshot.Credential.Device {
		return nil, domain.Reject(domain.NotFound)
	}
	encoded, err := protocol.Encode(command, protocol.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	l.nextRequest++
	requestID := "g:" + strconv.Itoa(l.nextRequest)
	frame, err := protocol.EncodeFrame(protocol.Frame{Version: protocol.Version, Type: protocol.Request, RequestID: requestID, Generation: protocol.Generation{BootEpoch: string(l.snapshot.Connection.BootEpoch), Counter: l.snapshot.Connection.Counter}, OperationID: string(operation), TTLMillis: 30000, Payload: encoded})
	if err != nil {
		return nil, err
	}
	digest := domain.Hash(encoded)
	return &fixtureReservation{link: l, command: command, route: routing.Request{Credential: l.snapshot.Credential, ProcessBoot: l.snapshot.ProcessBoot, Payload: encoded, Call: protocol.ControlCall{Generation: protocol.Generation{BootEpoch: string(l.snapshot.Connection.BootEpoch), Counter: l.snapshot.Connection.Counter}, RequestID: requestID, OperationID: string(operation), Operation: command.Operation, RequestSHA256: hexDigest(digest)}}, transmission: domain.Transmission{Operation: operation, Credential: l.snapshot.Credential, Connection: l.snapshot.Connection, EncodedFrameBytes: len(frame)}}, nil
}

type fixtureReservation struct {
	link             *fixtureLink
	command          protocol.Command
	transmission     domain.Transmission
	route            routing.Request
	armed, published bool
}

func (r *fixtureReservation) Routing() (routing.Request, error) { return r.route, nil }
func (r *fixtureReservation) ArmRouting(route routing.Request) error {
	r.route = route
	r.armed = true
	return nil
}

func (r *fixtureReservation) Transmission() domain.Transmission { return r.transmission }
func (r *fixtureReservation) TransferSnapshot() routing.TransferSnapshot {
	return routing.TransferSnapshot{WriteState: routing.WriteNotStarted, EncodedRequestFrameBytes: r.transmission.EncodedFrameBytes}
}

func (r *fixtureReservation) Publish(ctx context.Context, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return err
	}
	r.link.commands = append(r.link.commands, r.command)
	r.published = true
	return nil
}

func (r *fixtureReservation) Release(ctx context.Context) error {
	if r.armed && !r.published {
		return r.link.store.ReleaseUnpublishedRouting(ctx, r.route)
	}
	return nil
}

func (r *fixtureReservation) Await(ctx context.Context) (protocol.Reply, error) {
	task, err := peerTask(r.command)
	if err != nil {
		return protocol.Reply{}, err
	}
	if task.SpecSHA256 == "" {
		task.SpecSHA256 = hexDigest(domain.Hash([]byte("fixture Delegate spec")))
	}
	digest, err := r.link.admittedBrief(task.TaskID)
	if err != nil {
		return protocol.Reply{}, err
	}
	observation := protocol.TaskObservation{Task: task, BriefSHA256: hexDigest(digest), Resolution: "existing", Admission: "admitted", Liveness: "running", Publication: "pending"}
	body, err := protocol.Encode(observation, protocol.MaxFrameBytes)
	if err == nil {
		// The fixture CLI has finished its Wait and cleanup before response receipt;
		// the running Delegate task still owns its independent execution reservation.
		err = r.link.store.CompleteRouting(ctx, r.route.Credential, r.transmission.Connection, protocol.ControlCompletion{ProcessBoot: r.route.ProcessBoot, Call: r.route.Call, Disposition: protocol.ControlSettled}, r.link.now())
	}
	return protocol.Reply{Operation: r.command.Operation, Body: body}, err
}

func peerTask(command protocol.Command) (protocol.TaskBinding, error) {
	if command.Operation == protocol.Admit {
		var request protocol.Admission
		if err := protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes); err != nil {
			return protocol.TaskBinding{}, err
		}
		return request.Task, nil
	}
	var request protocol.TaskControl
	if err := protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes); err != nil {
		return protocol.TaskBinding{}, err
	}
	return request.Task, nil
}

// The controlled peer owns admission bytes. Passive requests carry only a
// binding, so their brief digest comes from that original admitted request.
func (l *fixtureLink) admittedBrief(task string) (domain.Digest, error) {
	for _, command := range l.commands {
		if command.Operation != protocol.Admit {
			continue
		}
		var request protocol.Admission
		if err := protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes); err != nil {
			return domain.Digest{}, err
		}
		if request.Task.TaskID == task {
			return domain.Hash([]byte(request.Brief)), nil
		}
	}
	return domain.Digest{}, errors.New("controlled peer has no admitted task")
}
func hexDigest(value domain.Digest) string { return hex.EncodeToString(value[:]) }

type fixture struct {
	store      *registry.Store
	service    *gateway.Service
	link       *fixtureLink
	adapter    *Adapter
	server     *httptest.Server
	clock      *fixtureClock
	alice, bob domain.Actor
}

func newFixture(t *testing.T, count int) *fixture {
	t.Helper()
	return newRecordedFixture(t, count, nil)
}

func newRecordedFixture(t *testing.T, count int, recorder Recorder) *fixture {
	t.Helper()
	return newConfiguredFixture(t, count, recorder, nil)
}

func newConfiguredFixture(t *testing.T, count int, recorder Recorder, configure func(*Options)) *fixture {
	t.Helper()
	f := &fixture{clock: &fixtureClock{value: time.Now().UTC().Truncate(time.Second)}, link: &fixtureLink{}}
	store, err := registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.sqlite"), registry.CreateOptions{Admin: fixtureAdmin{}})
	f.store = checked(t, store, err)
	f.link.store = f.store
	f.link.now = f.clock.now
	t.Cleanup(func() { check(t, f.store.Close()) })
	f.alice = f.principal(t, "alice")
	f.bob = f.principal(t, "bob")
	for i := range count {
		f.registerDevice(t, i)
	}
	if count > 0 {
		f.enrollPrimary(t)
	}
	generatedID, identityErr := store.Identity(t.Context())
	check(t, identityErr)
	service, err := gateway.New(f.store, f.link, generatedID, rand.Reader, f.clock.now, gateway.RoutingObserverFunc(func(gateway.RoutingObservation) {}))
	f.service = checked(t, service, err)
	mux := http.NewServeMux()
	f.server = httptest.NewUnstartedServer(mux)
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	options := Options{Registry: f.store, Operations: f.service, Presence: f.link, Authenticator: fixtureAuthenticator{alice: f.alice, bob: f.bob, clock: f.clock}, ResourceURL: f.server.URL + "/mcp", Issuer: "https://issuer.example/", Timeout: 30 * time.Second, Now: f.clock.now, Recorder: recorder}
	if configure != nil {
		configure(&options)
	}
	adapter, err := New(options)
	f.adapter = checked(t, adapter, err)
	guard, err := httpguard.New(httpguard.Options{PublicOrigin: f.server.URL, ConcurrentRequests: 128, Timeout: 35 * time.Second, MaxBodyBytes: 1 << 20})
	secure := checked(t, guard, err)
	mux.Handle("/mcp", secure.Wrap(f.adapter.Handler()))
	mux.Handle("/.well-known/oauth-protected-resource/mcp", secure.Wrap(f.adapter.Metadata()))
	return f
}

func (f *fixture) principal(t *testing.T, subject string) domain.Actor {
	t.Helper()
	principal, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: subject})
	p := checked(t, principal, err)
	return domain.Actor{Principal: p.ID, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}}
}

func deviceID(index int) domain.DeviceID { return domain.DeviceID(fmt.Sprintf("device-%03d", index)) }

func (f *fixture) registerDevice(t *testing.T, index int) {
	t.Helper()
	id := deviceID(index)
	device, err := f.store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: id, Name: fmt.Sprintf("Workstation %03d", index)})
	_ = checked(t, device, err)
	destination := domain.Destination{Device: id, Project: "public"}
	check(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: destination, Context: domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard(privateCanary)), Project: domain.ProjectGuard(protocol.WireContextGuard("private project path"))}}))
	check(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.alice.Principal, Destination: destination}, Scopes: f.alice.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 120}}))
}

func (f *fixture) enrollPrimary(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	private := checked(t, key, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	csrDER := checked(t, csr, err)
	info, err := devicecert.ParseCSR(csrDER)
	parsed := checked(t, info, err)
	token := domain.Hash([]byte("fixture enrollment"))
	now := f.clock.now()
	check(t, f.store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: token, Device: deviceID(0), Mode: domain.Regular, Generation: 1, CreatedAt: now, ExpiresAt: now.Add(domain.EnrollmentTTL)}))
	serial := make([]byte, 16)
	serial[0] = 1
	intent, err := f.store.BeginEnrollment(t.Context(), domain.EnrollmentAttempt{TokenHash: token, CSRHash: parsed.CSRHash, PublicKeyHash: parsed.PublicKeyHash, Issuance: "issuance", Serial: serial, Now: now})
	reserved := checked(t, intent, err)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := checked(t, caKey, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	caDER := checked(t, der, err)
	certificate, err := x509.ParseCertificate(caDER)
	certificateCA := checked(t, certificate, err)
	ca, err := devicecert.NewCertificateAuthority(certificateCA, signer)
	authority := checked(t, ca, err)
	der, err = authority.Sign(t.Context(), reserved, csrDER, new(big.Int).SetBytes(serial), rand.Reader)
	leaf := checked(t, der, err)
	receipt, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: reserved.ID, CertificateDER: leaf, Now: now})
	completed := checked(t, receipt, err)
	connection, err := f.store.NextConnectionGeneration(t.Context(), completed.Intent.Credential, "boot", now)
	generation := checked(t, connection, err)
	root := testsupport.OpenRoot(t, t.Context(), f.store, domain.RootInitializationStart{Route: domain.Destination{Device: deviceID(0), Project: "public"}, ExpectedContext: domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard(privateCanary)), Project: domain.ProjectGuard(protocol.WireContextGuard("private project path"))}, Credential: completed.Intent.Credential, Connection: generation, Now: now})
	f.link.snapshot = gateway.LinkSnapshot{Credential: completed.Intent.Credential, Connection: generation, ObservedAt: now, Capabilities: protocol.CapabilityReport{ObservedAt: now, Projects: []protocol.ProjectCapability{{Alias: "public", Context: protocol.ContextBinding{Root: protocol.WireContextGuard(privateCanary), Project: protocol.WireContextGuard("private project path")}, AdmissionGeneration: string(root.Generation), AdmissionOpen: true, ContractVersion: protocol.Version, Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}, Providers: []protocol.ProviderCapability{{Provider: "provider", Models: []string{"model"}, Efforts: []string{"high"}, Permissions: []string{"read-only", "workspace-write"}, MaxBudgetSeconds: 300, Authentication: "unknown"}}, Ready: true}}}}
	f.link.snapshot.ProcessBoot = strings.Repeat("1", 32)
	status, routingErr := f.store.ReconcileRouting(t.Context(), completed.Intent.Credential, protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: f.link.snapshot.ProcessBoot, BarrierID: strings.Repeat("a", 32), Generation: protocol.Generation{BootEpoch: string(generation.BootEpoch), Counter: generation.Counter}, Complete: true}, now)
	if !checked(t, status, routingErr).Ready {
		t.Fatal("fixture routing handshake blocked")
	}
}

func (f *fixture) session(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()
	clientHTTP := *f.server.Client()
	clientHTTP.Transport = bearerTransport{base: clientHTTP.Transport, token: token}
	client := mcp.NewClient(&mcp.Implementation{Name: "gateway-test", Version: "1"}, &mcp.ClientOptions{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: f.server.URL + "/mcp", HTTPClient: &clientHTTP, DisableStandaloneSSE: true, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	connected := checked(t, session, err)
	t.Cleanup(func() { check(t, connected.Close()) })
	return connected
}

func (f *fixture) call(t *testing.T, session *mcp.ClientSession, name string, args json.RawMessage) *mcp.CallToolResult {
	t.Helper()
	f.clock.advance() // Refill the production limiter using its configured clock.
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	return checked(t, result, err)
}

// The SDK exposes extension and structured JSON as any. Round-trip that SDK
// boundary into concrete wire DTOs before inspecting values; no unchecked casts.
func sdkValue[T any](t *testing.T, value any) T {
	t.Helper()
	encoded, err := json.Marshal(value)
	data := checked(t, encoded, err)
	var result T
	check(t, json.Unmarshal(data, &result))
	return result
}

type resultWire struct {
	IsError bool `json:"isError"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Structured json.RawMessage `json:"structuredContent"`
	Meta       struct {
		Challenges []string `json:"mcp/www_authenticate"`
	} `json:"_meta"`
}

func decodeResult[T any](t *testing.T, result *mcp.CallToolResult) Envelope[T] {
	t.Helper()
	wire := sdkValue[resultWire](t, result)
	if len(wire.Content) != 1 || wire.Content[0].Type != "text" || len(wire.Structured) == 0 {
		t.Fatal("tool omitted structured content or JSON text compatibility")
	}
	var structured, text Envelope[T]
	check(t, protocol.DecodeStrict(wire.Structured, &structured, 1<<20))
	check(t, protocol.DecodeStrict([]byte(wire.Content[0].Text), &text, 1<<20))
	if !reflect.DeepEqual(structured, text) || wire.IsError != (structured.Error != nil) {
		t.Fatal("structured content/text/error classification disagree")
	}
	return structured
}

func expectError[T any](t *testing.T, result *mcp.CallToolResult, code string) {
	t.Helper()
	envelope := decodeResult[T](t, result)
	if envelope.Error == nil || envelope.Error.Code != code || envelope.Data != nil {
		t.Fatalf("want error %s, got %+v", code, envelope)
	}
}
