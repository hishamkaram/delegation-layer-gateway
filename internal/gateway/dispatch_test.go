package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
	"github.com/hishamkaram/delegation-layer-gateway/internal/testsupport"
)

type dispatchAdmin struct{}

func (dispatchAdmin) AuthorizeAdmin(context.Context) error { return nil }
func dispatchMust[T any](t *testing.T, value T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func dispatchOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func dispatchCode(t *testing.T, err error, code domain.ErrorCode) {
	t.Helper()
	var classified *domain.Error
	if !errors.As(err, &classified) || classified.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

// The controlled link owns queue claims and writes. All observations of durable
// effects use the real registry API; this double never simulates store results.
type controlledLink struct {
	store        *registry.Store
	now          func() time.Time
	releaseError error
	snapshot     LinkSnapshot
	reserveError error
	beforeWrite  func(context.Context) error
	awaitError   error
	respond      func(context.Context, protocol.Command) (protocol.Reply, error)
	published    []protocol.Command
	reserves     int
	writes       int
	awaits       int
	releases     int
	nextRequest  int
}

func (l *controlledLink) Snapshot(domain.DeviceID) (LinkSnapshot, error) { return l.snapshot, nil }
func (l *controlledLink) Reserve(_ context.Context, device domain.DeviceID, operation domain.OperationID, command protocol.Command) (Reservation, error) {
	l.reserves++
	if l.reserveError != nil {
		return nil, l.reserveError
	}
	if device != l.snapshot.Credential.Device {
		return nil, domain.Reject(domain.Conflict)
	}
	payload, err := protocol.Encode(command, protocol.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	l.nextRequest++
	requestID := "g:" + strconv.Itoa(l.nextRequest)
	frame, err := protocol.EncodeFrame(protocol.Frame{Version: protocol.Version, Type: protocol.Request, RequestID: requestID, Generation: protocol.Generation{BootEpoch: string(l.snapshot.Connection.BootEpoch), Counter: l.snapshot.Connection.Counter}, OperationID: string(operation), TTLMillis: 30000, Payload: payload})
	if err != nil {
		return nil, err
	}
	digest := domain.Hash(payload)
	return &controlledReservation{owner: l, command: command, route: routing.Request{Credential: l.snapshot.Credential, ProcessBoot: l.snapshot.ProcessBoot, Payload: payload, Call: protocol.ControlCall{Generation: protocol.Generation{BootEpoch: string(l.snapshot.Connection.BootEpoch), Counter: l.snapshot.Connection.Counter}, RequestID: requestID, OperationID: string(operation), Operation: command.Operation, RequestSHA256: hex.EncodeToString(digest[:])}}, transmission: domain.Transmission{Operation: operation, Credential: l.snapshot.Credential, Connection: l.snapshot.Connection, EncodedFrameBytes: len(frame)}}, nil
}

type controlledReservation struct {
	owner            *controlledLink
	transmission     domain.Transmission
	command          protocol.Command
	route            routing.Request
	armed, published bool
}

func (r *controlledReservation) Routing() (routing.Request, error) { return r.route, nil }
func (r *controlledReservation) ArmRouting(route routing.Request) error {
	r.route = route
	r.armed = true
	return nil
}

func (r *controlledReservation) Transmission() domain.Transmission { return r.transmission }
func (r *controlledReservation) TransferSnapshot() routing.TransferSnapshot {
	// This fixture has no socket. Its reserved size is known; wire delivery is not.
	return routing.TransferSnapshot{WriteState: routing.WriteNotStarted, EncodedRequestFrameBytes: r.transmission.EncodedFrameBytes}
}

func (r *controlledReservation) Publish(ctx context.Context, guard func(context.Context) error) error {
	if r.owner.beforeWrite != nil {
		if err := r.owner.beforeWrite(ctx); err != nil {
			return err
		}
	}
	if err := guard(ctx); err != nil {
		return err
	}
	r.owner.writes++
	r.published = true
	r.owner.published = append(r.owner.published, r.command)
	return nil
}

func (r *controlledReservation) Await(ctx context.Context) (protocol.Reply, error) {
	r.owner.awaits++
	if r.owner.respond != nil {
		reply, err := r.owner.respond(ctx, r.command)
		if err == nil {
			// This controlled CLI has actually settled before delivering its reply.
			// Delegate task liveness/outcome is deliberately independent of this proof.
			err = r.owner.store.CompleteRouting(ctx, r.route.Credential, r.transmission.Connection, protocol.ControlCompletion{ProcessBoot: r.route.ProcessBoot, Call: r.route.Call, Disposition: protocol.ControlSettled}, r.owner.now())
		}
		return reply, err
	}
	return protocol.Reply{}, r.owner.awaitError
}

func (r *controlledReservation) Release(ctx context.Context) error {
	r.owner.releases++
	if r.owner.releaseError != nil {
		return r.owner.releaseError
	}
	if r.armed && !r.published {
		return r.owner.store.ReleaseUnpublishedRouting(ctx, r.route)
	}
	return nil
}

type dispatchEntropy struct {
	reads int
	deny  bool
}

func (r *dispatchEntropy) Read(data []byte) (int, error) {
	r.reads++
	if r.deny {
		return 0, errors.New("unexpected operation entropy read")
	}
	for i := range data {
		data[i] = byte(i + r.reads)
	}
	return len(data), nil
}

type dispatchFixture struct {
	store       *registry.Store
	service     *Service
	link        *controlledLink
	entropy     *dispatchEntropy
	actor       domain.Actor
	destination domain.Destination
	request     domain.FrozenRequest
	now         time.Time
	path        string
}

func dispatchOptions(gateway domain.GatewayID) registry.Options {
	return registry.Options{Gateway: gateway, Admin: dispatchAdmin{}}
}

func newDispatchFixture(t *testing.T) *dispatchFixture {
	t.Helper()
	f := &dispatchFixture{now: time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC), path: filepath.Join(t.TempDir(), "registry.sqlite"), destination: domain.Destination{Device: "device", Project: "project"}, entropy: &dispatchEntropy{}}
	store, err := registry.Create(t.Context(), f.path, registry.CreateOptions{Admin: dispatchAdmin{}})
	f.store = dispatchMust(t, store, err)
	t.Cleanup(func() { dispatchOK(t, f.store.Close()) })
	principal, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "alice"})
	p := dispatchMust(t, principal, err)
	f.actor = domain.Actor{Principal: p.ID, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}}
	device, err := f.store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: f.destination.Device, Name: "Fixture"})
	_ = dispatchMust(t, device, err)
	dispatchOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: f.destination, Context: domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard("root")), Project: domain.ProjectGuard(protocol.WireContextGuard("project-guard"))}}))
	f.grant(t)
	credential := issueDispatchCredential(t, f.store, f.now)
	connection, err := f.store.NextConnectionGeneration(t.Context(), credential, "boot", f.now)
	generation := dispatchMust(t, connection, err)
	f.link = &controlledLink{awaitError: errors.New("controlled acknowledgement loss"), snapshot: LinkSnapshot{Credential: credential, Connection: generation, ObservedAt: f.now, Capabilities: protocol.CapabilityReport{ObservedAt: f.now, Projects: []protocol.ProjectCapability{{Alias: "project", Context: protocol.ContextBinding{Root: protocol.WireContextGuard("root"), Project: protocol.WireContextGuard("project-guard")}, AdmissionGeneration: "generation", AdmissionOpen: true, ContractVersion: protocol.Version, Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}, Providers: []protocol.ProviderCapability{{Provider: "provider", Permissions: []string{"read-only"}, MaxBudgetSeconds: 300, Authentication: "unknown"}}, Ready: true}}}}}
	f.request = domain.FrozenRequest{Provider: "provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: domain.ReadOnly, BudgetSeconds: 60, Brief: "sensitive fixture brief"}
	f.link.store = f.store
	f.link.now = func() time.Time { return f.now }
	f.link.snapshot.ProcessBoot = strings.Repeat("1", 32)
	f.reconcileRouting(t)
	root := testsupport.OpenRoot(t, t.Context(), f.store, domain.RootInitializationStart{Route: f.destination, ExpectedContext: domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard("root")), Project: domain.ProjectGuard(protocol.WireContextGuard("project-guard"))}, Credential: credential, Connection: generation, Now: f.now})
	f.link.snapshot.Capabilities.Projects[0].AdmissionGeneration = string(root.Generation)
	service, err := New(f.store, f.link, dispatchIdentity(t, f.store), f.entropy, func() time.Time { return f.now }, RoutingObserverFunc(func(RoutingObservation) {}))
	f.service = dispatchMust(t, service, err)
	return f
}

func (f *dispatchFixture) grant(t *testing.T) {
	t.Helper()
	dispatchOK(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination}, Scopes: f.actor.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 300}}))
}

func issueDispatchCredential(t *testing.T, store *registry.Store, now time.Time) domain.CredentialRef {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceKey := dispatchMust(t, key, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, deviceKey)
	csrDER := dispatchMust(t, csr, err)
	info, err := devicecert.ParseCSR(csrDER)
	csrInfo := dispatchMust(t, info, err)
	token := domain.Hash([]byte("fixture enrollment token"))
	dispatchOK(t, store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: token, Device: "device", Mode: domain.Regular, Generation: 1, CreatedAt: now, ExpiresAt: now.Add(domain.EnrollmentTTL)}))
	serial := make([]byte, 16)
	serial[0] = 1
	intent, err := store.BeginEnrollment(t.Context(), domain.EnrollmentAttempt{TokenHash: token, CSRHash: csrInfo.CSRHash, PublicKeyHash: csrInfo.PublicKeyHash, Issuance: "issuance", Serial: serial, Now: now})
	reserved := dispatchMust(t, intent, err)
	ca := dispatchCA(t, now)
	certificate, err := ca.Sign(t.Context(), reserved, csrDER, new(big.Int).SetBytes(serial), rand.Reader)
	der := dispatchMust(t, certificate, err)
	receipt, err := store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: reserved.ID, CertificateDER: der, Now: now})
	completed := dispatchMust(t, receipt, err)
	return completed.Intent.Credential
}

func dispatchCA(t *testing.T, now time.Time) *devicecert.CertificateAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := dispatchMust(t, key, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	der := dispatchMust(t, certificate, err)
	parsed, err := x509.ParseCertificate(der)
	public := dispatchMust(t, parsed, err)
	ca, err := devicecert.NewCertificateAuthority(public, signer)
	return dispatchMust(t, ca, err)
}

func (f *dispatchFixture) prepare(t *testing.T) domain.PreparedOperation {
	t.Helper()
	operation, err := f.service.Prepare(t.Context(), f.actor, f.destination, f.request)
	return dispatchMust(t, operation, err)
}

func (f *dispatchFixture) view(t *testing.T, operation domain.OperationID) domain.OperationView {
	t.Helper()
	operationView, err := f.store.GetOperation(t.Context(), f.actor, operation)
	return dispatchMust(t, operationView, err)
}

func assertUnsent(t *testing.T, f *dispatchFixture, operation domain.OperationID) {
	t.Helper()
	view := f.view(t, operation)
	if view.Delivery != domain.Prepared || view.Reserved || f.link.writes != 0 || f.link.awaits != 0 {
		t.Fatal("pre-send failure changed durable delivery or wrote transport bytes")
	}
	if routingOutstandingFixture(t, f) != 0 {
		t.Fatal("pre-send rejection leaked a routing permit")
	}
}

func TestPrepareRejectsOverflowAndWrongRoutingWithoutPersistentEffects(t *testing.T) {
	cases := []struct {
		name   string
		change func(*dispatchFixture)
	}{
		{"encoded frame overflow", func(f *dispatchFixture) { f.request.Brief = strings.Repeat("\x00", domain.MaxBriefBytes) }},
		{"unknown explicit alias", func(f *dispatchFixture) { f.destination.Project = "missing" }},
		{"context substitution", func(f *dispatchFixture) {
			f.link.snapshot.Capabilities.Projects[0].Context.Project = protocol.WireContextGuard("substituted")
		}},
		{"capability refusal", func(f *dispatchFixture) { f.link.snapshot.Capabilities.Projects[0].Ready = false }},
		{"wrong device snapshot", func(f *dispatchFixture) { f.link.snapshot.Credential.Device = "other-device" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newDispatchFixture(t)
			test.change(f)
			_, err := f.service.Prepare(t.Context(), f.actor, f.destination, f.request)
			if err == nil {
				t.Fatal("invalid preparation accepted")
			}
			if test.name == "encoded frame overflow" {
				dispatchCode(t, err, domain.ResourceLimit)
			}
			operations, listErr := f.store.ListOperations(t.Context(), f.actor, domain.OperationPageRequest{})
			page := dispatchMust(t, operations, listErr)
			if len(page.Items) != 0 || f.link.reserves != 0 || f.link.writes != 0 {
				t.Fatal("rejected preparation left operation or transport side effects")
			}
		})
	}
}

func TestConfirmationRejectsChangedCapabilityAndQueueRefusalBeforePossibleSend(t *testing.T) {
	cases := []struct {
		name   string
		change func(*dispatchFixture)
	}{
		{"alias", func(f *dispatchFixture) { f.link.snapshot.Capabilities.Projects[0].Alias = "other" }},
		{"context", func(f *dispatchFixture) {
			f.link.snapshot.Capabilities.Projects[0].Context.Root = protocol.WireContextGuard("other-root")
		}},
		{"admission generation", func(f *dispatchFixture) {
			f.link.snapshot.Capabilities.Projects[0].AdmissionGeneration = "other-generation"
		}},
		{"provider ceiling", func(f *dispatchFixture) { f.link.snapshot.Capabilities.Projects[0].Providers[0].MaxBudgetSeconds = 30 }},
		{"queue refusal", func(f *dispatchFixture) { f.link.reserveError = domain.Reject(domain.ResourceLimit) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newDispatchFixture(t)
			prepared := f.prepare(t)
			test.change(f)
			if _, err := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation); err == nil {
				t.Fatal("unsafe confirmation accepted")
			}
			assertUnsent(t, f, prepared.Correlation.Operation)
		})
	}
}

func TestPossibleSendCommitPrecedesPublishAndLostAckSurvivesRestart(t *testing.T) {
	f := newDispatchFixture(t)
	prepared := f.prepare(t)
	f.link.beforeWrite = func(ctx context.Context) error {
		return f.checkPossibleSend(ctx, prepared.Correlation)
	}
	result, err := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	if !errors.Is(err, f.link.awaitError) || result.Operation.Delivery != domain.PossibleSend || !result.Operation.Reserved {
		t.Fatalf("lost ACK changed accounting: %+v %v", result, err)
	}
	assertDispatchTransportCounts(t, f.link, 1, 1, 1)
	dispatchOK(t, f.store.Close())
	store, err := registry.Open(t.Context(), f.path, dispatchOptions(prepared.Correlation.Gateway))
	f.store = dispatchMust(t, store, err)
	f.link.store = f.store
	f.entropy.deny = true
	service, err := New(f.store, f.link, dispatchIdentity(t, f.store), f.entropy, func() time.Time { return f.now }, RoutingObserverFunc(func(RoutingObservation) {}))
	f.service = dispatchMust(t, service, err)
	dispatcher := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	result, err = f.service.Dispatch(t.Context(), dispatcher, prepared.Correlation.Operation)
	duplicate := dispatchMust(t, result, err)
	if duplicate.Operation.Correlation != prepared.Correlation || !duplicate.Operation.Reserved || duplicate.Operation.Observation != nil {
		t.Fatal("restart changed correlation/reservation or exposed task-read cache")
	}
	if f.link.writes != 1 || f.link.reserves != 1 || f.entropy.reads != 1 {
		t.Fatal("duplicate confirmation generated IDs, queued or transmitted new admission")
	}
}

func (f *dispatchFixture) checkPossibleSend(ctx context.Context, correlation domain.Correlation) error {
	view, err := f.store.GetOperation(ctx, f.actor, correlation.Operation)
	if err != nil {
		return err
	}
	if view.Delivery != domain.PossibleSend || !view.Reserved || view.Correlation != correlation {
		return errors.New("publish preceded durable possible-send correlation")
	}
	status, routeErr := f.store.CheckRoutingReadiness(ctx, f.link.snapshot.Credential, f.link.snapshot.Connection, f.now)
	if routeErr != nil {
		return routeErr
	}
	if status.Outstanding != 1 {
		return errors.New("publish preceded durable routing permit")
	}
	return nil
}

func assertDispatchTransportCounts(t *testing.T, link *controlledLink, writes, awaits, releases int) {
	t.Helper()
	if link.writes != writes || link.awaits != awaits || link.releases != releases {
		t.Fatalf("transport counts writes/awaits/releases=%d/%d/%d, want %d/%d/%d", link.writes, link.awaits, link.releases, writes, awaits, releases)
	}
}

func TestResolvedDuplicateDispatchOnlyDoesNotRerouteOrReadResults(t *testing.T) {
	f := newDispatchFixture(t)
	prepared := f.prepare(t)
	_, err := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	if !errors.Is(err, f.link.awaitError) {
		t.Fatalf("unexpected initial admission result: %v", err)
	}
	resolution := domain.ValidatedResolution{ValidatedObservation: domain.ValidatedObservation{Correlation: prepared.Correlation, Connection: f.link.snapshot.Connection, Credential: f.link.snapshot.Credential, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Terminal, Closure: &domain.ClosureEvidence{Kind: domain.ClosureRegisteredNative, Reference: domain.Hash([]byte("canonical joined owner fixture"))}, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("spec")), Result: &domain.ResultDescriptor{Digest: domain.Hash([]byte("accepted")), Bytes: 8}}}, DurableRequest: true}
	_, err = f.store.ApplyResolution(t.Context(), resolution)
	dispatchOK(t, err)
	f.entropy.deny = true
	dispatcher := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	result, err := f.service.Dispatch(t.Context(), dispatcher, prepared.Correlation.Operation)
	duplicate := dispatchMust(t, result, err)
	if duplicate.Operation.Correlation != prepared.Correlation || duplicate.Operation.Delivery != domain.Resolved || duplicate.Operation.Observation != nil {
		t.Fatal("resolved duplicate changed identity or exposed cached results")
	}
	assertDispatchTransportCounts(t, f.link, 1, 1, 1)
	if f.link.reserves != 1 || f.entropy.reads != 1 {
		t.Fatal("resolved confirmation rerouted work or generated a new identity")
	}
	_, err = f.store.GetOperation(t.Context(), dispatcher, prepared.Correlation.Operation)
	dispatchCode(t, err, domain.Forbidden)
}

func TestRevocationBetweenCommitAndPublishDeniesWriteAndRetainsUncertainty(t *testing.T) {
	f := newDispatchFixture(t)
	prepared := f.prepare(t)
	f.link.beforeWrite = func(ctx context.Context) error {
		view, err := f.store.GetOperation(ctx, f.actor, prepared.Correlation.Operation)
		if err != nil {
			return err
		}
		if !view.Reserved || view.Delivery != domain.PossibleSend {
			return errors.New("revocation hook ran before durable reservation")
		}
		return f.store.RevokeGrant(ctx, domain.GrantKey{Principal: f.actor.Principal, Destination: f.destination})
	}
	_, err := f.service.Dispatch(t.Context(), f.actor, prepared.Correlation.Operation)
	dispatchCode(t, err, domain.NotFound)
	if f.link.writes != 0 || f.link.awaits != 0 || f.link.releases != 1 {
		t.Fatal("revoked queued frame was written or its resource leaked")
	}
	f.grant(t) // Explicit admin reapproval permits inspecting the retained devicecert.
	view := f.view(t, prepared.Correlation.Operation)
	if !view.Reserved || view.Delivery != domain.PossibleSend {
		t.Fatal("revocation incorrectly proved absence or freed uncertain execution capacity")
	}
}

func dispatchIdentity(t *testing.T, s *registry.Store) domain.GatewayID {
	t.Helper()
	id, err := s.Identity(t.Context())
	return dispatchMust(t, id, err)
}
