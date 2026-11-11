package recovery_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
	"github.com/hishamkaram/delegation-layer-gateway/internal/wirelink"
)

type (
	recoveryAuthorityKey struct{}
	recoveryAuthority    struct{ revoked atomic.Bool }
)

func (a *recoveryAuthority) AuthorizeAdmin(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if ctx.Value(recoveryAuthorityKey{}) != true || a.revoked.Load() {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

func recoveryOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func recoveryKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	recoveryOK(t, err)
	return k
}

func recoveryCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	recoveryOK(t, err)
	return c
}

// This strict routing peer models protocol ownership only. It owns no task or
// provider and reports no Delegate execution or native process closure.
type recoveryCensus struct{}

func (recoveryCensus) Inventory(ctx context.Context, g domain.ConnectionGeneration) (protocol.ControlInventory, error) {
	return protocol.ControlInventory{PolicyVersion: protocol.RoutingPolicyVersion, ProcessBoot: strings.Repeat("a", 32), BarrierID: strings.Repeat("b", 32), Generation: protocol.Generation{BootEpoch: string(g.BootEpoch), Counter: g.Counter}, Complete: true}, ctx.Err()
}

func (recoveryCensus) Acknowledge(ctx context.Context, _ protocol.ControlInventoryAck) error {
	return ctx.Err()
}

type recoveryTLS struct {
	peerGeneration   string
	peerOpen         bool
	stalePostReopen  bool
	rootOnlyRequired bool
	taskResponse     func(*testing.T, protocol.Command) protocol.TaskObservation
	ctx              context.Context
	admin            *recoveryAuthority
	store            *registry.Store
	hub              *transport.Hub
	peer             *transport.Client
	link             *wirelink.Link
	service          *recovery.Service
	initializer      *recovery.Initializer
	lookup           domain.RootInitializationLookup
	id               domain.GatewayID
	ref              domain.CredentialRef
	now              time.Time
}

func newRecoveryTLS(t *testing.T) *recoveryTLS {
	t.Helper()
	f := &recoveryTLS{admin: &recoveryAuthority{}, now: time.Now().UTC().Truncate(time.Second).Add(time.Millisecond)}
	f.ctx = context.WithValue(t.Context(), recoveryAuthorityKey{}, true)
	var err error
	f.store, err = registry.Create(f.ctx, filepath.Join(t.TempDir(), "registry.sqlite"), registry.CreateOptions{Admin: f.admin})
	recoveryOK(t, err)
	t.Cleanup(func() { recoveryOK(t, f.store.Close()) })
	f.id, err = f.store.Identity(f.ctx)
	recoveryOK(t, err)
	ca, cert, ref := issueRecoveryCredential(t, f.store, f.now.Truncate(time.Second))
	f.ref = ref
	binding := protocol.ContextBinding{Root: protocol.WireContextGuard("private-root"), Project: protocol.WireContextGuard("private-project")}
	f.lookup = domain.RootInitializationLookup{Route: domain.Destination{Device: "device-one", Project: "project-one"}, ExpectedContext: domain.ContextBinding{Root: domain.RootGuard(binding.Root), Project: domain.ProjectGuard(binding.Project)}}
	recoveryOK(t, f.store.RegisterProject(f.ctx, domain.ProjectRegistration{Destination: f.lookup.Route, Context: f.lookup.ExpectedContext}))
	f.hub, err = transport.NewHub(t.Context(), transport.Config{GatewayID: f.id, BootEpoch: "recovery-test-boot", Routing: f.store}, f.store, func() time.Time { return f.now })
	recoveryOK(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := httptest.NewUnstartedServer(f.hub)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(func() { recoveryOK(t, f.hub.Close()) })
	base, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected HTTP transport")
	}
	owned := base.Clone()
	owned.TLSClientConfig = base.TLSClientConfig.Clone()
	owned.TLSClientConfig.Certificates = []tls.Certificate{cert}
	t.Cleanup(owned.CloseIdleConnections)
	caps := protocol.CapabilityReport{ObservedAt: f.now, Projects: []protocol.ProjectCapability{{Alias: "project-one", Context: binding, ContractVersion: protocol.Version, Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}}}}
	f.peer, err = transport.Dial(t.Context(), transport.ClientConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https"), GatewayID: f.id, Certificate: cert.Leaf, Capabilities: caps, Routing: recoveryCensus{}}, &http.Client{Transport: owned}, func() time.Time { return f.now })
	recoveryOK(t, err)
	t.Cleanup(func() { recoveryOK(t, f.peer.Close()) })
	ready, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	recoveryOK(t, f.hub.WaitReady(ready, "device-one"))
	f.link, err = wirelink.New(f.hub)
	recoveryOK(t, err)
	f.service, err = recovery.New(f.store, f.link, f.id, func() time.Time { return f.now })
	recoveryOK(t, err)
	f.initializer, err = recovery.NewInitializer(f.store, f.service, func() time.Time { return f.now })
	recoveryOK(t, err)
	return f
}

func issueRecoveryCredential(t *testing.T, store *registry.Store, now time.Time) (*x509.Certificate, tls.Certificate, domain.CredentialRef) {
	t.Helper()
	caKey := recoveryKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "routing device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, caErr := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if caErr != nil {
		t.Fatal(caErr)
	}
	caCertificate := recoveryCertificate(t, caDER)
	ca, authorityErr := identity.NewCertificateAuthority(caCertificate, caKey)
	if authorityErr != nil {
		t.Fatal(authorityErr)
	}
	key := recoveryKey(t)
	csr, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if csrErr != nil {
		t.Fatal(csrErr)
	}
	info, infoErr := identity.ParseCSR(csr)
	if infoErr != nil {
		t.Fatal(infoErr)
	}
	if _, registerErr := store.RegisterDevice(context.WithValue(t.Context(), recoveryAuthorityKey{}, true), domain.DeviceRegistration{ID: "device-one", Name: "routing fixture"}); registerErr != nil {
		t.Fatal(registerErr)
	}
	token := domain.Hash([]byte("owned routing enrollment"))
	serial := make([]byte, 16)
	serial[0] = 1
	if grantErr := store.CreateEnrollment(context.WithValue(t.Context(), recoveryAuthorityKey{}, true), domain.EnrollmentGrant{TokenHash: token, Device: "device-one", Mode: domain.Regular, Generation: 1, CreatedAt: now, ExpiresAt: now.Add(domain.EnrollmentTTL)}); grantErr != nil {
		t.Fatal(grantErr)
	}
	intent, intentErr := store.BeginEnrollment(context.WithValue(t.Context(), recoveryAuthorityKey{}, true), domain.EnrollmentAttempt{TokenHash: token, CSRHash: info.CSRHash, PublicKeyHash: info.PublicKeyHash, Issuance: "fixture-issuance", Serial: serial, Now: now})
	if intentErr != nil {
		t.Fatal(intentErr)
	}
	leafDER, signErr := ca.Sign(context.WithValue(t.Context(), recoveryAuthorityKey{}, true), intent, csr, new(big.Int).SetBytes(serial), rand.Reader)
	if signErr != nil {
		t.Fatal(signErr)
	}
	if _, completeErr := store.CompleteIssuance(context.WithValue(t.Context(), recoveryAuthorityKey{}, true), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: leafDER, Now: now}); completeErr != nil {
		t.Fatal(completeErr)
	}
	leaf := recoveryCertificate(t, leafDER)
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key, Leaf: leaf}
	return caCertificate, certificate, intent.Credential
}

// runRecoveryCall joins its one caller even when a peer assertion fails.
func runRecoveryCall(t *testing.T, f *recoveryTLS, operations []protocol.Operation, call func(context.Context) error, corrupt bool) error {
	t.Helper()
	bounded, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	ctx, fail := context.WithCancelCause(bounded)
	defer fail(nil)
	done := make(chan error, 1)
	go func() {
		err := call(ctx)
		done <- err
		if err != nil {
			fail(err)
		}
	}()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	for _, op := range operations {
		f.answer(t, ctx, op, corrupt)
	}
	select {
	case err := <-done:
		joined = true
		return err
	case <-ctx.Done():
		select {
		case err := <-done:
			joined = true
			return err
		default:
			t.Fatal("recovery caller did not join")
			return ctx.Err()
		}
	}
}

func (f *recoveryTLS) answer(t *testing.T, ctx context.Context, op protocol.Operation, corrupt bool) {
	t.Helper()
	received, err := f.peer.Receive(ctx)
	if err != nil {
		t.Fatalf("receive recovery control: %v; caller cause: %v", err, context.Cause(ctx))
	}
	frame, err := received.Claim(ctx)
	recoveryOK(t, err)
	var command protocol.Command
	recoveryOK(t, protocol.DecodeStrict(frame.Payload, &command, protocol.MaxFrameBytes))
	if command.Operation != op || command.Project != string(f.lookup.Route.Project) || frame.Generation.Counter != f.peer.Generation().Counter {
		t.Fatal("wrong operation, alias or authenticated generation")
	}
	digest := domain.Hash(frame.Payload)
	if received.ControlCall().RequestSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("control does not bind exact encoded command")
	}
	progress, err := f.store.ReadRootInitializationProgress(ctx, f.lookup)
	recoveryOK(t, err)
	body := f.responseBody(t, command, progress, corrupt, frame.OperationID)
	replyCtx, stopReply := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stopReply()
	recoveryOK(t, received.ReplyControl(replyCtx, protocol.Reply{Operation: op, Body: body}, protocol.ControlCompletion{ProcessBoot: strings.Repeat("a", 32), Call: received.ControlCall(), Disposition: protocol.ControlSettled}))
}

func (f *recoveryTLS) responseBody(t *testing.T, c protocol.Command, p domain.RootInitializationProgress, corrupt bool, operation string) []byte {
	t.Helper()
	var response any
	switch c.Operation {
	case protocol.ContextInspect:
		response = f.inspectionResponse(t, c, p)
	case protocol.OriginBarrier:
		var input protocol.OriginBarrierRequest
		recoveryOK(t, protocol.DecodeStrict(c.Body, &input, protocol.MaxFrameBytes))
		expected := protocol.OriginBarrierRequest{GatewayID: string(f.id), RecoveryID: string(p.RecoveryID), Generation: string(p.Generation), ExpectedRoot: string(f.lookup.ExpectedContext.Root)}
		if input != expected || p.Generation == "" {
			t.Fatal("barrier does not bind Registry-minted expected-absent plan")
		}
		f.peerGeneration = input.Generation
		f.peerOpen = false
		response = protocol.OriginStateReport{GatewayID: input.GatewayID, RecoveryID: input.RecoveryID, Generation: input.Generation}
	case protocol.OriginInventory:
		var input protocol.OriginInventoryRequest
		recoveryOK(t, protocol.DecodeStrict(c.Body, &input, protocol.MaxFrameBytes))
		expected := protocol.OriginInventoryRequest{GatewayID: string(f.id), Generation: string(p.Generation), ExpectedRoot: string(f.lookup.ExpectedContext.Root), Limit: domain.MaxPageLimit}
		if input != expected {
			t.Fatal("inventory changed canonical root, cursor or minted generation")
		}
		response = protocol.OriginInventoryReport{Entries: []protocol.OriginInventoryEntry{}, Complete: true, MembershipSHA256: strings.Repeat("1", 64), CompletenessReceipt: strings.Repeat("2", 64)}
	case protocol.OriginReopen:
		var input protocol.OriginReopenRequest
		recoveryOK(t, protocol.DecodeStrict(c.Body, &input, protocol.MaxFrameBytes))
		if p.Reopen == nil {
			t.Fatal("reopen before durable approval")
		}
		expected := protocol.OriginReopenRequest{GatewayID: string(f.id), RecoveryID: string(p.RecoveryID), Generation: string(p.Generation), ExpectedRoot: string(f.lookup.ExpectedContext.Root), CompletenessReceipt: hex.EncodeToString(p.Reopen.Completeness[:])}
		if input != expected {
			t.Fatal("reopen changed approved completeness receipt or namespace")
		}
		f.peerOpen = true
		response = protocol.OriginStateReport{GatewayID: input.GatewayID, RecoveryID: input.RecoveryID, Generation: input.Generation, AdmissionOpen: true}
	case protocol.Admit, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel:
		response = f.taskObservation(t, c, operation)
	default:
		t.Fatal("unexpected recovery operation")
	}
	response = corruptBarrierResponse(t, c.Operation, response, corrupt)
	body, err := protocol.Encode(response, protocol.MaxFrameBytes)
	recoveryOK(t, err)
	return body
}

func (f *recoveryTLS) inspectionResponse(t *testing.T, c protocol.Command, p domain.RootInitializationProgress) any {
	t.Helper()
	var input protocol.InspectRequest
	recoveryOK(t, protocol.DecodeStrict(c.Body, &input, protocol.MaxFrameBytes))
	if input.GatewayID != string(f.id) {
		t.Fatal("inspect gateway changed")
	}
	if f.rootOnlyRequired && !input.RootOnly {
		t.Fatal("namespace recovery required a live project inspection")
	}
	if !input.RootOnly {
		return protocol.ProjectCapability{Alias: string(f.lookup.Route.Project), Context: protocol.ContextBinding{Root: string(f.lookup.ExpectedContext.Root), Project: string(f.lookup.ExpectedContext.Project)}, ContractVersion: protocol.Version, Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}, AdmissionGeneration: f.peerGeneration, AdmissionOpen: f.peerOpen && !f.stalePostReopen, Ready: f.peerOpen && !f.stalePostReopen}
	}
	report := protocol.RootCapability{Root: string(f.lookup.ExpectedContext.Root), ContractVersion: protocol.Version, Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}, OriginRegistered: f.peerGeneration != ""}
	if report.OriginRegistered {
		report.Origin = &protocol.OriginStateReport{GatewayID: string(f.id), RecoveryID: string(p.RecoveryID), Generation: f.peerGeneration, AdmissionOpen: f.peerOpen && !f.stalePostReopen}
	}
	return report
}

func (f *recoveryTLS) taskObservation(t *testing.T, command protocol.Command, operation string) protocol.TaskObservation {
	t.Helper()
	if f.taskResponse == nil {
		t.Fatal("task operation crossed administrative fixture")
	}
	var binding protocol.TaskBinding
	if command.Operation == protocol.Cancel {
		var input protocol.Cancellation
		recoveryOK(t, protocol.DecodeStrict(command.Body, &input, protocol.MaxFrameBytes))
		binding = input.Task
	} else {
		var input protocol.TaskControl
		recoveryOK(t, protocol.DecodeStrict(command.Body, &input, protocol.MaxFrameBytes))
		binding = input.Task
	}
	if operation != binding.Origin.OperationID {
		t.Fatal("administrative frame changed the immutable task operation identity")
	}
	return f.taskResponse(t, command)
}

func corruptBarrierResponse(t *testing.T, operation protocol.Operation, response any, corrupt bool) any {
	t.Helper()
	if corrupt && operation == protocol.OriginBarrier {
		report, ok := response.(protocol.OriginStateReport)
		if !ok {
			t.Fatal("invalid corruption target")
		}
		report.Generation = "foreign-generation"
		response = report
	}
	return response
}

func (f *recoveryTLS) advance(t *testing.T, ops ...protocol.Operation) domain.RootInitializationProgress {
	t.Helper()
	var result domain.RootInitializationProgress
	recoveryOK(t, runRecoveryCall(t, f, ops, func(ctx context.Context) error {
		var err error
		result, err = f.initializer.Advance(ctx, f.lookup)
		return err
	}, false))
	return result
}

func (f *recoveryTLS) approved(t *testing.T) domain.RootInitializationProgress {
	t.Helper()
	p := f.advance(t, protocol.ContextInspect, protocol.OriginBarrier)
	if p.Stage != domain.RootNeedsInventory {
		t.Fatal("barrier did not advance durable phase")
	}
	p = f.advance(t, protocol.ContextInspect, protocol.OriginInventory)
	if p.Stage != domain.RootNeedsApproval {
		t.Fatal("inventory did not advance durable phase")
	}
	p = f.advance(t, protocol.ContextInspect)
	if p.Stage != domain.RootNeedsReopen || p.Reopen == nil || p.Reopen.Revision == 0 {
		t.Fatal("missing durable reopen approval")
	}
	return p
}

func TestInitializerRealSQLiteMutualTLS(t *testing.T) {
	f := newRecoveryTLS(t)
	approved := f.approved(t)
	p := f.advance(t, protocol.ContextInspect, protocol.OriginReopen, protocol.ContextInspect, protocol.ContextInspect)
	if p.Stage != domain.RootReady || p.Generation != approved.Generation || p.RecoveryID != approved.RecoveryID {
		t.Fatal("reopen did not preserve initialized namespace identity")
	}
	p = f.advance(t)
	if p.Stage != domain.RootReady {
		t.Fatal("ready retry changed durable phase")
	}
}

func TestNamespaceReopenNeedsNoProjectAttestation(t *testing.T) {
	f := newRecoveryTLS(t)
	p := f.approved(t)
	f.rootOnlyRequired = true
	err := runRecoveryCall(t, f, []protocol.Operation{protocol.OriginReopen, protocol.ContextInspect}, func(ctx context.Context) error {
		_, err := f.service.Reopen(ctx, f.lookup.Route, f.lookup.ExpectedContext.Root, *p.Reopen)
		return err
	}, false)
	recoveryOK(t, err)
}

func TestInitializerRejectsForeignBarrierReplyOverMutualTLS(t *testing.T) {
	f := newRecoveryTLS(t)
	err := runRecoveryCall(t, f, []protocol.Operation{protocol.ContextInspect, protocol.OriginBarrier}, func(ctx context.Context) error { _, err := f.initializer.Advance(ctx, f.lookup); return err }, true)
	var rejected *domain.Error
	if !errors.As(err, &rejected) || rejected.Code != domain.EvidenceInvalid {
		t.Fatalf("foreign barrier reply: %v", err)
	}
	p, err := f.store.ReadRootInitializationProgress(f.ctx, f.lookup)
	recoveryOK(t, err)
	if p.Stage != domain.RootNeedsBarrier {
		t.Fatal("foreign barrier reply committed durable evidence")
	}
}

// This wrapper delays the REAL socket writer's application guard. All buffer,
// routing, wire, receipt and cleanup behavior remains the production adapter.
type (
	recoveryGuardLink struct {
		gateway.Link
		entered chan struct{}
		resume  chan struct{}
	}
	recoveryGuardReservation struct {
		gateway.Reservation
		owner *recoveryGuardLink
	}
)

func (l *recoveryGuardLink) Reserve(ctx context.Context, d domain.DeviceID, id domain.OperationID, c protocol.Command) (gateway.Reservation, error) {
	r, err := l.Link.Reserve(ctx, d, id, c)
	if err != nil {
		return nil, err
	}
	return &recoveryGuardReservation{Reservation: r, owner: l}, nil
}

func (r *recoveryGuardReservation) Publish(ctx context.Context, guard func(context.Context) error) error {
	return r.Reservation.Publish(ctx, func(call context.Context) error {
		close(r.owner.entered)
		select {
		case <-r.owner.resume:
			return guard(call)
		case <-call.Done():
			return call.Err()
		}
	})
}

func TestRecoveryQueuedReopenRechecksRealRegistry(t *testing.T) {
	for _, fault := range []string{"approval_revision", "administrative_authority", "connection_generation"} {
		t.Run(fault, func(t *testing.T) {
			testQueuedRecoveryFault(t, fault)
		})
	}
}

func testQueuedRecoveryFault(t *testing.T, fault string) {
	t.Helper()
	f := newRecoveryTLS(t)
	p := f.approved(t)
	delayed := &recoveryGuardLink{Link: f.link, entered: make(chan struct{}), resume: make(chan struct{})}
	service, err := recovery.New(f.store, delayed, f.id, func() time.Time { return f.now })
	recoveryOK(t, err)
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, callErr := service.Reopen(ctx, f.lookup.Route, f.lookup.ExpectedContext.Root, *p.Reopen)
		done <- callErr
	}()
	released := false
	joined := false
	defer func() {
		if !released {
			close(delayed.resume)
		}
		cancel()
		if !joined {
			<-done
		}
	}()
	select {
	case <-delayed.entered:
	case err = <-done:
		joined = true
		t.Fatalf("call ended before actual writer guard: %v", err)
	case <-ctx.Done():
		t.Fatal("actual writer guard not reached")
	}
	f.invalidateQueued(t, fault, *p.Reopen)
	close(delayed.resume)
	released = true
	select {
	case err = <-done:
		joined = true
		if err == nil {
			t.Fatal("stale queued reopen reached success")
		}
	case <-ctx.Done():
		t.Fatal("rejected queued reopen did not join")
	}
	f.admin.revoked.Store(false)
	current, readErr := f.store.ReadRootInitializationProgress(f.ctx, f.lookup)
	recoveryOK(t, readErr)
	if current.Stage == domain.RootReady {
		t.Fatal("rejected queued reopen made root eligible")
	}
	noFrame, stop := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer stop()
	received, receiveErr := f.peer.Receive(noFrame)
	if received != nil || receiveErr == nil {
		t.Fatal("rejected queued reopen crossed socket")
	}
}

func (f *recoveryTLS) invalidateQueued(t *testing.T, fault string, target domain.ReopenTarget) {
	t.Helper()
	switch fault {
	case "approval_revision":
		recoveryOK(t, f.store.RestartInventory(f.ctx, target.Destination))
	case "administrative_authority":
		f.admin.revoked.Store(true)
	case "connection_generation":
		_, err := f.store.NextConnectionGeneration(f.ctx, f.ref, "superseding-connection", f.now)
		recoveryOK(t, err)
	default:
		t.Fatal("unknown queued fault")
	}
}

func TestRecoveryRequiresAdministrativeAuthorityBeforeWire(t *testing.T) {
	f := newRecoveryTLS(t)
	_, _, err := f.service.Inspect(t.Context(), f.lookup.Route, f.lookup.ExpectedContext)
	if err == nil {
		t.Fatal("untrusted context performed protected inspect")
	}
	noFrame, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	received, receiveErr := f.peer.Receive(noFrame)
	if received != nil || receiveErr == nil {
		t.Fatal("unauthorized inspect crossed socket")
	}
}

// The response boundary hook runs only after the production adapter has decoded
// a correlated strict-routing response and its durable completion hook settled.
type recoveryReplyLink struct {
	gateway.Link
	afterReply func() error
}
type recoveryReplyReservation struct {
	gateway.Reservation
	afterReply func() error
}

func (l recoveryReplyLink) Reserve(ctx context.Context, d domain.DeviceID, id domain.OperationID, c protocol.Command) (gateway.Reservation, error) {
	r, err := l.Link.Reserve(ctx, d, id, c)
	if err != nil {
		return nil, err
	}
	return recoveryReplyReservation{Reservation: r, afterReply: l.afterReply}, nil
}

func (r recoveryReplyReservation) Await(ctx context.Context) (protocol.Reply, error) {
	reply, err := r.Reservation.Await(ctx)
	if err != nil {
		return protocol.Reply{}, err
	}
	if err = r.afterReply(); err != nil {
		return protocol.Reply{}, err
	}
	return reply, nil
}

func TestRecoveryRechecksAuthorityAfterRealTLSResponse(t *testing.T) {
	for _, fault := range []string{"administrative_authority", "connection_generation"} {
		t.Run(fault, func(t *testing.T) {
			f := newRecoveryTLS(t)
			link := recoveryReplyLink{Link: f.link, afterReply: func() error {
				if fault == "administrative_authority" {
					f.admin.revoked.Store(true)
					return nil
				}
				_, err := f.store.NextConnectionGeneration(f.ctx, f.ref, "response-supersession", f.now)
				return err
			}}
			service, err := recovery.New(f.store, link, f.id, func() time.Time { return f.now })
			recoveryOK(t, err)
			var report protocol.ProjectCapability
			err = runRecoveryCall(t, f, []protocol.Operation{protocol.ContextInspect}, func(ctx context.Context) error {
				var callErr error
				report, _, callErr = service.Inspect(ctx, f.lookup.Route, f.lookup.ExpectedContext)
				return callErr
			}, false)
			if err == nil || report.Alias != "" {
				t.Fatal("revoked response released administrative namespace metadata")
			}
		})
	}
}

func TestInitializerRequiresFreshOpenStateBeforeRegistryReady(t *testing.T) {
	f := newRecoveryTLS(t)
	f.approved(t)
	f.stalePostReopen = true
	err := runRecoveryCall(t, f, []protocol.Operation{protocol.ContextInspect, protocol.OriginReopen, protocol.ContextInspect}, func(ctx context.Context) error {
		_, advanceErr := f.initializer.Advance(ctx, f.lookup)
		return advanceErr
	}, false)
	var rejected *domain.Error
	if !errors.As(err, &rejected) || rejected.Code != domain.Conflict {
		t.Fatalf("closed post-reopen observation: %v", err)
	}
	p, err := f.store.ReadRootInitializationProgress(f.ctx, f.lookup)
	recoveryOK(t, err)
	if p.Stage != domain.RootNeedsReopen {
		t.Fatal("stale post-reopen observation opened Registry root")
	}
}
