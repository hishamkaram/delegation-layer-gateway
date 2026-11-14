package recovery_test

import (
	"context"
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
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/devicehub"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
	"github.com/hishamkaram/delegation-layer-gateway/internal/wirelink"
)

// This fixture has real self-enrollment, SQLite, mTLS, negotiated v2 and durable
// control accounting. Its peer models namespace replies; it runs no Native
// process or provider and proves neither native filtering nor task closure.
type ownedRecoveryTLS struct {
	store      *registry.Store
	peer       *transport.Client
	hub        *devicehub.Hub
	init       *recovery.OwnedInitializer
	port       *registry.OwnedRootPort
	admin      context.Context
	now        time.Time
	gateway    domain.GatewayID
	root       domain.RootGuard
	actor      domain.Actor
	generation string
	open       bool
	conflict   bool
}

func ownedTestCertificate(t *testing.T, f *ownedRecoveryTLS) (*x509.Certificate, tls.Certificate, domain.CredentialRef) {
	t.Helper()
	key := recoveryKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned-root test CA"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	recoveryOK(t, err)
	caCert := recoveryCertificate(t, caDER)
	ca, err := devicecert.NewCertificateAuthority(caCert, key)
	recoveryOK(t, err)
	deviceKey := recoveryKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, deviceKey)
	recoveryOK(t, err)
	issuer, err := enrollment.NewSelf(f.store, ca, rand.Reader, func() time.Time { return f.now })
	recoveryOK(t, err)
	receipt, err := issuer.SelfEnroll(t.Context(), f.actor, domain.RequestID(strings.Repeat("c", 32)), "Owned root fixture", csr, "", 0)
	recoveryOK(t, err)
	return caCert, tls.Certificate{Certificate: [][]byte{receipt.CertificateDER, caDER}, PrivateKey: deviceKey, Leaf: recoveryCertificate(t, receipt.CertificateDER)}, receipt.Intent.Credential
}

func newOwnedRecoveryTLS(t *testing.T) *ownedRecoveryTLS {
	t.Helper()
	f := &ownedRecoveryTLS{now: time.Now().UTC().Truncate(time.Second).Add(time.Millisecond), root: domain.RootGuard(protocol.WireContextGuard("owned-native-root"))}
	f.admin = context.WithValue(t.Context(), recoveryAuthorityKey{}, true)
	var err error
	f.store, err = registry.Create(t.Context(), filepath.Join(t.TempDir(), "registry.sqlite"), registry.CreateOptions{Admin: &recoveryAuthority{}})
	recoveryOK(t, err)
	t.Cleanup(func() { recoveryOK(t, f.store.Close()) })
	f.gateway, err = f.store.Identity(t.Context())
	recoveryOK(t, err)
	principal, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "owned-root-user"})
	recoveryOK(t, err)
	f.actor = domain.Actor{Principal: principal.ID, Scopes: domain.ScopeSet{domain.DeviceEnroll, domain.DeviceManage, domain.InventoryRead}}
	recoveryOK(t, f.store.PutOwnerPolicy(f.admin, principal.ID, domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 2}))
	ca, cert, ref := ownedTestCertificate(t, f)
	f.connectOwnedPeer(t, ca, cert, ref)
	return f
}

func (f *ownedRecoveryTLS) connectOwnedPeer(t *testing.T, ca *x509.Certificate, cert tls.Certificate, ref domain.CredentialRef) {
	t.Helper()
	var err error
	f.hub, err = devicehub.NewHub(t.Context(), devicehub.Config{EnableWireV2: true, GatewayID: f.gateway, BootEpoch: "owned-root-boot", Routing: f.store}, f.store, func() time.Time { return f.now })
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
		t.Fatal("unexpected test transport")
	}
	clientTransport := base.Clone()
	clientTransport.TLSClientConfig = base.TLSClientConfig.Clone()
	clientTransport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	t.Cleanup(clientTransport.CloseIdleConnections)
	report := protocol.CapabilityReportV2{ObservedAt: f.now, Root: &protocol.RootCapability{Root: string(f.root), ContractVersion: 1, Features: []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease, protocol.WorkspaceFeature}}}
	f.peer, err = transport.Dial(t.Context(), transport.ClientConfig{WireVersion: 2, URL: "wss" + strings.TrimPrefix(server.URL, "https"), GatewayID: f.gateway, Certificate: cert.Leaf, CapabilitiesV2: &report, Routing: recoveryCensus{}}, &http.Client{Transport: clientTransport}, func() time.Time { return f.now })
	recoveryOK(t, err)
	t.Cleanup(func() { recoveryOK(t, f.peer.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	recoveryOK(t, f.hub.WaitReady(ctx, ref.Device))
	f.port, err = registry.NewOwnedRootPort(t.Context(), f.store, domain.OwnedRootBinding{Route: domain.RootRoute{Device: ref.Device, Root: f.root}, Credential: ref, Connection: f.peer.Generation()}, func() time.Time { return f.now })
	recoveryOK(t, err)
	link, err := wirelink.New(f.hub)
	recoveryOK(t, err)
	f.init, err = recovery.NewOwnedInitializer(f.port, link, f.gateway, func() time.Time { return f.now }, gateway.RoutingObserverFunc(func(gateway.RoutingObservation) {}))
	recoveryOK(t, err)
}

func (f *ownedRecoveryTLS) advance(t *testing.T, operations ...protocol.Operation) (domain.RootInitializationProgress, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	type result struct {
		progress domain.RootInitializationProgress
		err      error
	}
	done := make(chan result, 1)
	go func() {
		progress, err := f.init.Advance(ctx)
		done <- result{progress, err}
	}()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	for _, operation := range operations {
		f.answer(t, ctx, operation)
	}
	value := <-done
	joined = true
	return value.progress, value.err
}

func (f *ownedRecoveryTLS) answer(t *testing.T, ctx context.Context, operation protocol.Operation) {
	t.Helper()
	received, err := f.peer.Receive(ctx)
	recoveryOK(t, err)
	frame, err := received.Claim(ctx)
	recoveryOK(t, err)
	command, err := protocol.DecodeCommandVersion(frame, 2)
	recoveryOK(t, err)
	if frame.Version != 2 || command.Operation != operation || command.Project != "" || command.Root != string(f.root) {
		t.Fatal("root control invented a project alias or changed negotiated identity")
	}
	progress, err := f.init.Progress(ctx)
	recoveryOK(t, err)
	response := f.response(t, command, progress)
	body, err := protocol.Encode(response, protocol.MaxFrameBytes)
	recoveryOK(t, err)
	recoveryOK(t, received.ReplyControl(ctx, protocol.Reply{Operation: operation, Body: body}, protocol.ControlCompletion{ProcessBoot: f.peer.ProcessBoot(), Call: received.ControlCall(), Disposition: protocol.ControlSettled}))
}

func (f *ownedRecoveryTLS) response(t *testing.T, command protocol.Command, progress domain.RootInitializationProgress) any {
	t.Helper()
	switch command.Operation {
	case protocol.ContextInspect:
		return f.inspectionResponse(t, command, progress)
	case protocol.OriginBarrier:
		return f.barrierResponse(t, command, progress)
	case protocol.OriginInventory:
		return f.inventoryResponse(t, command, progress)
	case protocol.OriginReopen:
		return f.reopenResponse(t, command, progress)
	case protocol.Admit, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel, protocol.ResolveProject:
		t.Fatal("task or project resolution crossed root initialization")
	}
	t.Fatal("unexpected root operation")
	return nil
}

func (f *ownedRecoveryTLS) inspectionResponse(t *testing.T, command protocol.Command, progress domain.RootInitializationProgress) any {
	t.Helper()
	var request protocol.InspectRequest
	recoveryOK(t, protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes))
	if request.GatewayID != string(f.gateway) || !request.RootOnly {
		t.Fatal("zero-project initialization depended on project inspection")
	}
	report := protocol.RootCapability{Root: string(f.root), ContractVersion: 1, Features: []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease, protocol.WorkspaceFeature}, OriginRegistered: f.generation != ""}
	if report.OriginRegistered {
		report.Origin = &protocol.OriginStateReport{GatewayID: string(f.gateway), RecoveryID: string(progress.RecoveryID), Generation: f.generation, AdmissionOpen: f.open}
	}
	return report
}

func (f *ownedRecoveryTLS) barrierResponse(t *testing.T, command protocol.Command, progress domain.RootInitializationProgress) any {
	t.Helper()
	var request protocol.OriginBarrierRequest
	recoveryOK(t, protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes))
	if request.GatewayID != string(f.gateway) || request.ExpectedRoot != string(f.root) || request.ExpectedGeneration != "" || request.Generation != string(progress.Generation) || request.RecoveryID != string(progress.RecoveryID) {
		t.Fatal("barrier lost Registry's expected-absent plan")
	}
	f.generation, f.open = request.Generation, false
	return protocol.OriginStateReport{GatewayID: request.GatewayID, RecoveryID: request.RecoveryID, Generation: request.Generation}
}

func (f *ownedRecoveryTLS) inventoryResponse(t *testing.T, command protocol.Command, progress domain.RootInitializationProgress) any {
	t.Helper()
	var request protocol.OriginInventoryRequest
	recoveryOK(t, protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes))
	if request.GatewayID != string(f.gateway) || request.ExpectedRoot != string(f.root) || request.Generation != string(progress.Generation) || request.Cursor != "" || request.Limit != domain.MaxPageLimit {
		t.Fatal("inventory lost the bound root or generation")
	}
	if f.conflict {
		id := strings.Repeat("d", 32)
		return protocol.OriginInventoryReport{Entries: []protocol.OriginInventoryEntry{{TaskID: id, Resolution: "permanently_refused"}}, NextCursor: id, MembershipSHA256: strings.Repeat("1", 64)}
	}
	return protocol.OriginInventoryReport{Entries: []protocol.OriginInventoryEntry{}, Complete: true, MembershipSHA256: strings.Repeat("1", 64), CompletenessReceipt: strings.Repeat("2", 64)}
}

func (f *ownedRecoveryTLS) reopenResponse(t *testing.T, command protocol.Command, progress domain.RootInitializationProgress) any {
	t.Helper()
	var request protocol.OriginReopenRequest
	recoveryOK(t, protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes))
	if progress.Reopen == nil || request.GatewayID != string(f.gateway) || request.ExpectedRoot != string(f.root) || request.Generation != string(progress.Generation) || request.RecoveryID != string(progress.RecoveryID) || request.CompletenessReceipt != hex.EncodeToString(progress.Reopen.Completeness[:]) {
		t.Fatal("reopen was not bound to the approved receipt")
	}
	f.open = true
	return protocol.OriginStateReport{GatewayID: request.GatewayID, RecoveryID: request.RecoveryID, Generation: request.Generation, AdmissionOpen: true}
}

func TestOwnedZeroProjectInitializationOverRealMutualTLS(t *testing.T) {
	f := newOwnedRecoveryTLS(t)
	progress, err := f.advance(t, protocol.ContextInspect, protocol.OriginBarrier)
	recoveryOK(t, err)
	if progress.Stage != domain.RootNeedsInventory || progress.Route.Project != "" || progress.RootRoute == nil {
		t.Fatal("root initialization required a dummy project")
	}
	originalRecovery, originalGeneration := progress.RecoveryID, progress.Generation
	_, err = f.advance(t, protocol.ContextInspect, protocol.OriginInventory)
	recoveryOK(t, err)
	_, err = f.advance(t, protocol.ContextInspect)
	recoveryOK(t, err)
	progress, err = f.advance(t, protocol.ContextInspect, protocol.OriginReopen, protocol.ContextInspect, protocol.ContextInspect)
	recoveryOK(t, err)
	if progress.Stage != domain.RootReady || progress.Generation != originalGeneration || progress.RecoveryID != originalRecovery {
		t.Fatal("root did not reopen the original durable generation")
	}
	progress, err = f.advance(t)
	recoveryOK(t, err)
	if progress.Stage != domain.RootReady {
		t.Fatal("ready replay started another initialization")
	}
	recoveryOK(t, f.store.RevokeOwnedDevice(t.Context(), f.actor, f.port.Binding().Route.Device))
	if _, err = f.init.Progress(t.Context()); err == nil {
		t.Fatal("revoked connection retained initialization authority")
	}
}

func TestOwnedRootIncompleteInventoryCannotOpenAdmission(t *testing.T) {
	f := newOwnedRecoveryTLS(t)
	_, err := f.advance(t, protocol.ContextInspect, protocol.OriginBarrier)
	recoveryOK(t, err)
	f.conflict = true
	_, err = f.advance(t, protocol.ContextInspect, protocol.OriginInventory)
	var refusal *domain.Error
	if !errors.As(err, &refusal) || refusal.Code != domain.Conflict {
		t.Fatal("canonical incomplete inventory did not require explicit recovery")
	}
	progress, err := f.init.Progress(t.Context())
	recoveryOK(t, err)
	if progress.Stage != domain.RootNeedsInventory || f.open {
		t.Fatal("failed inventory advanced durable initialization")
	}
}
