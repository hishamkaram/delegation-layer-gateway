package registry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type fixtureAdmin struct{}

func (fixtureAdmin) AuthorizeAdmin(context.Context) error { return nil }

type fixture struct {
	gateway    domain.GatewayID
	store      *Store
	path       string
	now        time.Time
	actor      domain.Actor
	credential domain.CredentialRef
	connection domain.ConnectionGeneration
	key        *ecdsa.PrivateKey
	next       int
}

func must[T any](t *testing.T, value T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func requireOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func requireCode(t *testing.T, err error, code domain.ErrorCode) {
	t.Helper()
	var classified *domain.Error
	if !errors.As(err, &classified) || classified.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func options(gateway domain.GatewayID) Options {
	return Options{Gateway: gateway, Admin: fixtureAdmin{}}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{path: filepath.Join(t.TempDir(), "registry.sqlite"), now: time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)}
	store, err := Create(t.Context(), f.path, CreateOptions{Admin: fixtureAdmin{}})
	f.store = must(t, store, err)
	f.gateway = fixtureIdentity(t, f.store)
	t.Cleanup(func() { requireOK(t, f.store.Close()) })
	principal, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "alice"})
	p := must(t, principal, err)
	f.actor = domain.Actor{Principal: p.ID, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}}
	device, err := f.store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "device", Name: "Workstation"})
	_ = must(t, device, err)
	requireOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: destination(), Context: binding()}))
	f.putGrant(t, f.actor.Principal, f.actor.Scopes)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.key = must(t, key, err)
	f.credential = f.enroll(t, domain.Regular)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "boot1", f.now)
	f.connection = must(t, connection, err)
	f.reconcileRouting(t, nil)
	openFixtureRoot(t, t.Context(), f.store, domain.RootInitializationStart{Route: destination(), ExpectedContext: binding(), Credential: f.credential, Connection: f.connection, Now: f.now})
	return f
}

func destination() domain.Destination {
	return domain.Destination{Device: "device", Project: "project"}
}

func binding() domain.ContextBinding {
	return domain.ContextBinding{Root: domain.RootGuard(fixtureGuard("root")), Project: domain.ProjectGuard(fixtureGuard("project-guard"))}
}

func fixtureGuard(token string) string {
	digest := domain.Hash([]byte(token))
	return "ctx1_" + hex.EncodeToString(digest[:])
}

func (f *fixture) putGrant(t *testing.T, principal domain.PrincipalID, scopes domain.ScopeSet) {
	t.Helper()
	requireOK(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: principal, Destination: destination()}, Scopes: scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 300}}))
}

func (f *fixture) enrollment(t *testing.T, mode domain.CredentialMode) domain.EnrollmentAttempt {
	t.Helper()
	f.next++
	device, err := transaction(t.Context(), f.store, func(tx *sql.Tx) (domain.Device, error) { return readDevice(t.Context(), tx, "device") })
	current := must(t, device, err)
	token := domain.Hash([]byte(fmt.Sprintf("token-%d", f.next)))
	requireOK(t, f.store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: token, Device: "device", Mode: mode, Generation: current.CredentialGeneration + 1, CreatedAt: f.now, ExpiresAt: f.now.Add(domain.EnrollmentTTL)}))
	encoded, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	spki := must(t, encoded, err)
	serial := make([]byte, 16)
	serial[0] = 1
	serial[15] = byte(f.next)
	return domain.EnrollmentAttempt{TokenHash: token, CSRHash: domain.Hash([]byte("CSR")), PublicKeyHash: domain.Hash(spki), Issuance: domain.IssuanceID(fmt.Sprintf("issuance-%d", f.next)), Serial: serial, Now: f.now}
}

func (f *fixture) enroll(t *testing.T, mode domain.CredentialMode) domain.CredentialRef {
	t.Helper()
	input := f.enrollment(t, mode)
	intent, err := f.store.BeginEnrollment(t.Context(), input)
	reserved := must(t, intent, err)
	certificate := signFixture(t, reserved, f.key)
	receipt, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: reserved.ID, CertificateDER: certificate, Now: f.now})
	completed := must(t, receipt, err)
	return completed.Intent.Credential
}

func signFixture(t *testing.T, intent domain.IssuanceIntent, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	parsed, err := url.Parse("spiffe://delegation-layer/device/" + string(intent.Credential.Device))
	deviceURI := must(t, parsed, err)
	parsed, err = url.Parse("urn:delegation-layer:credential:" + string(intent.Credential.Epoch) + ":" + strconv.FormatUint(intent.Credential.Generation, 10))
	credentialURI := must(t, parsed, err)
	template := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(intent.Serial), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: intent.NotBefore, NotAfter: intent.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{deviceURI, credentialURI}}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return must(t, encoded, err)
}

func (f *fixture) prepare(t *testing.T, label string) domain.Correlation {
	t.Helper()
	taskHash := domain.Hash([]byte(label))
	c := domain.Correlation{Operation: domain.OperationID(label), Task: domain.TaskID(hex.EncodeToString(taskHash[:16])), Gateway: fixtureIdentity(t, f.store), AdmissionGeneration: f.rootGeneration(t), Owner: domain.OperationOwner{Kind: domain.Owned, Principal: f.actor.Principal}, Destination: destination(), Context: binding()}
	r := domain.FrozenRequest{Provider: "provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: domain.ReadOnly, BudgetSeconds: 60, Brief: "sensitive brief"}
	c.BriefDigest = domain.Hash([]byte(r.Brief))
	digest, err := domain.RequestDigest(c, r)
	c.RequestDigest = must(t, digest, err)
	prepared, err := f.store.Prepare(t.Context(), f.actor, domain.Preparation{Correlation: c, Request: r, Now: f.now})
	_ = must(t, prepared, err)
	return c
}

func (f *fixture) transmission(c domain.Correlation) domain.Transmission {
	return domain.Transmission{Operation: c.Operation, Credential: f.credential, Connection: f.connection, EncodedFrameBytes: 512, Now: f.now}
}

func (f *fixture) restart(t *testing.T) {
	t.Helper()
	requireOK(t, f.store.Close())
	store, err := Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, store, err)
}

func TestConcurrentConfirmationIsDurableAndDoesNotReplay(t *testing.T) {
	f := newFixture(t)
	first := f.prepare(t, "first")
	second := f.prepare(t, "second")
	third := f.prepare(t, "third")
	const callers = 12
	results := make(chan domain.SendDecision, callers)
	failures := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Go(func() {
			result, err := f.markSettledControl(t.Context(), f.actor, f.transmission(first))
			if err != nil {
				failures <- err
				return
			}
			results <- result
		})
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	assertSingleSend(t, results)
	result, err := f.markSettledControl(t.Context(), f.actor, f.transmission(second))
	if must(t, result, err).Kind != domain.SendOnce {
		t.Fatal("second slot unavailable")
	}
	_, err = f.markSettledControl(t.Context(), f.actor, f.transmission(third))
	requireCode(t, err, domain.ResourceLimit)
	f.restart(t)
	result, err = f.markSettledControl(t.Context(), f.actor, f.transmission(first))
	if got := must(t, result, err); got.Kind != domain.ObserveExisting || got.Request.Brief != "" {
		t.Fatal("restart replayed original admission")
	}
	observation := domain.ValidatedObservation{Correlation: first, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Unknown, ObservedAt: f.now}}
	requireOK(t, f.store.RecordObservation(t.Context(), observation))
	view, err := f.store.GetOperation(t.Context(), f.actor, first.Operation)
	if !must(t, view, err).Reserved {
		t.Fatal("uncertainty released reservation")
	}
	observation.Observation.Kind = domain.Terminal
	observation.Observation.Closure = canonicalClosureEvidence()
	observation.Observation.SpecDigest = domain.Hash([]byte("canonical spec"))
	resolved, err := f.store.ApplyResolution(t.Context(), domain.ValidatedResolution{ValidatedObservation: observation, DurableRequest: true})
	if must(t, resolved, err).Reserved {
		t.Fatal("terminal proof retained reservation")
	}
	var retained int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COALESCE(length(request),0) FROM operations WHERE id=?", first.Operation).Scan(&retained))
	if retained != 0 {
		t.Fatal("durable receipt did not remove retained brief")
	}
	result, err = f.markSettledControl(t.Context(), f.actor, f.transmission(third))
	if must(t, result, err).Kind != domain.SendOnce {
		t.Fatal("closed reservation did not become available")
	}
}

func assertSingleSend(t *testing.T, results <-chan domain.SendDecision) {
	t.Helper()
	sends := 0
	for result := range results {
		if result.Kind == domain.SendOnce {
			sends++
			if result.Request.Brief != "sensitive brief" {
				t.Fatal("first send lacks frozen brief")
			}
		} else if result.Request.Brief != "" {
			t.Fatal("replay exposed admission bytes")
		}
	}
	if sends != 1 {
		t.Fatalf("want exactly one possible send, got %d", sends)
	}
}

func TestDispatchOnlyAndCurrentAuthorization(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "authorization")
	dispatcher := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	view, err := f.store.GetForDispatch(t.Context(), dispatcher, c.Operation, f.now)
	if must(t, view, err).Request.Brief == "" {
		t.Fatal("dispatch-only owner cannot encode own request")
	}
	_, err = f.store.GetOperation(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.Forbidden)
	page, err := f.store.ListOperations(t.Context(), dispatcher, domain.OperationPageRequest{})
	if len(must(t, page, err).Items) != 1 {
		t.Fatal("dispatch-only draft omitted")
	}
	other, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "bob"})
	bob := must(t, other, err)
	f.putGrant(t, bob.ID, f.actor.Scopes)
	_, err = f.store.GetForDispatch(t.Context(), domain.Actor{Principal: bob.ID, Scopes: f.actor.Scopes}, c.Operation, f.now)
	requireCode(t, err, domain.NotFound)
	requireOK(t, f.store.RevokeGrant(t.Context(), domain.GrantKey{Principal: f.actor.Principal, Destination: destination()}))
	_, err = f.markSettledControl(t.Context(), dispatcher, f.transmission(c))
	requireCode(t, err, domain.NotFound)
	f.putGrant(t, f.actor.Principal, f.actor.Scopes)
	bad := f.transmission(c)
	bad.EncodedFrameBytes = domain.MaxFrameBytes + 1
	if _, err = f.markSettledControl(t.Context(), f.actor, bad); err == nil {
		t.Fatal("oversized frame accepted")
	}
	read, err := f.store.GetOperation(t.Context(), f.actor, c.Operation)
	if must(t, read, err).Reserved {
		t.Fatal("pre-send rejection reserved execution")
	}
	requireOK(t, f.store.SetPrincipalRevoked(t.Context(), f.actor.Principal, true))
	_, err = f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireCode(t, err, domain.Forbidden)
	principal, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "alice"})
	if p := must(t, principal, err); p.ID != f.actor.Principal || !p.Revoked {
		t.Fatal("login bypassed persisted denylist")
	}
}

func TestIssuanceIntentReplayRotationAndRenewal(t *testing.T) {
	f := newFixture(t)
	old := f.credential
	input := f.enrollment(t, domain.Regular)
	intent, err := f.store.BeginEnrollment(t.Context(), input)
	reserved := must(t, intent, err)
	_, err = f.store.CheckCredential(t.Context(), old, f.now)
	requireCode(t, err, domain.Forbidden)
	_, err = f.store.CheckCredential(t.Context(), reserved.Credential, f.now)
	requireCode(t, err, domain.NotFound)
	f.restart(t)
	retry := input
	retry.Issuance = "ignored-retry"
	retry.Serial = bytes.Repeat([]byte{2}, 16)
	intent, err = f.store.BeginEnrollment(t.Context(), retry)
	if !reflect.DeepEqual(must(t, intent, err), reserved) {
		t.Fatal("retry changed immutable issuance intent")
	}
	retry.CSRHash = domain.Hash([]byte("different CSR"))
	_, err = f.store.BeginEnrollment(t.Context(), retry)
	requireCode(t, err, domain.Conflict)
	der := signFixture(t, reserved, f.key)
	receipt, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: reserved.ID, CertificateDER: der, Now: f.now})
	first := must(t, receipt, err)
	receipt, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: reserved.ID, CertificateDER: signFixture(t, reserved, f.key), Now: f.now})
	if !bytes.Equal(must(t, receipt, err).CertificateDER, first.CertificateDER) {
		t.Fatal("replay changed persisted certificate bytes")
	}
	renew := domain.RenewalAttempt{Credential: reserved.Credential, Request: "renewal", CSRHash: input.CSRHash, PublicKeyHash: input.PublicKeyHash, Issuance: "renewed", Serial: bytes.Repeat([]byte{3}, 16), Now: f.now}
	_, err = f.store.BeginRenewal(t.Context(), renew)
	requireCode(t, err, domain.Forbidden)
	renew.Now = f.now.Add(domain.RenewalAfter)
	intent, err = f.store.BeginRenewal(t.Context(), renew)
	renewal := must(t, intent, err)
	receipt, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: renewal.ID, CertificateDER: signFixture(t, renewal, f.key), Now: renew.Now})
	_ = must(t, receipt, err)
	intent, err = f.store.BeginRenewal(t.Context(), renew)
	if !reflect.DeepEqual(must(t, intent, err), renewal) {
		t.Fatal("renewal lost-response retry changed intent")
	}
	requireOK(t, f.store.SetDeviceRevoked(t.Context(), "device", true))
	_, err = f.store.BeginRenewal(t.Context(), renew)
	requireCode(t, err, domain.Forbidden)
}

func TestAdminDefaultsDenyAndDraftExpiryKeepsPossibleSend(t *testing.T) {
	f := newFixture(t)
	unsent := f.prepare(t, "unsent")
	possible := f.prepare(t, "possible")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(possible))
	requireOK(t, err)
	count, err := f.store.ExpireUnsent(t.Context(), f.now.Add(domain.DraftTTL))
	if must(t, count, err).Count != 1 {
		t.Fatal("expiry did not select exactly one unsent draft")
	}
	view, err := f.store.GetOperation(t.Context(), f.actor, unsent.Operation)
	if must(t, view, err).Delivery != domain.ExpiredUnsent {
		t.Fatal("draft did not expire")
	}
	view, err = f.store.GetOperation(t.Context(), f.actor, possible.Operation)
	if got := must(t, view, err); !got.Reserved || got.Delivery != domain.PossibleSend {
		t.Fatal("expiry erased uncertain transmission")
	}
	f.store.admin = nil
	_, err = f.store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "forbidden", Name: "Forbidden"})
	requireCode(t, err, domain.Forbidden)
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "forbidden", Epoch: "epoch2", Now: f.now})
	requireCode(t, err, domain.Forbidden)
}

func TestCommittedPossibleSendSurvivesProcessCrash(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "crash")
	requireOK(t, f.store.Close())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistryCrashWriter$")
	command.Env = append(os.Environ(), "GATEWAY_REGISTRY_CRASH_FIXTURE="+f.path)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 92 {
		t.Fatalf("fixture did not crash at committed boundary: %v %s", err, output)
	}
	store, err := Open(t.Context(), f.path, options(f.gateway))
	f.store = must(t, store, err)
	result, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	got := must(t, result, err)
	if got.Kind != domain.ObserveExisting || !got.Operation.Reserved || got.Request.Brief != "" {
		t.Fatal("crash lost marker or replayed admission")
	}
}

func TestRegistryCrashWriter(t *testing.T) {
	path := os.Getenv("GATEWAY_REGISTRY_CRASH_FIXTURE")
	if path == "" {
		t.Skip("subprocess-only crash fixture")
	}
	store, err := Open(t.Context(), path, options(readFixtureIdentity(t, path)))
	s := must(t, store, err)
	principal, err := s.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "alice"})
	p := must(t, principal, err)
	actor := domain.Actor{Principal: p.ID, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	crashFixture := &fixture{store: s}
	_, err = crashFixture.markSettledControl(t.Context(), actor, domain.Transmission{Operation: "crash", Credential: domain.CredentialRef{Device: "device", Epoch: fixtureEpoch(t, s), Generation: 1}, Connection: domain.ConnectionGeneration{BootEpoch: "boot1", Counter: 1}, EncodedFrameBytes: 512, Now: time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)})
	requireOK(t, err)
	os.Exit(92) // Intentional abrupt process death exercises WAL recovery without Close.
}

func fixtureIdentity(t *testing.T, s *Store) domain.GatewayID {
	t.Helper()
	id, err := s.Identity(t.Context())
	return must(t, id, err)
}

func fixtureEpoch(t *testing.T, s *Store) domain.CredentialEpoch {
	t.Helper()
	var epoch string
	requireOK(t, s.db.QueryRowContext(t.Context(), "SELECT epoch FROM settings WHERE id=1").Scan(&epoch))
	return domain.CredentialEpoch(epoch)
}

func readFixtureIdentity(t *testing.T, path string) domain.GatewayID {
	t.Helper()
	id, err := ReadIdentity(t.Context(), path)
	return must(t, id, err)
}
