package deviceclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

type privateAdmin struct{}

func (privateAdmin) AuthorizeAdmin(context.Context) error { return nil }

type verifiedOwner struct {
	mu    sync.Mutex
	actor domain.Actor
}

func (a *verifiedOwner) AuthenticateToken(_ context.Context, token string) (identity.VerifiedToken, error) {
	if token != "access-secret-DO-NOT-LOG" {
		return identity.VerifiedToken{}, errors.New("denied")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return identity.VerifiedToken{Actor: a.actor, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

type ownedRevoker struct{ store *registry.Store }

func (r ownedRevoker) RevokeOwned(ctx context.Context, actor domain.Actor, device domain.DeviceID) error {
	return r.store.RevokeOwnedDevice(ctx, actor, device)
}

func realSelfService(t *testing.T, f *gatewayFixture) (*registry.Store, domain.Actor, *verifiedOwner) {
	t.Helper()
	registryPath := filepath.Join(t.TempDir(), "registry.db")
	store, err := registry.Create(t.Context(), registryPath, registry.CreateOptions{Admin: privateAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	principal, err := store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: f.descriptor.Issuer, Subject: "real-owner"})
	if err != nil {
		t.Fatal(err)
	}
	policy := domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskRead, domain.TaskDispatch, domain.TaskCancel}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 2}
	if err = store.PutOwnerPolicy(t.Context(), principal.ID, policy); err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{Principal: principal.ID, Scopes: domain.ScopeSet{domain.DeviceEnroll, domain.DeviceManage, domain.InventoryRead}}
	gateway, err := store.Identity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	service, err := enrollment.NewSelf(store, f.ca, rand.Reader, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	descriptor := f.descriptor
	descriptor.GatewayID = string(gateway)
	auth := &verifiedOwner{actor: actor}
	handler, err := selfservice.New(selfservice.Options{Descriptor: descriptor, Authenticator: auth, Enroller: service, Revoker: ownedRevoker{store: store}, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.descriptor = descriptor
	f.selfHTTP = handler
	f.registryPath = registryPath
	f.mu.Unlock()
	return store, actor, auth
}

// The TLS listener, self-service handler, enrollment service, CA, SQLite Registry
// and client profile stores are real. Only external issuer authentication is a
// controlled fixture; this does not establish Auth0 or Cloud-client acceptance.
func TestConnectThroughRealSelfServiceAndRegistryReplaysCommittedCertificate(t *testing.T) {
	f := newGatewayFixture(t)
	store, actor, _ := realSelfService(t, f)
	f.mu.Lock()
	f.failNext = true
	f.mu.Unlock()
	if _, err := Connect(t.Context(), f.options); !errors.Is(err, ErrTransport) {
		t.Fatal("committed response loss not reported", err)
	}
	first := readDiscardedReceipt(t, f)
	status, err := Connect(t.Context(), f.options)
	if err != nil {
		t.Fatal(err)
	}
	if status.DeviceID != first.DeviceID || status.OwnerPrincipal != string(actor.Principal) || status.CredentialGeneration != 1 {
		t.Fatal("retry changed authoritative identity")
	}
	devices, err := store.ListDevices(t.Context(), actor, domain.DevicePageRequest{Limit: 10})
	if err != nil || len(devices.Items) != 1 || devices.Items[0].ID != domain.DeviceID(status.DeviceID) {
		t.Fatal("retry allocated another authoritative device", err)
	}
	assertInstalledReceipt(t, f, first)
	assertIssuanceRows(t, f.registryPath, 1)
	replacement := f.options
	replacement.ReplaceExisting = true
	replaced, err := Connect(t.Context(), replacement)
	if err != nil || replaced.DeviceID != status.DeviceID || replaced.CredentialGeneration != 2 {
		t.Fatal("real Registry CAS replacement failed", err)
	}
	repeated, err := Connect(t.Context(), replacement)
	if err != nil || repeated.CredentialGeneration != 2 {
		t.Fatal("replacement retry advanced generation twice", err)
	}
	assertIssuanceRows(t, f.registryPath, 2)
}

func readDiscardedReceipt(t *testing.T, f *gatewayFixture) contract.EnrollmentResponse {
	t.Helper()
	f.mu.Lock()
	data := bytes.Clone(f.droppedResponse)
	f.mu.Unlock()
	var receipt contract.EnrollmentResponse
	if protocol.DecodeStrict(data, &receipt, contract.MaxBodyBytes) != nil {
		t.Fatal("missing actually committed response")
	}
	return receipt
}

func assertInstalledReceipt(t *testing.T, f *gatewayFixture, receipt contract.EnrollmentResponse) {
	t.Helper()
	identityStore, err := deviceidentity.Open(filepath.Join(f.options.ProfileDirectory, "identity"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := identityStore.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(f.descriptor.DeviceCAPEM)) {
		t.Fatal("invalid CA fixture")
	}
	certificate, _, err := identityStore.Certificate(roots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	original, err := base64.StdEncoding.DecodeString(receipt.CertificateDERBase64)
	if err != nil || !bytes.Equal(original, certificate.Certificate[0]) {
		t.Fatal("retry installed a different certificate than the persisted Registry receipt", err)
	}
}

func TestLostEnrollmentResponseCannotBeReplayedByAnotherAuthorizedOwner(t *testing.T) {
	f := newGatewayFixture(t)
	store, original, auth := realSelfService(t, f)
	other, err := store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: f.descriptor.Issuer, Subject: "different-owner"})
	if err != nil {
		t.Fatal(err)
	}
	policy := domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.InventoryRead}, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60}, MaxDevices: 2}
	if err = store.PutOwnerPolicy(t.Context(), other.ID, policy); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failNext = true
	f.mu.Unlock()
	if _, err = Connect(t.Context(), f.options); !errors.Is(err, ErrTransport) {
		t.Fatal(err)
	}
	second := domain.Actor{Principal: other.ID, Scopes: original.Scopes}
	auth.mu.Lock()
	auth.actor = second
	auth.mu.Unlock()
	if _, err = Connect(t.Context(), f.options); !errors.Is(err, ErrConflict) {
		t.Fatal("cross-owner request identity was adopted", err)
	}
	devices, err := store.ListDevices(t.Context(), second, domain.DevicePageRequest{Limit: 10})
	if err != nil || len(devices.Items) != 0 {
		t.Fatal("different owner received a duplicate device", err)
	}
	auth.mu.Lock()
	auth.actor = original
	auth.mu.Unlock()
	status, err := Connect(t.Context(), f.options)
	if err != nil || status.OwnerPrincipal != string(original.Principal) {
		t.Fatal("original intent did not recover", err)
	}
}

func assertIssuanceRows(t *testing.T, path string, want int) {
	t.Helper()
	address := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	var issuances, requests int
	if err = db.QueryRowContext(t.Context(), "SELECT (SELECT COUNT(*) FROM issuance),(SELECT COUNT(*) FROM self_enrollments)").Scan(&issuances, &requests); err != nil {
		t.Fatal(err)
	}
	if issuances != want || requests != want {
		t.Fatalf("authoritative issuance/request rows = %d/%d, want %d/%d", issuances, requests, want, want)
	}
}
