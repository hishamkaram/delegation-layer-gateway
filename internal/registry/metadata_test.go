package registry

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func newMetadataStore(t *testing.T) *Store {
	t.Helper()
	store, err := Create(t.Context(), filepath.Join(t.TempDir(), "registry.sqlite"), CreateOptions{Admin: fixtureAdmin{}})
	s := must(t, store, err)
	t.Cleanup(func() { requireOK(t, s.Close()) })
	return s
}

func metadataPrincipal(t *testing.T, store *Store, subject string) domain.PrincipalID {
	t.Helper()
	principal, err := store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: subject})
	return must(t, principal, err).ID
}

func metadataProject(t *testing.T, store *Store, device domain.DeviceID, project domain.ProjectAlias) domain.Destination {
	t.Helper()
	_, err := store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: device, Name: string(device)})
	requireOK(t, err)
	destination := domain.Destination{Device: device, Project: project}
	requireOK(t, store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: destination, Context: binding()}))
	return destination
}

func metadataGrant(t *testing.T, store *Store, principal domain.PrincipalID, destination domain.Destination, scopes ...domain.Scope) domain.Grant {
	t.Helper()
	grant := domain.Grant{
		Key:    domain.GrantKey{Principal: principal, Destination: destination},
		Scopes: scopes,
		Ceiling: domain.DispatchCeiling{
			Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60,
		},
	}
	requireOK(t, store.PutGrant(t.Context(), grant))
	return grant
}

func assertMetadataSnapshot(t *testing.T, store *Store, active, authorized uint64) {
	t.Helper()
	snapshot, err := store.MetadataSnapshot(t.Context())
	requireOK(t, err)
	if want := (MetadataSnapshot{RegisteredDevices: active, AuthorizedDevices: authorized}); snapshot != want {
		t.Fatalf("metadata snapshot: want %+v, got %+v", want, snapshot)
	}
}

func TestMetadataSnapshotCountsConfiguredDevicesAcrossPrincipalsAndProjects(t *testing.T) {
	store := newMetadataStore(t)
	assertMetadataSnapshot(t, store, 0, 0)
	alice, bob := metadataPrincipal(t, store, "alice"), metadataPrincipal(t, store, "bob")
	first := metadataProject(t, store, "first", "main")
	second := metadataProject(t, store, "second", "main")
	otherProject := metadataProject(t, store, "first", "other")
	_, err := store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: "no-grant", Name: "No grant"})
	requireOK(t, err)
	assertMetadataSnapshot(t, store, 3, 0)
	metadataGrant(t, store, alice, first, domain.InventoryRead)
	metadataGrant(t, store, alice, otherProject, domain.TaskRead)
	metadataGrant(t, store, bob, first, domain.TaskCancel)
	assertMetadataSnapshot(t, store, 3, 1)
	metadataGrant(t, store, bob, second, domain.TaskDispatch)
	// No device was enrolled or connected. This is configured coverage, not
	// token-specific authorization, online presence or execution readiness.
	assertMetadataSnapshot(t, store, 3, 2)
}

func TestMetadataSnapshotTracksGrantDeletionAndPrincipalDeviceRevocation(t *testing.T) {
	store := newMetadataStore(t)
	alice, bob := metadataPrincipal(t, store, "alice"), metadataPrincipal(t, store, "bob")
	first := metadataProject(t, store, "first", "main")
	second := metadataProject(t, store, "second", "main")
	firstAlice := metadataGrant(t, store, alice, first, domain.TaskRead)
	metadataGrant(t, store, bob, first, domain.TaskCancel)
	metadataGrant(t, store, alice, second, domain.InventoryRead)
	assertMetadataSnapshot(t, store, 2, 2)
	requireOK(t, store.RevokeGrant(t.Context(), firstAlice.Key))
	assertMetadataSnapshot(t, store, 2, 2)
	requireOK(t, store.SetPrincipalRevoked(t.Context(), alice, true))
	assertMetadataSnapshot(t, store, 2, 1)
	requireOK(t, store.SetDeviceRevoked(t.Context(), "first", true))
	assertMetadataSnapshot(t, store, 1, 0)
	requireOK(t, store.SetDeviceRevoked(t.Context(), "first", false))
	assertMetadataSnapshot(t, store, 2, 1)
	requireOK(t, store.SetPrincipalRevoked(t.Context(), alice, false))
	assertMetadataSnapshot(t, store, 2, 2)
	requireOK(t, store.RevokeGrant(t.Context(), domain.GrantKey{Principal: bob, Destination: first}))
	assertMetadataSnapshot(t, store, 2, 1)
}

func TestMetadataSnapshotDoesNotCountUnknownScopesAndSurfacesMalformedStorage(t *testing.T) {
	store := newMetadataStore(t)
	principal := metadataPrincipal(t, store, "alice")
	destination := metadataProject(t, store, "first", "main")
	grant := metadataGrant(t, store, principal, destination, domain.TaskRead)
	value, err := encode(grant)
	requireOK(t, err)
	unknown := strings.Replace(string(value), string(domain.TaskRead), "unknown:scope", 1)
	_, err = store.db.ExecContext(t.Context(), "UPDATE grants SET value=? WHERE principal=? AND device=? AND project=?", []byte(unknown), principal, destination.Device, destination.Project)
	requireOK(t, err)
	assertMetadataSnapshot(t, store, 1, 0)
	_, err = store.db.ExecContext(t.Context(), "UPDATE grants SET value=? WHERE principal=? AND device=? AND project=?", []byte("{malformed"), principal, destination.Device, destination.Project)
	requireOK(t, err)
	if snapshot, err := store.MetadataSnapshot(t.Context()); err == nil || snapshot != (MetadataSnapshot{}) {
		t.Fatalf("malformed grant must make snapshot unavailable, got %+v, %v", snapshot, err)
	}
}

type metadataDeniedAdmin struct{ cause error }

func (a metadataDeniedAdmin) AuthorizeAdmin(context.Context) error { return a.cause }

func TestMetadataSnapshotRequiresAdminBeforeOpeningTransaction(t *testing.T) {
	// A nil database makes any accidental pre-authorization access fail loudly.
	store := &Store{}
	_, err := store.MetadataSnapshot(t.Context())
	requireCode(t, err, domain.Forbidden)
	denied := errors.New("denied metadata observer")
	store.admin = metadataDeniedAdmin{cause: denied}
	if snapshot, err := store.MetadataSnapshot(t.Context()); !errors.Is(err, denied) || snapshot != (MetadataSnapshot{}) {
		t.Fatalf("admin failure must survive without storage access: %+v, %v", snapshot, err)
	}
}

func TestMetadataSnapshotStorageAndContextFailuresAreNotHealthyZeroCounts(t *testing.T) {
	store := newMetadataStore(t)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.MetadataSnapshot(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled metadata request must fail, got %v", err)
	}
	requireOK(t, store.Close())
	if snapshot, err := store.MetadataSnapshot(t.Context()); err == nil || snapshot != (MetadataSnapshot{}) {
		t.Fatalf("closed registry must make snapshot unavailable, got %+v, %v", snapshot, err)
	}
}
