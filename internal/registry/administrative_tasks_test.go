package registry

import (
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func fixtureAdministrativeRoute(f *fixture) domain.AdministrativeRouteBinding {
	return domain.AdministrativeRouteBinding{Destination: destination(), Context: binding(), Credential: f.credential, Connection: f.connection, Now: f.now}
}

func TestAdministrativeRouteIsSharedAndInvalidatedOnReconnect(t *testing.T) {
	f := newFixture(t)
	source, page := importedFixture(t, f)
	first := canonicalImport(t, source, "first-import", "a")
	second := canonicalImport(t, source, "second-import", "b")
	page.Entries = []domain.ImportedInventoryEntry{{Existing: &first}, {Existing: &second}}
	_, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	debt, err := transaction(t.Context(), f.store, func(tx *sql.Tx) (int, error) {
		return missingDestinationMappings(t.Context(), tx, page.Destination)
	})
	if must(t, debt, err) != 0 {
		t.Fatal("one exact context route did not cover every task in that context")
	}
	var count int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM administrative_routes").Scan(&count))
	if count != 1 {
		t.Fatal("administrative route was copied per task")
	}
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "reconnected", f.now)
	f.connection = must(t, connection, err)
	debt, err = transaction(t.Context(), f.store, func(tx *sql.Tx) (int, error) {
		return missingDestinationMappings(t.Context(), tx, page.Destination)
	})
	if must(t, debt, err) != 3 {
		t.Fatal("reconnect retained a stale proof or lost an absent snapshot hold")
	}
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	progress, err := f.store.ReadRecoveryProgress(t.Context(), domain.RecoveryProgressRequest{Recovery: page.Destination.Recovery, Limit: 100, Now: f.now})
	view := must(t, progress, err)
	if len(view.Destinations) != 1 || view.Destinations[0].MissingMappings != 0 || view.Destinations[0].Stage != domain.RootNeedsRegularCredential {
		t.Fatal("derived recovery phase did not preserve closed namespace mapping")
	}
}

func TestAdministrativeUnknownSpecAndCancellationHaveOneOwner(t *testing.T) {
	f := newFixture(t)
	source, page := importedFixture(t, f)
	key := domain.NativeTaskKey{Device: source.Destination.Device, Root: source.Context.Root, Task: source.Task}
	check := domain.AdministrativeDrainCheck{Key: key, Destination: source.Destination, Action: domain.AdministrativeCancel, Credential: f.credential, Connection: f.connection, Now: f.now}
	requireCode(t, f.store.CheckAdministrativeDrain(t.Context(), check), domain.Conflict)
	check.Action = domain.AdministrativeResolve
	requireOK(t, f.store.CheckAdministrativeDrain(t.Context(), check))
	task, err := f.store.GetAdministrativeTask(t.Context(), key)
	original := must(t, task, err)
	if original.Receipt != nil || original.Binding.SpecDigest != (domain.Digest{}) {
		t.Fatal("snapshot row fabricated a native receipt or spec")
	}
	spec := domain.Hash([]byte("newly learned canonical spec"))
	observation := domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: spec}
	wrong := original.Binding
	wrong.Origin.RequestDigest = domain.Hash([]byte("different frozen request"))
	_, err = f.store.RecordAdministrativeObservation(t.Context(), domain.AdministrativeObservation{Check: check, Binding: wrong, Observation: observation})
	requireCode(t, err, domain.EvidenceInvalid)
	updated, err := f.store.RecordAdministrativeObservation(t.Context(), domain.AdministrativeObservation{Check: check, Binding: original.Binding, Observation: observation})
	known := must(t, updated, err)
	if known.Binding.SpecDigest != spec || known.Receipt != nil {
		t.Fatal("spec learning invented a receipt or failed to retain genuine spec")
	}
	id := domain.CancellationID(strings.Repeat("a", 32))
	_, err = f.store.BindAdministrativeCancellation(t.Context(), key, id)
	requireOK(t, err)
	_, err = f.store.BindAdministrativeCancellation(t.Context(), key, domain.CancellationID(strings.Repeat("b", 32)))
	requireCode(t, err, domain.Conflict)
	check.Action = domain.AdministrativeCancel
	if err = f.store.CheckAdministrativeDrain(t.Context(), check); err == nil {
		t.Fatal("cancel lacked a current full context route")
	}
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	requireOK(t, f.store.CheckAdministrativeDrain(t.Context(), check))
	observation.Kind = domain.Terminal
	observation.ConfirmedStop = &domain.StopConfirmation{Cancellation: id}
	updated, err = f.store.RecordAdministrativeObservation(t.Context(), domain.AdministrativeObservation{Check: check, Binding: known.Binding, Observation: observation})
	closed := must(t, updated, err)
	if closed.Reserved || closed.Delivery != domain.Resolved {
		t.Fatal("matching fresh stop failed to release the reservation")
	}
	var missing int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations WHERE reserved=1").Scan(&missing))
	if missing != 0 {
		t.Fatal("closed task remained counted")
	}
	_, err = f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
}

func TestCanonicalClassificationSerializesAliasRegistration(t *testing.T) {
	f := newFixture(t)
	source, page := importedFixture(t, f)
	source.Destination.Project = "registered-after-cut"
	entry := canonicalImport(t, source, "late-alias-task", "a")
	page.Entries = []domain.ImportedInventoryEntry{{Existing: &entry}}
	other, err := Open(t.Context(), f.path, options(f.gateway))
	second := must(t, other, err)
	t.Cleanup(func() { requireOK(t, second.Close()) })
	_, err = second.db.ExecContext(t.Context(), "PRAGMA busy_timeout=1")
	requireOK(t, err)
	digest, err := importedPageDigest(page)
	requireOK(t, err)
	_, err = transaction(t.Context(), f.store, func(tx *sql.Tx) (domain.InventoryApplyResult, error) {
		registrationErr := second.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: source.Destination, Context: source.Context})
		var busy *sqlite.Error
		if !errors.As(registrationErr, &busy) || busy.Code() != sqlite3.SQLITE_BUSY {
			t.Fatal("competing alias writer was not excluded by the immediate import transaction")
		}
		return applyImportedPage(t.Context(), tx, page, digest)
	})
	requireOK(t, err)
	requireOK(t, second.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: source.Destination, Context: source.Context}))
	_, err = f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	view, err := f.store.GetAdministrativeTask(t.Context(), domain.NativeTaskKey{Device: page.Destination.Device, Root: page.Destination.Root, Task: entry.Receipt.Binding.Task})
	if must(t, view, err).Correlation != nil {
		t.Fatal("late catalog registration changed committed classification")
	}
}

func TestRecoveryProgressKeepsReopenProofAcrossRouteChanges(t *testing.T) {
	f := newFixture(t)
	_, page := importedFixture(t, f)
	_, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), page.Destination.Recovery, []domain.DeviceID{page.Destination.Device}))
	f.reconcileRouting(t, nil)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	f.credential = f.enroll(t, domain.Regular)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "regular-recovery", f.now)
	f.connection = must(t, connection, err)
	f.reconcileRouting(t, nil)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: page.Destination.Recovery, Now: f.now})
	approved := must(t, plan, err).Targets[0]
	receipt := domain.Hash([]byte("verified native reopen"))
	requireOK(t, f.store.RecordReopen(t.Context(), domain.ValidatedReopenReceipt{Target: approved, Receipt: receipt, Now: f.now}))
	request := domain.RecoveryProgressRequest{Recovery: page.Destination.Recovery, Limit: 100, Now: f.now}
	progress, err := f.store.ReadRecoveryProgress(t.Context(), request)
	first := must(t, progress, err)
	if len(first.Destinations) != 1 || first.Destinations[0].Stage != domain.RootReady || first.Status != domain.RecoveryActive {
		t.Fatal("a reopened root did not become ready for the separate whole-session finish")
	}
	alternative := fixtureAdministrativeRoute(f)
	alternative.Destination.Project = "alternative-drain-route"
	requireOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: alternative.Destination, Context: alternative.Context}))
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), alternative))
	requireCode(t, f.store.CheckReopen(t.Context(), domain.ReopenCheck{Target: approved, Credential: f.credential, Connection: f.connection, Now: f.now}), domain.Conflict)
	progress, err = f.store.ReadRecoveryProgress(t.Context(), request)
	changed := must(t, progress, err)
	if changed.Destinations[0].Stage != domain.RootNeedsApproval || !reflect.DeepEqual(changed.Destinations[0].RecordedReopen, &receipt) {
		t.Fatal("route change erased native reopen facts or retained old approval")
	}
	_, err = f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: page.Destination.Recovery, Now: f.now})
	requireOK(t, err)
	progress, err = f.store.ReadRecoveryProgress(t.Context(), request)
	if must(t, progress, err).Destinations[0].Stage != domain.RootReady {
		t.Fatal("fresh approval forced a duplicate native reopen")
	}
	credential, err := f.store.CheckCredential(t.Context(), f.credential, f.now)
	current := must(t, credential, err)
	requireCode(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: page.Destination.Recovery, Now: current.NotAfter}), domain.Expired)
	requireOK(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: page.Destination.Recovery, Now: f.now}))
	connection, err = f.store.NextConnectionGeneration(t.Context(), f.credential, "post-finish-reconnect", f.now)
	f.connection = must(t, connection, err)
	progress, err = f.store.ReadRecoveryProgress(t.Context(), request)
	finished := must(t, progress, err)
	if finished.Status != domain.RecoveryFinished || finished.Destinations[0].Stage != domain.RootReady || finished.Destinations[0].MissingMappings != 0 {
		t.Fatal("stale route after finish resurrected recovery mapping debt")
	}
}

func TestUnattributedCancellationDrainsWithoutPublicIdentity(t *testing.T) {
	f := newFixture(t)
	source, page := importedFixture(t, f)
	source.Destination.Project = "lost-original-alias"
	entry := canonicalImport(t, source, "unattributed-drain", "a")
	page.Entries = []domain.ImportedInventoryEntry{{Existing: &entry}}
	_, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	key := domain.NativeTaskKey{Device: page.Destination.Device, Root: page.Destination.Root, Task: entry.Receipt.Binding.Task}
	view, err := f.store.BindAdministrativeCancellation(t.Context(), key, domain.CancellationID(strings.Repeat("a", 32)))
	bound := must(t, view, err)
	if bound.Correlation != nil || bound.Cancellation == "" {
		t.Fatal("administrative cancellation invented a public operation identity")
	}
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	check := domain.AdministrativeDrainCheck{Key: key, Destination: destination(), Action: domain.AdministrativeCancel, Credential: f.credential, Connection: f.connection, Now: f.now}
	observation := domain.DelegateObservation{Kind: domain.Terminal, ObservedAt: f.now, SpecDigest: bound.Binding.SpecDigest, ConfirmedStop: &domain.StopConfirmation{Cancellation: bound.Cancellation}}
	view, err = f.store.RecordAdministrativeObservation(t.Context(), domain.AdministrativeObservation{Check: check, Binding: bound.Binding, Observation: observation})
	closed := must(t, view, err)
	if closed.Reserved || closed.Correlation != nil || closed.Observation == nil || closed.Observation.Kind != domain.Terminal {
		t.Fatal("unattributed task did not drain through its physical row")
	}
	_, err = f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	view, err = f.store.GetAdministrativeTask(t.Context(), key)
	replayed := must(t, view, err)
	if replayed.Reserved || !reflect.DeepEqual(replayed.Observation, closed.Observation) {
		t.Fatal("inventory replay erased the administrative closure")
	}
	_, err = f.store.GetOperation(t.Context(), f.actor, entry.Receipt.Binding.Origin.Operation)
	requireCode(t, err, domain.NotFound)
}

// The fixture models a validated fresh full-context reply after the certificate
// transition. Production obtains this proof over the new authenticated socket.
func rebindRegularFixture(t *testing.T, f *fixture) {
	t.Helper()
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "regular-recovery-proof", f.now)
	f.connection = must(t, connection, err)
	f.reconcileRouting(t, nil)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
}
