package registry

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func pendingRoot(t *testing.T, f *fixture) domain.RootInitializationStart {
	t.Helper()
	route := domain.Destination{Device: "device", Project: "new-root"}
	binding := domain.ContextBinding{Root: domain.RootGuard(fixtureGuard("new-root")), Project: domain.ProjectGuard(fixtureGuard("new-project"))}
	requireOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: route, Context: binding}))
	requireOK(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: route}, Scopes: f.actor.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 300}}))
	return domain.RootInitializationStart{Route: route, ExpectedContext: binding, Credential: f.credential, Connection: f.connection, Now: f.now}
}

func prepareRootOperation(t *testing.T, f *fixture, start domain.RootInitializationStart, generation domain.AdmissionGeneration) (domain.PreparedOperation, error) {
	t.Helper()
	request := domain.FrozenRequest{Provider: "provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: domain.ReadOnly, BudgetSeconds: 60, Brief: "root guarded brief"}
	task := domain.Hash([]byte("root guarded task"))
	c := domain.Correlation{Operation: "root-guarded", Task: domain.TaskID(hex.EncodeToString(task[:16])), Gateway: f.gateway, AdmissionGeneration: generation, Owner: domain.OperationOwner{Kind: domain.Owned, Principal: f.actor.Principal}, Destination: start.Route, Context: start.ExpectedContext, BriefDigest: domain.Hash([]byte(request.Brief))}
	digest, err := domain.RequestDigest(c, request)
	c.RequestDigest = must(t, digest, err)
	return f.store.Prepare(t.Context(), f.actor, domain.Preparation{Correlation: c, Request: request, Now: f.now})
}

func TestRegisteredRootIsPendingUntilAllProofsAndDoesNotResetAuthority(t *testing.T) {
	f := newFixture(t)
	start := pendingRoot(t, f)
	// An arbitrary valid caller generation is deliberately unproven here.
	_, pendingErr := prepareRootOperation(t, f, start, "unproven-caller-generation")
	requireCode(t, pendingErr, domain.Pending)
	epoch := fixtureEpoch(t, f.store)
	progress, err := f.store.BeginRootInitialization(t.Context(), start)
	p := must(t, progress, err)
	if p.Stage != domain.RootNeedsBarrier || p.Generation == "" || p.GatewayID != f.gateway {
		t.Fatal("root plan not durably minted before send")
	}
	_, err = prepareRootOperation(t, f, start, p.Generation)
	requireCode(t, err, domain.Pending)
	if fixtureEpoch(t, f.store) != epoch {
		t.Fatal("root initialization rotated fleet epoch")
	}
	if _, err = f.store.CheckCredential(t.Context(), f.credential, f.now); err != nil {
		t.Fatal("root initialization reset current credential")
	}
	_, err = f.store.Authorize(t.Context(), domain.AuthorizationRequest{Actor: f.actor, Destination: start.Route, Scope: domain.TaskRead})
	requireOK(t, err)
	again, err := f.store.BeginRootInitialization(t.Context(), start)
	if !reflect.DeepEqual(p, must(t, again, err)) {
		t.Fatal("lost ACK retry minted a new attempt or generation")
	}
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "blocked-by-root", Epoch: "new-fleet-epoch", Now: f.now})
	requireCode(t, err, domain.Conflict)
	destination := domain.RecoveryDestination{Recovery: p.RecoveryID, Device: start.Route.Device, Root: start.ExpectedContext.Root}
	member := domain.Hash([]byte("empty membership"))
	complete := domain.Hash([]byte("complete namespace"))
	page := domain.ValidatedInventoryPage{Destination: destination, Generation: p.Generation, Membership: member, CompletenessReceipt: &complete, Now: f.now}
	requireCode(t, f.store.ApplyInventoryPage(t.Context(), page), domain.Pending)
	requireCode(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: p.RecoveryID, Now: f.now}), domain.Pending)
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: destination, Generation: p.Generation, Receipt: domain.Hash([]byte("barrier"))}))
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page)) // Exact final-page retry includes its atomic completeness receipt.
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: p.RecoveryID, Now: f.now})
	approved := must(t, plan, err)
	requireCode(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: p.RecoveryID, Now: f.now}), domain.Pending)
	check := domain.ReopenCheck{Target: approved.Targets[0], Credential: f.credential, Connection: f.connection, Now: f.now}
	requireOK(t, f.store.CheckReopen(t.Context(), check))
	requireOK(t, f.store.RecordReopen(t.Context(), domain.ValidatedReopenReceipt{Target: check.Target, Receipt: domain.Hash([]byte("reopened")), Now: f.now}))
	requireOK(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: p.RecoveryID, Now: f.now}))
	_, err = prepareRootOperation(t, f, start, p.Generation)
	requireOK(t, err)
}

func TestSecondAliasReusesOpenRootAndAbandonRequiresExplicitRestore(t *testing.T) {
	f := newFixture(t)
	alias := domain.ProjectRegistration{Destination: domain.Destination{Device: "device", Project: "same-root"}, Context: binding()}
	requireOK(t, f.store.RegisterProject(t.Context(), alias))
	ready, err := f.store.BeginRootInitialization(t.Context(), domain.RootInitializationStart{Route: alias.Destination, ExpectedContext: alias.Context, Credential: f.credential, Connection: f.connection, Now: f.now})
	open := must(t, ready, err)
	if open.Stage != domain.RootReady || open.Generation != f.rootGeneration(t) {
		t.Fatal("alias established a second root authority")
	}
	start := pendingRoot(t, f)
	progress, err := f.store.BeginRootInitialization(t.Context(), start)
	p := must(t, progress, err)
	requireOK(t, f.store.AbandonRootInitialization(t.Context(), p.RecoveryID))
	_, err = f.store.BeginRootInitialization(t.Context(), start)
	requireCode(t, err, domain.Conflict)
	progress, err = f.store.ReadRootInitializationProgress(t.Context(), domain.RootInitializationLookup{Route: start.Route, ExpectedContext: start.ExpectedContext})
	abandoned := must(t, progress, err)
	if abandoned.Stage != domain.RootRestoreRequired || abandoned.Generation != p.Generation {
		t.Fatal("abandon hid immutable attempt or allowed fresh adoption")
	}
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "explicit-restore", Epoch: "explicit-new-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.AbandonRootInitialization(t.Context(), p.RecoveryID)) // Old retry cannot mutate the newer restore session.
	var active string
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT recovery FROM settings WHERE id=1").Scan(&active))
	if active != "explicit-restore" {
		t.Fatal("old abandon retry changed current restore")
	}
}

func TestReopenRevisionAndConnectionAreCheckedAtWriteBoundary(t *testing.T) {
	f := newFixture(t)
	start := pendingRoot(t, f)
	progress, err := f.store.BeginRootInitialization(t.Context(), start)
	p := must(t, progress, err)
	d := domain.RecoveryDestination{Recovery: p.RecoveryID, Device: start.Route.Device, Root: start.ExpectedContext.Root}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: d, Generation: p.Generation, Receipt: domain.Hash([]byte("barrier"))}))
	member := domain.Hash([]byte("membership"))
	complete := domain.Hash([]byte("complete"))
	page := domain.ValidatedInventoryPage{Destination: d, Generation: p.Generation, Membership: member, CompletenessReceipt: &complete, Now: f.now}
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: p.RecoveryID, Now: f.now})
	target := must(t, plan, err).Targets[0]
	check := domain.ReopenCheck{Target: target, Credential: f.credential, Connection: f.connection, Now: f.now}
	requireOK(t, f.store.CheckReopen(t.Context(), check))
	requireOK(t, f.store.RestartInventory(t.Context(), d))
	requireCode(t, f.store.CheckReopen(t.Context(), check), domain.Conflict)
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	plan, err = f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: p.RecoveryID, Now: f.now})
	newTarget := must(t, plan, err).Targets[0]
	if newTarget.Revision <= target.Revision {
		t.Fatal("reapproval reused queued write authority")
	}
	requireCode(t, f.store.RecordReopen(t.Context(), domain.ValidatedReopenReceipt{Target: target, Receipt: domain.Hash([]byte("stale reopen")), Now: f.now}), domain.Conflict)
	check.Target = newTarget
	next, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "new-connection", f.now)
	newConnection := must(t, next, err)
	requireCode(t, f.store.CheckReopen(t.Context(), check), domain.Conflict)
	check.Connection = newConnection
	requireOK(t, f.store.CheckReopen(t.Context(), check))
}

func TestRootInventoryRejectsUnexpectedExistingAndAtomicReceiptMismatch(t *testing.T) {
	f := newFixture(t)
	start := pendingRoot(t, f)
	progress, err := f.store.BeginRootInitialization(t.Context(), start)
	p := must(t, progress, err)
	d := domain.RecoveryDestination{Recovery: p.RecoveryID, Device: start.Route.Device, Root: start.ExpectedContext.Root}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: d, Generation: p.Generation, Receipt: domain.Hash([]byte("barrier"))}))
	// A canonical existing task under this new origin is a fault, even if the
	// protected caller supplied otherwise well-formed, authenticated inventory.
	c := f.prepare(t, "existing-origin-task")
	c.Destination = start.Route
	c.Context = start.ExpectedContext
	entry := domain.InventoryEntry{Correlation: c, Observation: domain.DelegateObservation{Kind: domain.Existing, SpecDigest: domain.Hash([]byte("canonical existing")), ObservedAt: f.now}}
	complete := domain.Hash([]byte("complete"))
	member := domain.Hash([]byte("member"))
	page := domain.ValidatedInventoryPage{Destination: d, Generation: p.Generation, Membership: member, CompletenessReceipt: &complete, Entries: []domain.InventoryEntry{entry}, Now: f.now}
	requireCode(t, f.store.ApplyInventoryPage(t.Context(), page), domain.EvidenceInvalid)
	var count int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM inventory_pages WHERE recovery=?", p.RecoveryID).Scan(&count))
	if count != 0 {
		t.Fatal("rejected root inventory advanced its durable cursor")
	}
	page.Entries = nil
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	changed := domain.Hash([]byte("substituted complete"))
	page.CompletenessReceipt = &changed
	requireCode(t, f.store.ApplyInventoryPage(t.Context(), page), domain.Conflict)
}

func TestRestoreBarrierFactoryRetainsVerifiedExpectationAndRejectsForeignChange(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "barrier-expectation", Epoch: "next-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "barrier-expectation", ExpectedDestinations: 1}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "recovery", f.now)
	f.connection = must(t, connection, err)
	input := domain.BarrierPreparation{Destination: domain.RecoveryDestination{Recovery: "barrier-expectation", Device: "device", Root: binding().Root}, Credential: f.credential, Connection: f.connection, ExpectedGeneration: "verified-current-not-in-snapshot", Now: f.now}
	first, err := f.store.PrepareRecoveryBarrier(t.Context(), input)
	plan := must(t, first, err)
	input.ExpectedGeneration = plan.Generation // A lost ACK can leave the remote at our persisted target.
	repeated, err := f.store.PrepareRecoveryBarrier(t.Context(), input)
	if must(t, repeated, err) != plan {
		t.Fatal("lost ACK retry adopted a new expectation or generation")
	}
	input.ExpectedGeneration = "unrelated-foreign-generation"
	_, err = f.store.PrepareRecoveryBarrier(t.Context(), input)
	requireCode(t, err, domain.Conflict)
}

func TestPendingRootIndependentlyBlocksQueuedAdmissionAndResume(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "queued-root")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireOK(t, err)
	requireOK(t, f.store.RecordObservation(t.Context(), domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("known spec"))}}))
	// Model a partial/stale restored eligibility row independently of the global
	// block. This negative fault injection cannot establish readiness.
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE root_admissions SET state='pending' WHERE device=? AND root_guard=?", c.Destination.Device, c.Context.Root)
	requireOK(t, err)
	requireCode(t, f.store.CheckQueuedAdmission(t.Context(), f.actor, f.transmission(c)), domain.Pending)
	_, err = f.store.GetForRecovery(t.Context(), f.actor, c.Operation)
	requireCode(t, err, domain.Pending)
	if view, readErr := f.store.GetOperation(t.Context(), f.actor, c.Operation); readErr != nil || !view.Reserved {
		t.Fatal("root gating prevented authorized observation or released quota")
	}
	_, err = f.store.BindCancellation(t.Context(), f.actor, c.Operation, domain.CancellationID(strings.Repeat("a", 32)))
	requireOK(t, err)
}

func TestAbandonRefusesRecordedReopenAndRetainsReservations(t *testing.T) {
	f := newFixture(t)
	held := f.prepare(t, "held-through-abandon")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(held))
	requireOK(t, err)
	start := pendingRoot(t, f)
	progress, err := f.store.BeginRootInitialization(t.Context(), start)
	p := must(t, progress, err)
	d := domain.RecoveryDestination{Recovery: p.RecoveryID, Device: start.Route.Device, Root: start.ExpectedContext.Root}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: d, Generation: p.Generation, Receipt: domain.Hash([]byte("barrier"))}))
	member := domain.Hash([]byte("membership"))
	complete := domain.Hash([]byte("complete"))
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), domain.ValidatedInventoryPage{Destination: d, Generation: p.Generation, Membership: member, CompletenessReceipt: &complete, Now: f.now}))
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: p.RecoveryID, Now: f.now})
	target := must(t, plan, err).Targets[0]
	requireOK(t, f.store.RecordReopen(t.Context(), domain.ValidatedReopenReceipt{Target: target, Receipt: domain.Hash([]byte("reopened")), Now: f.now}))
	requireCode(t, f.store.AbandonRootInitialization(t.Context(), p.RecoveryID), domain.Conflict)
	view, err := f.store.GetOperation(t.Context(), f.actor, held.Operation)
	if !must(t, view, err).Reserved {
		t.Fatal("failed abandon released unrelated task quota")
	}
	requireOK(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: p.RecoveryID, Now: f.now}))
}

func TestRestoreCannotAdoptAbsentKnownOrigin(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "lost-origin", Epoch: "new-origin-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "lost-origin", ExpectedDestinations: 1}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "lost-origin", f.now)
	f.connection = must(t, connection, err)
	input := domain.BarrierPreparation{Destination: domain.RecoveryDestination{Recovery: "lost-origin", Device: "device", Root: binding().Root}, Credential: f.credential, Connection: f.connection, Now: f.now}
	_, err = f.store.PrepareRecoveryBarrier(t.Context(), input)
	requireCode(t, err, domain.Conflict)
	var generation string
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT generation FROM recovery_destinations WHERE recovery='lost-origin'").Scan(&generation))
	if generation != "" {
		t.Fatal("origin-loss rejection minted an adopting attempt")
	}
}

func TestRootAdministrativeBoundariesDefaultDeny(t *testing.T) {
	f := newFixture(t)
	start := pendingRoot(t, f)
	f.store.admin = nil
	operations := []func() error{
		func() error { return f.store.AuthorizeAdministrative(t.Context()) },
		func() error { _, err := f.store.BeginRootInitialization(t.Context(), start); return err },
		func() error {
			_, err := f.store.ReadRootInitializationProgress(t.Context(), domain.RootInitializationLookup{Route: start.Route, ExpectedContext: start.ExpectedContext})
			return err
		},
		func() error {
			_, err := f.store.PrepareRecoveryBarrier(t.Context(), domain.BarrierPreparation{})
			return err
		},
		func() error { return f.store.CheckReopen(t.Context(), domain.ReopenCheck{}) },
		func() error { return f.store.AbandonRootInitialization(t.Context(), "unknown-session") },
	}
	for _, operation := range operations {
		requireCode(t, operation(), domain.Forbidden)
	}
}

func TestRestoreCannotAdoptAbsentOriginAfterRecordedUnopenedBarrier(t *testing.T) {
	f := newFixture(t)
	start := pendingRoot(t, f)
	progress, err := f.store.BeginRootInitialization(t.Context(), start)
	p := must(t, progress, err)
	d := domain.RecoveryDestination{Recovery: p.RecoveryID, Device: start.Route.Device, Root: start.ExpectedContext.Root}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: d, Generation: p.Generation, Receipt: domain.Hash([]byte("recorded not opened"))}))
	requireOK(t, f.store.AbandonRootInitialization(t.Context(), p.RecoveryID))
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "recorded-origin-lost", Epoch: "recorded-origin-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "recorded-origin-lost", ExpectedDestinations: 2}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "recorded-origin", f.now)
	f.connection = must(t, connection, err)
	_, err = f.store.PrepareRecoveryBarrier(t.Context(), domain.BarrierPreparation{Destination: domain.RecoveryDestination{Recovery: "recorded-origin-lost", Device: start.Route.Device, Root: start.ExpectedContext.Root}, Credential: f.credential, Connection: f.connection, Now: f.now})
	requireCode(t, err, domain.Conflict)
}

func TestFinalInventoryReceiptFailureRollsBackPageAndRestartsAtProofStage(t *testing.T) {
	f := newFixture(t)
	start := pendingRoot(t, f)
	progress, err := f.store.BeginRootInitialization(t.Context(), start)
	p := must(t, progress, err)
	d := domain.RecoveryDestination{Recovery: p.RecoveryID, Device: start.Route.Device, Root: start.ExpectedContext.Root}
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: d, Generation: p.Generation, Receipt: domain.Hash([]byte("barrier"))}))
	_, err = f.store.db.ExecContext(t.Context(), `CREATE TRIGGER reject_complete BEFORE UPDATE OF completeness ON recovery_destinations WHEN NEW.completeness IS NOT NULL BEGIN SELECT RAISE(ABORT,'fixture final receipt failure'); END`)
	requireOK(t, err)
	member := domain.Hash([]byte("membership"))
	complete := domain.Hash([]byte("complete"))
	page := domain.ValidatedInventoryPage{Destination: d, Generation: p.Generation, Membership: member, CompletenessReceipt: &complete, Now: f.now}
	if applyErr := f.store.ApplyInventoryPage(t.Context(), page); applyErr == nil {
		t.Fatal("final receipt storage failure was hidden")
	}
	var pages int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM inventory_pages WHERE recovery=?", p.RecoveryID).Scan(&pages))
	if pages != 0 {
		t.Fatal("page committed without its final completeness receipt")
	}
	_, err = f.store.db.ExecContext(t.Context(), "DROP TRIGGER reject_complete")
	requireOK(t, err)
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	f.restart(t)
	after, err := f.store.ReadRootInitializationProgress(t.Context(), domain.RootInitializationLookup{Route: start.Route, ExpectedContext: start.ExpectedContext})
	durable := must(t, after, err)
	if durable.Stage != domain.RootNeedsApproval || durable.Completeness != complete || durable.Membership != member {
		t.Fatal("restart lost atomic final inventory proof")
	}
}

func TestRootStartRejectsUninitializedConnectionEvenWhenStoredCounterMatches(t *testing.T) {
	f := newFixture(t)
	start := pendingRoot(t, f)
	// Model the initial enrolled-but-never-connected device row. Its zero
	// counter must not turn a zero-value caller generation into authentication.
	_, err := f.store.db.ExecContext(t.Context(), "UPDATE devices SET counter=0,boot='' WHERE id='device'")
	requireOK(t, err)
	start.Connection = domain.ConnectionGeneration{}
	if _, startErr := f.store.BeginRootInitialization(t.Context(), start); startErr == nil {
		t.Fatal("uninitialized connection was treated as an authenticated current peer")
	}
}
