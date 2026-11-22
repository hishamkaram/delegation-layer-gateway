package registry

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func compactPreparation(t *testing.T, f *fixture, label string, kind domain.RequestKind) domain.Preparation {
	t.Helper()
	input := routedPreparation(t, f, label, domain.Hash([]byte(label)).Hex()[:32])
	c := &input.Correlation
	c.RequestVersion, c.Kind = domain.CompactRequestVersion, kind
	c.Route.InputFormat = domain.DispatchInputV1
	c.BriefPresent, input.Request.BriefPresent = true, true
	selector := domain.RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}
	var err error
	if kind == domain.RequestKindContinuation {
		input.Request = domain.FrozenRequest{Continuation: domain.ContinuationOverrides{Version: 1}}
		c.BriefPresent, c.BriefDigest = false, domain.Digest{}
		c.Route.InputFormat = domain.ContinuationInputV1
		c.Predecessor = domain.ContinuationPredecessor{Operation: "original-parent", Task: domain.TaskID(strings.Repeat("f", 32)), SpecDigest: domain.Hash([]byte("original predecessor spec")), RequestDigest: domain.Hash([]byte("original predecessor origin"))}
		c.Route.InputDigest, err = domain.ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, domain.RequestSelector{}, false, input.Request.Continuation, false, domain.Digest{})
	} else {
		c.Route.InputDigest, err = domain.DispatchInputDigestV1(c.Destination.Device, selector, input.Request.Options(), c.BriefDigest)
	}
	requireOK(t, err)
	digest, err := domain.RequestDigest(*c, input.Request)
	c.RequestDigest = must(t, digest, err)
	return input
}

func compactReceipt(t *testing.T, c domain.Correlation) domain.NativeTaskReceipt {
	t.Helper()
	origin, err := domain.CompactOrigin(c)
	brief := c.BriefDigest
	if !c.BriefPresent {
		brief = domain.Hash([]byte("inherited actual Native brief"))
	}
	return domain.NativeTaskReceipt{Binding: domain.NativeTaskBinding{Task: c.Task, Context: c.Context, Origin: must(t, origin, err), SpecDigest: domain.Hash([]byte("Native canonical spec " + string(c.Operation)))}, BriefDigest: brief}
}

func compactRestorePage(t *testing.T, f *fixture) domain.ImportedInventoryPage {
	t.Helper()
	_, err := f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "compact-restore", Epoch: "compact-restore-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "compact-restore", ExpectedDestinations: 1}))
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, testOwnerPolicy()))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "compact-restore-connection", f.now)
	f.connection = must(t, connection, err)
	destination := domain.RecoveryDestination{Recovery: "compact-restore", Device: f.credential.Device, Root: binding().Root}
	generation := f.barrierGeneration(t, destination)
	requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: destination, Generation: generation, Receipt: domain.Hash([]byte("compact restore barrier"))}))
	complete := domain.Hash([]byte("compact canonical completeness"))
	return domain.ImportedInventoryPage{Destination: destination, Generation: generation, Membership: domain.Hash([]byte("compact canonical membership")), CompletenessReceipt: &complete, Credential: f.credential, Connection: f.connection, Now: f.now}
}

func TestCompactCanonicalImportRestoresLostPreparation(t *testing.T) {
	for _, test := range []struct {
		name    string
		kind    domain.RequestKind
		refusal bool
	}{
		{"accepted", domain.RequestKindDispatch, false},
		{"refusal", domain.RequestKindDispatch, true},
		{"continuation", domain.RequestKindContinuation, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			removeOwnedFixtureProjects(t, f)
			input := compactPreparation(t, f, "lost-compact-"+test.name, test.kind)
			prepared, err := f.store.Prepare(t.Context(), f.actor, input)
			original := must(t, prepared, err).Correlation
			receipt := compactReceipt(t, original)
			// The canonical Native task/refusal survives a lost Registry snapshot.
			_, err = f.store.db.ExecContext(t.Context(), "DELETE FROM operations WHERE id=?", original.Operation)
			requireOK(t, err)
			page := compactRestorePage(t, f)
			entry := domain.ImportedInventoryEntry{Existing: &domain.CanonicalInventoryExisting{Receipt: receipt, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: receipt.Binding.SpecDigest}}}
			if test.refusal {
				origin := receipt.Binding.Origin
				entry = domain.ImportedInventoryEntry{Refusal: &domain.NamespaceRefusal{Task: original.Task, Origin: &origin}}
			}
			page.Entries = []domain.ImportedInventoryEntry{entry}
			result, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
			if !must(t, result, err).CanonicalComplete {
				t.Fatal("canonical import did not record final completeness")
			}
			f.restart(t)
			replayed, found, err := f.store.LookupPreparation(t.Context(), f.actor, original.Destination.Device, original.Route.RequestID, original.Route.InputDigest)
			requireOK(t, err)
			if !found || replayed.Correlation != original {
				t.Fatal("canonical import lost original preparation key, operation or task")
			}
			prepared, err = f.store.Prepare(t.Context(), f.actor, input)
			if must(t, prepared, err).Correlation != original {
				t.Fatal("replayed preparation replaced the original restored identity")
			}
			assertRestoredCompactState(t, f, original.Operation, test.refusal)
			_, _, err = f.store.LookupPreparation(t.Context(), f.actor, original.Destination.Device, original.Route.RequestID, domain.Hash([]byte("changed caller input")))
			requireCode(t, err, domain.Conflict)
			var rows int
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations").Scan(&rows))
			if rows != 1 {
				t.Fatalf("one restored identity retained %d operations", rows)
			}
		})
	}
}

func assertRestoredCompactState(t *testing.T, f *fixture, id domain.OperationID, refusal bool) {
	t.Helper()
	var bodyNull, optionsNull, digestNull, receiptNull, reserved bool
	var state domain.DeliveryState
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT request IS NULL,execution_options IS NULL,options_sha256 IS NULL,native_receipt IS NULL,reserved,state FROM operations WHERE id=?", id).Scan(&bodyNull, &optionsNull, &digestNull, &receiptNull, &reserved, &state))
	if !bodyNull || !optionsNull || !digestNull || receiptNull != refusal || reserved == refusal {
		t.Fatal("canonical import invented requested data or discarded actual Native evidence")
	}
	wantState := domain.PossibleSend
	if refusal {
		wantState = domain.Resolved
	}
	if state != wantState {
		t.Fatalf("restored state: want %s, got %s", wantState, state)
	}
}

func TestRouteOneReservationsHaveNoTaskLifetimeCeiling(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	for i := range 33 {
		input := routedPreparation(t, f, fmt.Sprintf("route-one-reservation-%d", i), fmt.Sprintf("%032x", i+1))
		prepared, err := f.store.Prepare(t.Context(), f.actor, input)
		c := must(t, prepared, err).Correlation
		decision, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
		if err != nil {
			t.Fatalf("Route1 reservation %d rejected by a task lifetime ceiling: %v", i+1, err)
		}
		if decision.Kind != domain.SendOnce {
			t.Fatal("new route did not reserve exactly its original task")
		}
		if i == 31 {
			assertLegacyGlobalReservationLimit(t, f)
		}
	}
	var held int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations WHERE reserved=1").Scan(&held))
	if held != 33 {
		t.Fatalf("task lifetime ceiling removal discarded uncertain reservations: %d", held)
	}
}

func assertLegacyGlobalReservationLimit(t *testing.T, f *fixture) {
	t.Helper()
	peer := addRoutingDevice(t, f, "legacy-device")
	destination := domain.Destination{Device: peer.credential.Device, Project: "legacy-project"}
	requireOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: destination, Context: binding()}))
	requireOK(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: destination}, Scopes: f.actor.Scopes}))
	progress := openFixtureRoot(t, t.Context(), f.store, domain.RootInitializationStart{Route: destination, ExpectedContext: binding(), Credential: peer.credential, Connection: peer.connection, Now: f.now})
	request := domain.FrozenRequest{Provider: "provider", Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}, Permission: domain.ReadOnly, BudgetSeconds: 60, Brief: "legacy global reservation boundary"}
	c := domain.Correlation{Operation: "legacy-after-32-holds", Task: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Gateway: f.gateway, AdmissionGeneration: progress.Generation, Owner: domain.OperationOwner{Kind: domain.Owned, Principal: f.actor.Principal}, Destination: destination, Context: binding(), BriefDigest: domain.Hash([]byte(request.Brief))}
	digest, err := domain.RequestDigest(c, request)
	c.RequestDigest = must(t, digest, err)
	_, err = f.store.Prepare(t.Context(), f.actor, domain.Preparation{Correlation: c, Request: request, Now: f.now})
	requireOK(t, err)
	// This device has zero task reservations. Only the unchanged global legacy
	// 32 limit can reject its first possible-send; the per-device limit cannot.
	_, err = peer.markSettledControl(t.Context(), f.actor, peer.transmission(c))
	requireCode(t, err, domain.ResourceLimit)
	assertUnsentCompact(t, f, c.Operation)
}

func TestCompactBoundRecoveryDoesNotRequireLegacyAlias(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	input := compactPreparation(t, f, "compact-root-mapping", domain.RequestKindDispatch)
	receipt := compactReceipt(t, input.Correlation)
	page := compactRestorePage(t, f)
	page.Entries = []domain.ImportedInventoryEntry{{Existing: &domain.CanonicalInventoryExisting{Receipt: receipt, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: receipt.Binding.SpecDigest}}}}
	result, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	if got := must(t, result, err); !got.CanonicalComplete || got.MissingMappings != 0 {
		t.Fatalf("verified compact root route still requires a legacy project mapping: %+v", got)
	}
	finishCompactRestore(t, f, page.Destination)
	f.restart(t)
	view, err := f.store.GetForRecovery(t.Context(), domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}, input.Correlation.Operation)
	if got := must(t, view, err); got.Correlation != input.Correlation || got.SpecDigest != receipt.Binding.SpecDigest {
		t.Fatal("bodyless compact task lost its canonical recovery identity")
	}
	observation := domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("conflicting retained spec"))}
	data, err := encode(observation)
	requireOK(t, err)
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET observation=? WHERE id=?", data, input.Correlation.Operation)
	requireOK(t, err)
	_, err = f.store.GetForRecovery(t.Context(), f.actor, input.Correlation.Operation)
	requireCode(t, err, domain.EvidenceInvalid)
}

func finishCompactRestore(t *testing.T, f *fixture, destination domain.RecoveryDestination) {
	t.Helper()
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), destination.Recovery, []domain.DeviceID{destination.Device}))
	f.reconcileRouting(t, nil)
	f.credential = f.enroll(t, domain.Regular)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "compact-regular-recovery", f.now)
	f.connection = must(t, connection, err)
	f.reconcileRouting(t, nil)
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: destination.Recovery, Now: f.now})
	approved := must(t, plan, err)
	if len(approved.Targets) != 1 {
		t.Fatal("compact restoration did not retain its exact root roster")
	}
	requireOK(t, f.store.RecordReopen(t.Context(), domain.ValidatedReopenReceipt{Target: approved.Targets[0], Receipt: domain.Hash([]byte("compact verified Native reopen")), Now: f.now}))
	requireOK(t, f.store.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: destination.Recovery, Now: f.now}))
}

func TestLegacyCanonicalImportStillRequiresAliasMapping(t *testing.T) {
	f := newFixture(t)
	source, page := importedFixture(t, f)
	entry := canonicalImport(t, source, "legacy-needs-alias", "a")
	page.Entries = []domain.ImportedInventoryEntry{{Existing: &entry}}
	_, err := f.store.db.ExecContext(t.Context(), "DELETE FROM projects")
	requireOK(t, err)
	result, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	if got := must(t, result, err); !got.CanonicalComplete || got.MissingMappings == 0 {
		t.Fatal("legacy missing aliases were exempted from recovery mapping")
	}
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), page.Destination.Recovery, []domain.DeviceID{page.Destination.Device}))
	f.reconcileRouting(t, nil)
	device, err := transaction(t.Context(), f.store, func(tx *sql.Tx) (domain.Device, error) { return readDevice(t.Context(), tx, page.Destination.Device) })
	current := must(t, device, err)
	err = f.store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: domain.Hash([]byte("legacy-regular-denied")), Device: current.ID, Mode: domain.Regular, Generation: current.CredentialGeneration + 1, CreatedAt: f.now, ExpiresAt: f.now.Add(domain.EnrollmentTTL)})
	requireCode(t, err, domain.Pending)
}

func compactExisting(t *testing.T, f *fixture, c domain.Correlation) domain.ImportedInventoryEntry {
	t.Helper()
	receipt := compactReceipt(t, c)
	return domain.ImportedInventoryEntry{Existing: &domain.CanonicalInventoryExisting{Receipt: receipt, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: receipt.Binding.SpecDigest}}}
}

func rebindCompact(t *testing.T, c domain.Correlation) domain.Correlation {
	t.Helper()
	value, err := domain.BuildOriginBinding(c)
	c.RequestDigest = domain.Hash([]byte(must(t, value, err)))
	requireOK(t, c.Validate())
	return c
}

func TestCompactImportRejectsInvalidBindingAndOwnerAtomically(t *testing.T) {
	for _, mode := range []string{"invalid", "unknown version", "noncanonical", "outer owner", "device owner", "missing owner", "preparation key"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			removeOwnedFixtureProjects(t, f)
			first := compactPreparation(t, f, "first-bound-task", domain.RequestKindDispatch).Correlation
			second := compactPreparation(t, f, "second-bound-task", domain.RequestKindDispatch).Correlation
			if mode == "device owner" {
				second.Owner.Principal = "another-original-owner"
				second = rebindCompact(t, second)
			}
			if mode == "preparation key" {
				second.Route.RequestID = first.Route.RequestID
				second = rebindCompact(t, second)
			}
			page := compactRestorePage(t, f)
			entry := compactExisting(t, f, second)
			changeCompactImportOrigin(&entry.Existing.Receipt.Binding.Origin, mode)
			if mode == "missing owner" {
				_, err := f.store.db.ExecContext(t.Context(), "DELETE FROM device_owners WHERE device=?", second.Destination.Device)
				requireOK(t, err)
			}
			page.Entries = []domain.ImportedInventoryEntry{compactExisting(t, f, first), entry}
			sort.Slice(page.Entries, func(i, j int) bool {
				return page.Entries[i].Existing.Receipt.Binding.Task < page.Entries[j].Existing.Receipt.Binding.Task
			})
			_, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
			requireCode(t, err, domain.EvidenceInvalid)
			assertCompactPageRolledBack(t, f, page.Destination)
		})
	}
}

func changeCompactImportOrigin(origin *domain.TaskOrigin, mode string) {
	switch mode {
	case "invalid":
		origin.Binding = "present-invalid-binding"
	case "unknown version":
		origin.Binding = strings.Replace(origin.Binding, `"v":4`, `"v":999`, 1)
	case "noncanonical":
		origin.Binding += " "
	case "outer owner":
		origin.Principal = "different-outer-principal"
	}
}

func assertCompactPageRolledBack(t *testing.T, f *fixture, destination domain.RecoveryDestination) {
	t.Helper()
	var rows, pages, complete int
	var blocked bool
	var root domain.RootState
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations").Scan(&rows))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM inventory_pages WHERE recovery=?", destination.Recovery).Scan(&pages))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM recovery_destinations WHERE recovery=? AND completeness IS NOT NULL", destination.Recovery).Scan(&complete))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT blocked FROM settings").Scan(&blocked))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT state FROM root_admissions WHERE device=? AND root_guard=?", destination.Device, destination.Root).Scan(&root))
	if rows != 0 || pages != 0 || complete != 0 || !blocked || root != domain.RootPending {
		t.Fatalf("rejected bound page changed durable recovery state: rows=%d pages=%d complete=%d blocked=%t root=%s", rows, pages, complete, blocked, root)
	}
}

func TestCompactKnownReceiptHydrationPreservesAbsentRequestedBrief(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	input := compactPreparation(t, f, "known-inherited-brief", domain.RequestKindContinuation)
	_, err := f.store.Prepare(t.Context(), f.actor, input)
	requireOK(t, err)
	page := compactRestorePage(t, f)
	// Import authenticates the current credential but does not require current
	// dispatch scope to establish the immutable historical owner and request key.
	policy := testOwnerPolicy()
	policy.Scopes = domain.ScopeSet{domain.TaskRead}
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), f.actor.Principal, policy))
	page.Entries = []domain.ImportedInventoryEntry{compactExisting(t, f, input.Correlation)}
	_, err = f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	f.restart(t)
	var bodyNull, optionsNull, digestNull bool
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT request IS NULL,execution_options IS NULL,options_sha256 IS NULL FROM operations WHERE id=?", input.Correlation.Operation).Scan(&bodyNull, &optionsNull, &digestNull))
	row, err := f.store.GetAdministrativeTask(t.Context(), domain.NativeTaskKey{Device: input.Correlation.Destination.Device, Root: input.Correlation.Context.Root, Task: input.Correlation.Task})
	got := must(t, row, err)
	if !bodyNull || !optionsNull || !digestNull || got.Correlation == nil || *got.Correlation != input.Correlation || got.Correlation.BriefDigest != (domain.Digest{}) || got.Receipt == nil || got.Receipt.BriefDigest == (domain.Digest{}) || got.Receipt.Options != (domain.HistoricalExecutionOptions{}) {
		t.Fatal("known compact receipt invented requested options or inherited requested brief")
	}
	_, _, err = f.store.LookupPreparation(t.Context(), f.actor, input.Correlation.Destination.Device, input.Correlation.Route.RequestID, input.Correlation.Route.InputDigest)
	requireCode(t, err, domain.NotFound)
}

func TestCompactAdministrativeDrainUsesExactStoredRouteDuringRecovery(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	c := compactPreparation(t, f, "compact-administrative-drain", domain.RequestKindDispatch).Correlation
	page := compactRestorePage(t, f)
	page.Entries = []domain.ImportedInventoryEntry{compactExisting(t, f, c)}
	_, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	check := domain.AdministrativeDrainCheck{Key: domain.NativeTaskKey{Device: c.Destination.Device, Root: c.Context.Root, Task: c.Task}, Destination: c.Destination, Credential: f.credential, Connection: f.connection, Now: f.now}
	for _, action := range []domain.AdministrativeAction{domain.AdministrativeResolve, domain.AdministrativeFence, domain.AdministrativeStatus, domain.AdministrativeCollect} {
		check.Action = action
		requireOK(t, f.store.CheckAdministrativeDrain(t.Context(), check))
	}
	check.Action = domain.AdministrativeCancel
	requireCode(t, f.store.CheckAdministrativeDrain(t.Context(), check), domain.Conflict)
	_, err = f.store.BindAdministrativeCancellation(t.Context(), check.Key, domain.CancellationID(strings.Repeat("a", 32)))
	requireOK(t, err)
	requireOK(t, f.store.CheckAdministrativeDrain(t.Context(), check))
	check.Destination.Project = "another-operation"
	requireCode(t, f.store.CheckAdministrativeDrain(t.Context(), check), domain.Conflict)
	check.Destination = c.Destination
	_, err = f.store.db.ExecContext(t.Context(), "DELETE FROM device_owners WHERE device=?", c.Destination.Device)
	requireOK(t, err)
	requireCode(t, f.store.CheckAdministrativeDrain(t.Context(), check), domain.EvidenceInvalid)
	_, err = f.store.db.ExecContext(t.Context(), "INSERT INTO device_owners(device,principal) VALUES(?,?)", c.Destination.Device, c.Owner.Principal)
	requireOK(t, err)
	_, err = f.store.NextConnectionGeneration(t.Context(), f.credential, "replacement-drain-connection", f.now)
	requireOK(t, err)
	requireCode(t, f.store.CheckAdministrativeDrain(t.Context(), check), domain.Conflict)
}

func TestCompactAdministrativeDrainRequiresKnownSpecBeforeTaskControls(t *testing.T) {
	f := newFixture(t)
	removeOwnedFixtureProjects(t, f)
	input := compactPreparation(t, f, "compact-drain-unknown-spec", domain.RequestKindDispatch)
	_, err := f.store.Prepare(t.Context(), f.actor, input)
	requireOK(t, err)
	compactRestorePage(t, f)
	c := input.Correlation
	check := domain.AdministrativeDrainCheck{Key: domain.NativeTaskKey{Device: c.Destination.Device, Root: c.Context.Root, Task: c.Task}, Destination: c.Destination, Credential: f.credential, Connection: f.connection, Now: f.now}
	for _, action := range []domain.AdministrativeAction{domain.AdministrativeResolve, domain.AdministrativeFence} {
		check.Action = action
		requireOK(t, f.store.CheckAdministrativeDrain(t.Context(), check))
	}
	for _, action := range []domain.AdministrativeAction{domain.AdministrativeStatus, domain.AdministrativeCollect, domain.AdministrativeCancel} {
		check.Action = action
		requireCode(t, f.store.CheckAdministrativeDrain(t.Context(), check), domain.Conflict)
	}
}
