package registry

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func importedFixture(t *testing.T, f *fixture) (domain.Correlation, domain.ImportedInventoryPage) {
	t.Helper()
	source := f.prepare(t, "reserved-snapshot")
	_, sendErr := f.markSettledControl(t.Context(), f.actor, f.transmission(source))
	requireOK(t, sendErr)
	page := closureInventoryPage(t, f)
	complete := domain.Hash([]byte("canonical complete"))
	return source, domain.ImportedInventoryPage{Destination: page.Destination, Generation: page.Generation, Membership: page.Membership, CompletenessReceipt: &complete, Now: f.now, Credential: f.credential, Connection: f.connection}
}

func canonicalImport(t *testing.T, c domain.Correlation, operation, task string) domain.CanonicalInventoryExisting {
	t.Helper()
	c.Operation = domain.OperationID(operation)
	c.Task = domain.TaskID(strings.Repeat(task, 32))
	options := domain.ExecutionOptions{Provider: "provider", Permission: domain.ReadOnly, BudgetSeconds: 60, Model: domain.Selection{Kind: domain.NativeDefault}, Effort: domain.Selection{Kind: domain.NativeDefault}}
	digest, err := domain.RequestBindingDigest(c, options, c.BriefDigest)
	c.RequestDigest = must(t, digest, err)
	receipt := domain.NativeTaskReceipt{Binding: domain.NativeTaskBinding{Task: c.Task, Context: c.Context, Origin: domain.OriginFromCorrelation(c), SpecDigest: domain.Hash([]byte(operation + " task bytes"))}, Options: domain.HistoricalExecutionOptions{Provider: options.Provider, Permission: options.Permission, BudgetNanoseconds: int64(time.Minute), Model: options.Model, Effort: options.Effort}, BriefDigest: c.BriefDigest}
	return domain.CanonicalInventoryExisting{Receipt: receipt, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC), SpecDigest: receipt.Binding.SpecDigest}}
}

func TestCanonicalImportKeepsAllHoldsAndReplayClassification(t *testing.T) {
	f := newFixture(t)
	source, page := importedFixture(t, f)
	attributed := canonicalImport(t, source, "attributed", "a")
	unmappedSource := source
	unmappedSource.Destination.Project = "missing-original-alias"
	unmapped := canonicalImport(t, unmappedSource, "unattributed", "b")
	fractional := canonicalImport(t, source, "fractional", "c")
	fractional.Receipt.Options.BudgetNanoseconds = int64(1500 * time.Millisecond)
	page.Entries = []domain.ImportedInventoryEntry{{Existing: &attributed}, {Existing: &unmapped}, {Existing: &fractional}}
	result, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	got := must(t, result, err)
	if !got.CanonicalComplete || got.MissingMappings != 4 {
		t.Fatal("final import dropped a hold or hid mapping debt")
	}
	var attributedCount, unmatchedCount, reserved int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT sum(kind='attributed'),sum(kind='unattributed'),sum(reserved) FROM operations").Scan(&attributedCount, &unmatchedCount, &reserved))
	if attributedCount != 2 || unmatchedCount != 2 || reserved != 4 {
		t.Fatal("canonical import fabricated or dropped attribution/reservations")
	}
	requireOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: unmappedSource.Destination, Context: unmappedSource.Context}))
	page.Now = page.Now.Add(time.Second)
	_, err = f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	row, err := f.store.GetAdministrativeTask(t.Context(), domain.NativeTaskKey{Device: page.Destination.Device, Root: page.Destination.Root, Task: unmapped.Receipt.Binding.Task})
	view := must(t, row, err)
	if view.Correlation != nil || view.Receipt == nil || !view.Reserved {
		t.Fatal("later alias registration promoted an unmatched physical task")
	}
	requireOK(t, f.store.RestartInventory(t.Context(), page.Destination))
	_, err = f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	row, err = f.store.GetAdministrativeTask(t.Context(), view.Key)
	if must(t, row, err).Correlation != nil {
		t.Fatal("a new scan promoted the stored unattributed row during hydration")
	}
	var body []byte
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT completeness FROM recovery_destinations WHERE recovery=?", page.Destination.Recovery).Scan(&body))
	if !digestMatches(body, *page.CompletenessReceipt) {
		t.Fatal("mapping debt prevented durable final completeness")
	}
}

func TestCanonicalImportCollisionRollsBackPage(t *testing.T) {
	for _, kind := range []string{"physical", "origin-operation", "immutable-options"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			source, page := importedFixture(t, f)
			first := canonicalImport(t, source, "first-new-row", "a")
			conflict := canonicalImport(t, source, "conflicting-row", "b")
			switch kind {
			case "physical":
				conflict.Receipt.Binding.Task = source.Task
			case "origin-operation":
				conflict.Receipt.Binding.Origin.Operation = source.Operation
			case "immutable-options":
				conflict.Receipt.Binding.Task = source.Task
				conflict.Receipt.Binding.Origin = domain.OriginFromCorrelation(source)
				conflict.Receipt.Options.Permission = domain.WorkspaceWrite
			}
			page.Entries = []domain.ImportedInventoryEntry{{Existing: &first}, {Existing: &conflict}}
			// Task ordering is a canonical page property, independent of the
			// insertion order that exercises transaction rollback.
			if page.Entries[0].Existing.Receipt.Binding.Task > page.Entries[1].Existing.Receipt.Binding.Task {
				page.Entries[0], page.Entries[1] = page.Entries[1], page.Entries[0]
			}
			_, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
			requireCode(t, err, domain.EvidenceInvalid)
			var rows, pages int
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations WHERE origin_operation=?", first.Receipt.Binding.Origin.Operation).Scan(&rows))
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM inventory_pages WHERE recovery=?", page.Destination.Recovery).Scan(&pages))
			if rows != 0 || pages != 0 {
				t.Fatal("conflicting canonical page committed an earlier row or page progress")
			}
		})
	}
}

func TestOwnerlessAttributionNeverAttachesToLaterLogin(t *testing.T) {
	f := newFixture(t)
	source, page := importedFixture(t, f)
	source.Owner.Principal = "principal-lost-with-snapshot"
	entry := canonicalImport(t, source, "ownerless-attributed", "a")
	page.Entries = []domain.ImportedInventoryEntry{{Existing: &entry}}
	_, err := f.store.ApplyImportedInventoryPage(t.Context(), page)
	requireOK(t, err)
	var owner sql.NullString
	var id domain.OperationID
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT id,owner FROM operations WHERE origin_operation=?", entry.Receipt.Binding.Origin.Operation).Scan(&id, &owner))
	if id != entry.Receipt.Binding.Origin.Operation || owner.Valid {
		t.Fatal("lost principal mapping erased attribution or invented visibility")
	}
	f.putGrant(t, f.actor.Principal, f.actor.Scopes)
	_, err = f.store.GetOperation(t.Context(), f.actor, id)
	requireCode(t, err, domain.NotFound)
	login, err := f.store.ResolvePrincipal(t.Context(), domain.ExternalSubject{Issuer: "https://issuer.example/", Subject: "later-login"})
	actor := domain.Actor{Principal: must(t, login, err).ID, Scopes: domain.ScopeSet{domain.TaskRead}}
	requireOK(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: actor.Principal, Destination: source.Destination}, Scopes: actor.Scopes}))
	_, err = f.store.GetOperation(t.Context(), actor, id)
	requireCode(t, err, domain.NotFound)
	f.restart(t)
	_, err = f.store.GetOperation(t.Context(), actor, id)
	requireCode(t, err, domain.NotFound)
}

func TestFinalCanonicalImportRollsBackRowsWhenCompletenessWriteFails(t *testing.T) {
	f := newFixture(t)
	source, page := importedFixture(t, f)
	entry := canonicalImport(t, source, "failed-final-page", "a")
	page.Entries = []domain.ImportedInventoryEntry{{Existing: &entry}}
	_, err := f.store.db.ExecContext(t.Context(), `CREATE TRIGGER fail_import_completeness BEFORE UPDATE OF completeness ON recovery_destinations BEGIN SELECT RAISE(ABORT,'fixture completeness failure'); END`)
	requireOK(t, err)
	if _, err = f.store.ApplyImportedInventoryPage(t.Context(), page); err == nil {
		t.Fatal("injected final completeness failure was hidden")
	}
	var imported, pages, complete int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations WHERE origin_operation=?", entry.Receipt.Binding.Origin.Operation).Scan(&imported))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM inventory_pages WHERE recovery=?", page.Destination.Recovery).Scan(&pages))
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM recovery_destinations WHERE recovery=? AND completeness IS NOT NULL", page.Destination.Recovery).Scan(&complete))
	if imported != 0 || pages != 0 || complete != 0 {
		t.Fatal("failed final transaction retained imported rows, progress or completeness")
	}
}
