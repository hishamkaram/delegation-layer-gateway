package registry

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func seedExpiredHistory(t *testing.T, f *fixture, seed domain.Preparation) {
	t.Helper()
	options, err := encode(seed.Request.Options())
	requireOK(t, err)
	optionsDigest := domain.Hash(options)
	_, err = transaction(t.Context(), f.store, func(tx *sql.Tx) (_ struct{}, result error) {
		statement, prepareErr := tx.PrepareContext(t.Context(), "INSERT INTO operations(id,origin_operation,kind,task,owner,device,root_guard,project_guard,project,correlation,execution_options,options_sha256,state,created,expires) VALUES(?,?,'attributed',?,?,?,?,?,?,?,?,?,?,?,?)")
		if prepareErr != nil {
			return struct{}{}, prepareErr
		}
		defer func() { result = errors.Join(result, statement.Close()) }()
		// The former lifetime limit was 100000. Each row is valid durable expired
		// evidence with no retained body; this history must never block new work.
		for number := range 100000 {
			c := seed.Correlation
			c.Operation = domain.OperationID(fmt.Sprintf("historical-%d", number))
			task := domain.Hash([]byte(c.Operation))
			c.Task = domain.TaskID(hex.EncodeToString(task[:16]))
			digest, digestErr := domain.RequestDigest(c, seed.Request)
			if digestErr != nil {
				return struct{}{}, digestErr
			}
			c.RequestDigest = digest
			encoded, encodeErr := encode(c)
			if encodeErr != nil {
				return struct{}{}, encodeErr
			}
			if _, err = statement.ExecContext(t.Context(), c.Operation, c.Operation, c.Task, c.Owner.Principal, c.Destination.Device, c.Context.Root, c.Context.Project, c.Destination.Project, encoded, options, optionsDigest[:], domain.ExpiredUnsent, seed.Now.UTC().Format(timestampLayout), seed.Now.UTC().Format(timestampLayout)); err != nil {
				return struct{}{}, err
			}
		}
		return struct{}{}, nil
	})
	requireOK(t, err)
}

func TestDurableHistoryNeverLimitsPreparationOrRecoveryImport(t *testing.T) {
	f := newFixture(t)
	seed := preparationInput(t, f, f.actor, "history-seed", f.now)
	seedExpiredHistory(t, f, seed)
	f.restart(t)
	f.prepare(t, "after-one-hundred-thousand")
	page := closureInventoryPage(t, f)
	page.Entries = []domain.InventoryEntry{{Correlation: seed.Correlation, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("native-existing-history"))}}}
	requireOK(t, f.store.ApplyInventoryPage(t.Context(), page))
	var rows int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations").Scan(&rows))
	if rows != 100002 {
		t.Fatalf("history was discarded or recovery failed to append: %d rows", rows)
	}
}
