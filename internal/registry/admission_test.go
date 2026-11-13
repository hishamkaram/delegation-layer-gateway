package registry

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestDispatchOnlyRecoveryRequiresKnownSpecAndCurrentExecutionCeiling(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "recover")
	dispatcher := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	_, err := f.store.GetForRecovery(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.Conflict)
	_, err = f.markSettledControl(t.Context(), dispatcher, f.transmission(c))
	requireOK(t, err)
	_, err = f.store.GetForRecovery(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.Pending)
	known := domain.Hash([]byte("canonical existing spec"))
	observation := domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: known}}
	_, err = f.store.ApplyResolution(t.Context(), domain.ValidatedResolution{ValidatedObservation: observation, DurableRequest: true})
	requireOK(t, err)
	f.restart(t)
	view, err := f.store.GetForRecovery(t.Context(), dispatcher, c.Operation)
	recovery := must(t, view, err)
	if recovery.Correlation != c || recovery.SpecDigest != known {
		t.Fatal("recovery changed canonical identity")
	}
	var requestBytes int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COALESCE(length(request),0) FROM operations WHERE id=?", c.Operation).Scan(&requestBytes))
	if requestBytes != 0 {
		t.Fatal("durable receipt retained brief")
	}
	_, err = f.store.GetOperation(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.Forbidden)
	grant := domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: destination()}, Scopes: f.actor.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 30}}
	requireOK(t, f.store.PutGrant(t.Context(), grant))
	_, err = f.store.GetForRecovery(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.Forbidden)
	f.putGrant(t, f.actor.Principal, f.actor.Scopes)
	// Structurally valid, grant-allowed options with a changed budget must still
	// fail their retained integrity binding after the sensitive brief is gone.
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET execution_options=? WHERE id=?", []byte(`{"Provider":"provider","Model":{"Kind":"native_default","Value":""},"Effort":{"Kind":"native_default","Value":""},"Permission":"read-only","BudgetSeconds":1}`), c.Operation)
	requireOK(t, err)
	_, err = f.store.GetForRecovery(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.EvidenceInvalid)
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET execution_options=NULL,options_sha256=NULL WHERE id=?", c.Operation)
	requireOK(t, err)
	_, err = f.store.GetForRecovery(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.Pending)
	requireOK(t, f.store.RevokeGrant(t.Context(), grant.Key))
	_, err = f.store.GetForRecovery(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.NotFound)
}

func TestCancellationOnlyBindsMetadataAndPermanentlyBlocksUnsentAdmission(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "cancel-unsent")
	canceller := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskCancel}}
	id := domain.CancellationID(strings.Repeat("a", 32))
	binding, err := f.store.BindCancellation(t.Context(), canceller, c.Operation, id)
	stopped := must(t, binding, err)
	if !stopped.DefinitelyUnsent || stopped.Correlation != c || stopped.SpecDigest != (domain.Digest{}) {
		t.Fatal("unsent cancellation returned wrong identity/evidence")
	}
	f.restart(t)
	binding, err = f.store.BindCancellation(t.Context(), canceller, c.Operation, id)
	if must(t, binding, err) != stopped {
		t.Fatal("cancellation binding changed after restart")
	}
	_, err = f.store.BindCancellation(t.Context(), canceller, c.Operation, domain.CancellationID(strings.Repeat("b", 32)))
	requireCode(t, err, domain.Conflict)
	_, err = f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireCode(t, err, domain.Conflict)
	_, err = f.store.GetForDispatch(t.Context(), f.actor, c.Operation, f.now)
	requireCode(t, err, domain.Conflict)
	_, err = f.store.GetOperation(t.Context(), canceller, c.Operation)
	requireCode(t, err, domain.Forbidden)
	view, err := f.store.GetOperation(t.Context(), f.actor, c.Operation)
	if must(t, view, err).Reserved {
		t.Fatal("definitely-unsent cancellation reserved execution")
	}
}

func TestQueuedAdmissionRechecksCancellationAndCurrentAuthority(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *fixture, domain.Correlation)
		code   domain.ErrorCode
	}{
		{"cancel", func(t *testing.T, f *fixture, c domain.Correlation) {
			_, err := f.store.BindCancellation(t.Context(), f.actor, c.Operation, domain.CancellationID(strings.Repeat("a", 32)))
			requireOK(t, err)
		}, domain.Conflict},
		{"grant", func(t *testing.T, f *fixture, _ domain.Correlation) {
			requireOK(t, f.store.RevokeGrant(t.Context(), domain.GrantKey{Principal: f.actor.Principal, Destination: destination()}))
		}, domain.NotFound},
		{"principal denylist", func(t *testing.T, f *fixture, _ domain.Correlation) {
			requireOK(t, f.store.SetPrincipalRevoked(t.Context(), f.actor.Principal, true))
		}, domain.Forbidden},
		{"connection", func(t *testing.T, f *fixture, _ domain.Correlation) {
			_, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "replacement", f.now)
			requireOK(t, err)
		}, domain.Conflict},
		{"ceiling", func(t *testing.T, f *fixture, _ domain.Correlation) {
			requireOK(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: destination()}, Scopes: f.actor.Scopes, Ceiling: domain.DispatchCeiling{Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.WorkspaceWrite}, MaxBudgetSeconds: 300}}))
		}, domain.Forbidden},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.prepare(t, "queued")
			_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
			requireOK(t, err)
			requireOK(t, f.store.CheckQueuedAdmission(t.Context(), f.actor, f.transmission(c)))
			test.change(t, f, c)
			requireCode(t, f.store.CheckQueuedAdmission(t.Context(), f.actor, f.transmission(c)), test.code)
			var reserved bool
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT reserved FROM operations WHERE id=?", c.Operation).Scan(&reserved))
			if !reserved {
				t.Fatal("queued rejection freed possible-send capacity")
			}
		})
	}
}

func TestRegistryOpenRejectsOldOrIncompleteOptionsSchema(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			f := newFixture(t)
			requireOK(t, f.store.Close())
			db, err := sql.Open("sqlite", f.path)
			database := must(t, db, err)
			if version == 1 {
				_, err = database.ExecContext(t.Context(), "PRAGMA user_version=1")
			} else {
				_, err = database.ExecContext(t.Context(), "ALTER TABLE operations DROP COLUMN execution_options")
			}
			requireOK(t, err)
			requireOK(t, database.Close())
			store, err := Open(t.Context(), f.path, options(f.gateway))
			if err == nil {
				requireOK(t, store.Close())
				t.Fatal("old or incomplete registry schema was silently accepted")
			}
		})
	}
}
