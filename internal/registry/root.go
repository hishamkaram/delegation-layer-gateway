package registry

import (
	"context"
	"database/sql"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func rootLookup(ctx context.Context, tx *sql.Tx, input domain.RootInitializationLookup) error {
	if input.Validate() != nil {
		return domain.ErrInvalid
	}
	if input.RootRoute != nil {
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM root_admissions WHERE device=? AND root_guard=?", input.RootRoute.Device, input.RootRoute.Root).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return domain.Reject(domain.NotFound)
		}
		return nil
	}
	binding, err := readContext(ctx, tx, input.Route)
	if err != nil {
		return err
	}
	if binding != input.ExpectedContext {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func (s *Store) BeginRootInitialization(ctx context.Context, input domain.RootInitializationStart) (domain.RootInitializationProgress, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.RootInitializationProgress{}, err
	}
	lookup := input.Lookup()
	root, err := lookup.Namespace()
	if err != nil || input.Now.IsZero() || input.Credential.Device != root.Device {
		return domain.RootInitializationProgress{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.RootInitializationProgress, error) {
		return beginRootInitialization(ctx, tx, input, lookup)
	})
}

func startRootSession(ctx context.Context, tx *sql.Tx, id domain.RecoveryID, input domain.RootInitializationStart) error {
	root, err := input.Lookup().Namespace()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO recoveries(id,kind,started,sealed) VALUES(?,'root',?,1)", id, input.Now.UTC().Format(timestampLayout)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO recovery_destinations(recovery,device,root_guard) VALUES(?,?,?)", id, root.Device, root.Root); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE root_admissions SET session=?,state='pending' WHERE device=? AND root_guard=?", id, root.Device, root.Root); err != nil {
		return err
	}
	_, err = prepareBarrier(ctx, tx, domain.BarrierPreparation{Destination: domain.RecoveryDestination{Recovery: id, Device: root.Device, Root: root.Root}, Credential: input.Credential, Connection: input.Connection, Now: input.Now})
	return err
}

func (s *Store) ReadRootInitializationProgress(ctx context.Context, input domain.RootInitializationLookup) (domain.RootInitializationProgress, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.RootInitializationProgress{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.RootInitializationProgress, error) {
		if err := rootLookup(ctx, tx, input); err != nil {
			return domain.RootInitializationProgress{}, err
		}
		return readRootProgress(ctx, tx, input)
	})
}

func readRootProgress(ctx context.Context, tx *sql.Tx, input domain.RootInitializationLookup) (domain.RootInitializationProgress, error) {
	root, err := input.Namespace()
	if err != nil {
		return domain.RootInitializationProgress{}, err
	}
	result := domain.RootInitializationProgress{Route: input.Route, Context: input.ExpectedContext, RootRoute: input.RootRoute, Stage: domain.RootNeedsBarrier}
	var state domain.RootState
	if err = tx.QueryRowContext(ctx, "SELECT gateway FROM settings WHERE id=1").Scan(&result.GatewayID); err != nil {
		return result, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT state,generation,session FROM root_admissions WHERE device=? AND root_guard=?", root.Device, root.Root).Scan(&state, &result.Generation, &result.RecoveryID); err != nil {
		return result, notFound(err)
	}
	if state == domain.RootOpen {
		result.Stage = domain.RootReady
		return result, nil
	}
	if state != domain.RootPending {
		return result, domain.Reject(domain.EvidenceInvalid)
	}
	if result.RecoveryID == "" {
		return result, nil
	}
	session, err := readRecovery(ctx, tx, result.RecoveryID)
	if err != nil {
		return result, err
	}
	if session.status == "aborted" {
		result.Stage = domain.RootRestoreRequired
		err = tx.QueryRowContext(ctx, "SELECT generation FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", result.RecoveryID, root.Device, root.Root).Scan(&result.Generation)
		return result, err
	}
	var barrier, membership, complete, reopened []byte
	var approved bool
	if err = tx.QueryRowContext(ctx, "SELECT generation,barrier,membership,cursor,completeness,approved,reopened FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", result.RecoveryID, root.Device, root.Root).Scan(&result.Generation, &barrier, &membership, &result.Cursor, &complete, &approved, &reopened); err != nil {
		return result, err
	}
	copy(result.Membership[:], membership)
	copy(result.Completeness[:], complete)
	switch {
	case len(barrier) == 0:
		result.Stage = domain.RootNeedsBarrier
	case len(complete) == 0:
		result.Stage = domain.RootNeedsInventory
	case !approved:
		result.Stage = domain.RootNeedsApproval
	default:
		result.Stage = domain.RootNeedsReopen
		result.Reopen = &domain.ReopenTarget{Destination: domain.RecoveryDestination{Recovery: result.RecoveryID, Device: root.Device, Root: root.Root}, Generation: result.Generation, Completeness: result.Completeness, Revision: session.revision}
	}
	return result, nil
}

func (s *Store) AbandonRootInitialization(ctx context.Context, id domain.RecoveryID) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if domain.RoutingToken(string(id)) != nil {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		session, err := readRecovery(ctx, tx, id)
		if err != nil {
			return struct{}{}, err
		}
		if session.kind != domain.RootRecovery {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		if session.status == "aborted" {
			return struct{}{}, nil
		}
		if session.status != "active" {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		var reopened int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM recovery_destinations WHERE recovery=? AND reopened IS NOT NULL", id).Scan(&reopened); err != nil {
			return struct{}{}, err
		}
		if reopened != 0 {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		if _, err = tx.ExecContext(ctx, "UPDATE recoveries SET status='aborted',revision=revision+1 WHERE id=?", id); err != nil {
			return struct{}{}, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE root_admissions SET state='pending' WHERE session=?", id); err != nil {
			return struct{}{}, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET approved=0 WHERE recovery=?", id)
		return struct{}{}, err
	})
	return err
}

func beginRootInitialization(ctx context.Context, tx *sql.Tx, input domain.RootInitializationStart, lookup domain.RootInitializationLookup) (domain.RootInitializationProgress, error) {
	if err := rootLookup(ctx, tx, lookup); err != nil {
		return domain.RootInitializationProgress{}, err
	}
	if err := admissionsOpen(ctx, tx); err != nil {
		return domain.RootInitializationProgress{}, err
	}
	cred, err := checkConnection(ctx, tx, input.Credential, input.Connection, input.Now)
	if err != nil {
		return domain.RootInitializationProgress{}, err
	}
	if cred.Mode != domain.Regular {
		return domain.RootInitializationProgress{}, domain.Reject(domain.Forbidden)
	}
	progress, err := readRootProgress(ctx, tx, lookup)
	if err != nil {
		return progress, err
	}
	if progress.Stage == domain.RootRestoreRequired {
		return progress, domain.Reject(domain.Conflict)
	}
	if progress.RecoveryID != "" || progress.Stage == domain.RootReady {
		return progress, nil
	}
	id, err := mintAdmissionToken()
	if err != nil {
		return progress, err
	}
	if err = startRootSession(ctx, tx, domain.RecoveryID(id), input); err != nil {
		return progress, err
	}
	return readRootProgress(ctx, tx, lookup)
}
