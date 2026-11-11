package registry

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type recoveryState struct {
	kind     domain.RecoveryKind
	status   string
	sealed   bool
	revision uint64
}

func readRecovery(ctx context.Context, tx *sql.Tx, id domain.RecoveryID) (recoveryState, error) {
	var state recoveryState
	err := tx.QueryRowContext(ctx, "SELECT kind,status,sealed,revision FROM recoveries WHERE id=?", id).Scan(&state.kind, &state.status, &state.sealed, &state.revision)
	return state, notFound(err)
}

func activeRecovery(ctx context.Context, tx *sql.Tx, id domain.RecoveryID, requireSealed bool) error {
	if domain.RoutingToken(string(id)) != nil {
		return domain.ErrInvalid
	}
	state, err := readRecovery(ctx, tx, id)
	if err != nil {
		var classified *domain.Error
		if errors.As(err, &classified) && classified.Code == domain.NotFound {
			return domain.Reject(domain.Conflict)
		}
		return err
	}
	if state.status != "active" || requireSealed && !state.sealed {
		return domain.Reject(domain.Conflict)
	}
	var blocked bool
	var active domain.RecoveryID
	if err = tx.QueryRowContext(ctx, "SELECT blocked,recovery FROM settings WHERE id=1").Scan(&blocked, &active); err != nil {
		return err
	}
	switch state.kind {
	case domain.RestoreRecovery:
		if !blocked || active != id {
			return domain.Reject(domain.Conflict)
		}
	case domain.RootRecovery:
		if blocked {
			return domain.Reject(domain.Pending)
		}
	default:
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func mintAdmissionToken() (string, error) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(entropy[:]), nil
}

func validateBarrierPreparation(input domain.BarrierPreparation) error {
	if err := validateRecoveryDestination(input.Destination); err != nil {
		return err
	}
	if input.ExpectedGeneration != "" && domain.RoutingToken(string(input.ExpectedGeneration)) != nil {
		return domain.ErrInvalid
	}
	if input.Credential.Device != input.Destination.Device || input.Now.IsZero() {
		return domain.ErrInvalid
	}
	if err := input.Credential.Validate(); err != nil {
		return err
	}
	return input.Connection.Validate()
}

func (s *Store) PrepareRecoveryBarrier(ctx context.Context, input domain.BarrierPreparation) (domain.BarrierPlan, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.BarrierPlan{}, err
	}
	if err := validateBarrierPreparation(input); err != nil {
		return domain.BarrierPlan{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.BarrierPlan, error) { return prepareBarrier(ctx, tx, input) })
}

func prepareBarrier(ctx context.Context, tx *sql.Tx, input domain.BarrierPreparation) (domain.BarrierPlan, error) {
	plan := domain.BarrierPlan{Destination: input.Destination, ExpectedGeneration: input.ExpectedGeneration}
	session, err := barrierSession(ctx, tx, input)
	if err != nil {
		return plan, err
	}
	var generation, expected domain.AdmissionGeneration
	if err = tx.QueryRowContext(ctx, "SELECT generation,expected_generation FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", input.Destination.Recovery, input.Destination.Device, input.Destination.Root).Scan(&generation, &expected); err != nil {
		return plan, notFound(err)
	}
	if generation != "" {
		if expected != input.ExpectedGeneration && generation != input.ExpectedGeneration {
			return plan, domain.Reject(domain.Conflict)
		}
		plan.ExpectedGeneration = expected
		plan.Generation = generation
		return plan, nil
	}
	if session.kind == domain.RestoreRecovery && input.ExpectedGeneration == "" {
		if err = rejectKnownOriginLoss(ctx, tx, input.Destination); err != nil {
			return plan, err
		}
	}
	token, err := mintAdmissionToken()
	if err != nil {
		return plan, err
	}
	plan.Generation = domain.AdmissionGeneration(token)
	_, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET generation=?,expected_generation=? WHERE recovery=? AND device=? AND root_guard=?", plan.Generation, plan.ExpectedGeneration, input.Destination.Recovery, input.Destination.Device, input.Destination.Root)
	return plan, err
}

func (s *Store) CheckReopen(ctx context.Context, input domain.ReopenCheck) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if input.Now.IsZero() || input.Credential.Device != input.Target.Destination.Device || input.Credential.Validate() != nil || input.Connection.Validate() != nil {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if _, err := checkConnection(ctx, tx, input.Credential, input.Connection, input.Now); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, checkReopenTarget(ctx, tx, input.Target, input.Now)
	})
	return err
}

func checkReopenTarget(ctx context.Context, tx *sql.Tx, target domain.ReopenTarget, now time.Time) error {
	if err := validateRecoveryDestination(target.Destination); err != nil {
		return err
	}
	if target.Revision == 0 || target.Completeness.Validate() != nil || domain.RoutingToken(string(target.Generation)) != nil {
		return domain.ErrInvalid
	}
	if err := activeRecovery(ctx, tx, target.Destination.Recovery, true); err != nil {
		return err
	}
	state, err := readRecovery(ctx, tx, target.Destination.Recovery)
	if err != nil {
		return err
	}
	if state.revision != target.Revision {
		return domain.Reject(domain.Conflict)
	}
	if err = regularRecoveryCredential(ctx, tx, target.Destination.Device, now); err != nil {
		return err
	}
	var approved bool
	var generation domain.AdmissionGeneration
	var completeness []byte
	if err = tx.QueryRowContext(ctx, "SELECT approved,generation,completeness FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", target.Destination.Recovery, target.Destination.Device, target.Destination.Root).Scan(&approved, &generation, &completeness); err != nil {
		return notFound(err)
	}
	if !approved || generation != target.Generation || !digestMatches(completeness, target.Completeness) {
		return domain.Reject(domain.Conflict)
	}
	if state.kind == domain.RestoreRecovery {
		if err = requireRoutingRecoveryCoverage(ctx, tx); err != nil {
			return err
		}
	}
	return requireRecoveryMappings(ctx, tx, target.Destination.Recovery, now, true, "")
}

func digestMatches(data []byte, digest domain.Digest) bool {
	return len(data) == len(digest) && string(data) == string(digest[:])
}

func requireNoRootSessions(ctx context.Context, tx *sql.Tx) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM recoveries WHERE kind='root' AND status='active'").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func sessionCoverage(ctx context.Context, tx *sql.Tx, id domain.RecoveryID) error {
	state, err := readRecovery(ctx, tx, id)
	if err != nil {
		return err
	}
	if state.kind == domain.RootRecovery {
		return nil
	}
	return requireRoutingRecoveryCoverage(ctx, tx)
}

func rejectKnownOriginLoss(ctx context.Context, tx *sql.Tx, d domain.RecoveryDestination) error {
	var known bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM root_admissions WHERE device=? AND root_guard=? AND generation!='') OR EXISTS(SELECT 1 FROM recovery_destinations WHERE device=? AND root_guard=? AND barrier IS NOT NULL)`, d.Device, d.Root, d.Device, d.Root).Scan(&known)
	if err != nil {
		return err
	}
	if known {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func barrierSession(ctx context.Context, tx *sql.Tx, input domain.BarrierPreparation) (recoveryState, error) {
	if err := activeRecovery(ctx, tx, input.Destination.Recovery, true); err != nil {
		return recoveryState{}, err
	}
	state, err := readRecovery(ctx, tx, input.Destination.Recovery)
	if err != nil {
		return state, err
	}
	credential, err := checkConnection(ctx, tx, input.Credential, input.Connection, input.Now)
	if err != nil {
		return state, err
	}
	if state.kind == domain.RootRecovery && (credential.Mode != domain.Regular || input.ExpectedGeneration != "") {
		return state, domain.Reject(domain.Forbidden)
	}
	return state, nil
}
