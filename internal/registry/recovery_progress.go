package registry

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func (s *Store) ReadRecoveryProgress(ctx context.Context, input domain.RecoveryProgressRequest) (domain.RecoveryProgressPage, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.RecoveryProgressPage{}, err
	}
	if err := validateRecoveryProgressRequest(input); err != nil {
		return domain.RecoveryProgressPage{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.RecoveryProgressPage, error) {
		return readRecoveryProgress(ctx, tx, input)
	})
}

func validateRecoveryProgressRequest(input domain.RecoveryProgressRequest) error {
	if input.Now.IsZero() || input.Recovery != "" && domain.RoutingToken(string(input.Recovery)) != nil {
		return domain.ErrInvalid
	}
	if _, err := domain.PageLimit(input.Limit); err != nil {
		return err
	}
	if input.After != nil && (domain.CredentialToken(string(input.After.Device)) != nil || domain.ContextToken(string(input.After.Root)) != nil) {
		return domain.ErrInvalid
	}
	return nil
}

func readRecoveryProgress(ctx context.Context, tx *sql.Tx, input domain.RecoveryProgressRequest) (domain.RecoveryProgressPage, error) {
	var result domain.RecoveryProgressPage
	id := input.Recovery
	if id == "" {
		if err := tx.QueryRowContext(ctx, "SELECT recovery FROM settings WHERE id=1").Scan(&id); err != nil {
			return result, err
		}
		if id == "" {
			return result, domain.Reject(domain.NotFound)
		}
	}
	var started string
	err := tx.QueryRowContext(ctx, "SELECT kind,coalesce(epoch,''),started,sealed,status,revision FROM recoveries WHERE id=?", id).Scan(&result.Session.Kind, &result.Session.Epoch, &started, &result.Session.RosterSealed, &result.Status, &result.Revision)
	if err != nil {
		return result, notFound(err)
	}
	result.Session.ID = id
	result.Session.StartedAt, err = time.Parse(time.RFC3339Nano, started)
	if err != nil {
		return result, err
	}
	if !validRecoveryStatus(result.Status) || result.Session.Kind != domain.RootRecovery && result.Session.Kind != domain.RestoreRecovery {
		return result, domain.Reject(domain.EvidenceInvalid)
	}
	result.Destinations, err = readRecoveryDestinationPage(ctx, tx, id, input)
	if err != nil {
		return result, err
	}
	if len(result.Destinations) > input.Limit {
		result.Destinations = result.Destinations[:input.Limit]
		last := result.Destinations[len(result.Destinations)-1].Destination
		result.Next = &domain.RecoveryDestinationCursor{Device: last.Device, Root: last.Root}
	}
	for index := range result.Destinations {
		progress := &result.Destinations[index]
		if err = deriveRecoveryDestination(ctx, tx, progress, result, input.Now); err != nil {
			return result, err
		}
	}
	return result, nil
}

func validRecoveryStatus(status domain.RecoveryStatus) bool {
	switch status {
	case domain.RecoveryActive, domain.RecoveryFinished, domain.RecoveryAborted:
		return true
	default:
		return false
	}
}

func readRecoveryDestinationPage(ctx context.Context, tx *sql.Tx, id domain.RecoveryID, input domain.RecoveryProgressRequest) (items []domain.RecoveryDestinationProgress, err error) {
	after := domain.RecoveryDestinationCursor{}
	if input.After != nil {
		after = *input.After
	}
	rows, err := tx.QueryContext(ctx, "SELECT device,root_guard,generation,expected_generation,barrier,cursor,membership,completeness,approved,reopened FROM recovery_destinations WHERE recovery=? AND (device,root_guard)>(?,?) ORDER BY device,root_guard LIMIT ?", id, after.Device, after.Root, input.Limit+1)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		progress, scanErr := scanRecoveryDestination(rows, id)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, progress)
	}
	return items, rows.Err()
}

func scanRecoveryDestination(rows *sql.Rows, id domain.RecoveryID) (domain.RecoveryDestinationProgress, error) {
	result := domain.RecoveryDestinationProgress{Destination: domain.RecoveryDestination{Recovery: id}}
	var generation, expected domain.AdmissionGeneration
	var barrier, membership, completeness, reopened []byte
	var approved bool
	if err := rows.Scan(&result.Destination.Device, &result.Destination.Root, &generation, &expected, &barrier, &result.Cursor, &membership, &completeness, &approved, &reopened); err != nil {
		return result, err
	}
	if err := validateRecoveryDestination(result.Destination); err != nil {
		return result, domain.Reject(domain.EvidenceInvalid)
	}
	if generation != "" {
		if domain.RoutingToken(string(generation)) != nil || expected != "" && domain.RoutingToken(string(expected)) != nil {
			return result, domain.Reject(domain.EvidenceInvalid)
		}
		result.Barrier = &domain.BarrierPlan{Destination: result.Destination, Generation: generation, ExpectedGeneration: expected}
	}
	for _, item := range []struct {
		data   []byte
		target **domain.Digest
	}{{barrier, &result.BarrierReceipt}, {membership, &result.Membership}, {completeness, &result.Completeness}, {reopened, &result.RecordedReopen}} {
		if len(item.data) == 0 {
			continue
		}
		if len(item.data) != len(domain.Digest{}) {
			return result, domain.Reject(domain.EvidenceInvalid)
		}
		var digest domain.Digest
		copy(digest[:], item.data)
		if digest.Validate() != nil {
			return result, domain.Reject(domain.EvidenceInvalid)
		}
		*item.target = &digest
	}
	if approved {
		if result.Completeness == nil || result.Barrier == nil {
			return result, domain.Reject(domain.EvidenceInvalid)
		}
		result.Reopen = &domain.ReopenTarget{Destination: result.Destination, Generation: generation, Completeness: *result.Completeness}
	}
	return result, nil
}

func deriveRecoveryDestination(ctx context.Context, tx *sql.Tx, progress *domain.RecoveryDestinationProgress, page domain.RecoveryProgressPage, now time.Time) error {
	switch page.Status {
	case domain.RecoveryFinished:
		progress.Stage = domain.RootReady
		progress.Reopen = nil
		return nil
	case domain.RecoveryAborted:
		progress.Stage = domain.RootRestoreRequired
		progress.Reopen = nil
		return nil
	case domain.RecoveryActive:
	default:
		return domain.Reject(domain.EvidenceInvalid)
	}
	switch {
	case progress.BarrierReceipt == nil:
		progress.Stage = domain.RootNeedsBarrier
		return nil
	case progress.Completeness == nil:
		progress.Stage = domain.RootNeedsInventory
		return nil
	}
	var err error
	progress.MissingMappings, err = missingDestinationMappings(ctx, tx, progress.Destination)
	if err != nil {
		return err
	}
	if progress.MissingMappings != 0 {
		progress.Stage = domain.RootNeedsMapping
		progress.Reopen = nil
		return nil
	}
	if err = regularRecoveryCredential(ctx, tx, progress.Destination.Device, now); err != nil {
		if hasCode(err, domain.Forbidden) || hasCode(err, domain.NotFound) || hasCode(err, domain.Expired) {
			progress.Stage = domain.RootNeedsRegularCredential
			progress.Reopen = nil
			return nil
		}
		return err
	}
	if progress.Reopen == nil {
		progress.Stage = domain.RootNeedsApproval
		return nil
	}
	progress.Stage = domain.RootNeedsReopen
	progress.Reopen.Revision = page.Revision
	if progress.RecordedReopen != nil {
		progress.Stage = domain.RootReady
	}
	return nil
}
