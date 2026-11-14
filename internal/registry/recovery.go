package registry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func (s *Store) BeginRecovery(ctx context.Context, input domain.RecoveryStart) (domain.RecoverySession, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.RecoverySession{}, err
	}
	if err := domain.Token(string(input.ID)); err != nil {
		return domain.RecoverySession{}, err
	}
	if err := domain.CredentialToken(string(input.Epoch)); err != nil {
		return domain.RecoverySession{}, err
	}
	if input.Now.IsZero() {
		return domain.RecoverySession{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.RecoverySession, error) {
		if err := requireNoRootSessions(ctx, tx); err != nil {
			return domain.RecoverySession{}, err
		}
		var epoch domain.CredentialEpoch
		var active domain.RecoveryID
		var started string
		var sealed bool
		var blocked bool
		if err := tx.QueryRowContext(ctx, "SELECT s.epoch,s.recovery,coalesce(r.started,''),coalesce(r.sealed,0),s.blocked FROM settings s LEFT JOIN recoveries r ON r.id=s.recovery WHERE s.id=1").Scan(&epoch, &active, &started, &sealed, &blocked); err != nil {
			return domain.RecoverySession{}, err
		}
		if active == input.ID && epoch == input.Epoch {
			if !blocked {
				return domain.RecoverySession{}, domain.Reject(domain.Conflict)
			}
			when, err := time.Parse(time.RFC3339Nano, started)
			return domain.RecoverySession{Kind: domain.RestoreRecovery, ID: active, Epoch: epoch, StartedAt: when, RosterSealed: sealed}, err
		}
		if epoch == input.Epoch {
			return domain.RecoverySession{}, domain.Reject(domain.Conflict)
		}
		return startRecovery(ctx, tx, input)
	})
}

func startRecovery(ctx context.Context, tx *sql.Tx, input domain.RecoveryStart) (domain.RecoverySession, error) {
	if err := ensureRecoveryIdentityUnused(ctx, tx, input); err != nil {
		return domain.RecoverySession{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO credential_epochs(epoch) VALUES(?)", input.Epoch); err != nil {
		return domain.RecoverySession{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE recoveries SET status='aborted',revision=revision+1 WHERE kind='restore' AND status='active'"); err != nil {
		return domain.RecoverySession{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO recoveries(id,kind,epoch,started) VALUES(?,'restore',?,?)", input.ID, input.Epoch, input.Now.UTC().Format(timestampLayout)); err != nil {
		return domain.RecoverySession{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE settings SET epoch=?,blocked=1,recovery=? WHERE id=1", input.Epoch, input.ID); err != nil {
		return domain.RecoverySession{}, err
	}
	for _, statement := range []string{"DELETE FROM enrollment", "DELETE FROM credentials", "DELETE FROM grants", "DELETE FROM owner_policies"} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return domain.RecoverySession{}, err
		}
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO recovery_destinations(recovery,device,root_guard) SELECT ?,device,root_guard FROM projects GROUP BY device,root_guard", input.ID)
	if err != nil {
		return domain.RecoverySession{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO recovery_destinations(recovery,device,root_guard) SELECT ?,device,root_guard FROM operations`, input.ID); err != nil {
		return domain.RecoverySession{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO recovery_destinations(recovery,device,root_guard) SELECT ?,device,root_guard FROM root_admissions", input.ID); err != nil {
		return domain.RecoverySession{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO root_admissions(device,root_guard) SELECT device,root_guard FROM recovery_destinations WHERE recovery=?", input.ID); err != nil {
		return domain.RecoverySession{}, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE root_admissions SET state='pending',session=?", input.ID)
	return domain.RecoverySession{Kind: domain.RestoreRecovery, ID: input.ID, Epoch: input.Epoch, StartedAt: input.Now}, err
}

func validateRecoveryDestination(destination domain.RecoveryDestination) error {
	if err := domain.RoutingToken(string(destination.Recovery)); err != nil {
		return err
	}
	if err := domain.CredentialToken(string(destination.Device)); err != nil {
		return err
	}
	return domain.ContextToken(string(destination.Root))
}

func (s *Store) RegisterRecoveryDestination(ctx context.Context, destination domain.RecoveryDestination) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validateRecoveryDestination(destination); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if err := activeRecovery(ctx, tx, destination.Recovery, false); err != nil {
			return struct{}{}, err
		}
		var sealed bool
		if err := tx.QueryRowContext(ctx, "SELECT sealed FROM recoveries WHERE id=?", destination.Recovery).Scan(&sealed); err != nil {
			return struct{}{}, err
		}
		if sealed {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		if _, err := readDevice(ctx, tx, destination.Device); err != nil {
			return struct{}{}, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO root_admissions(device,root_guard,session) VALUES(?,?,?)", destination.Device, destination.Root, destination.Recovery); err != nil {
			return struct{}{}, err
		}
		_, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO recovery_destinations(recovery,device,root_guard) VALUES(?,?,?)", destination.Recovery, destination.Device, destination.Root)
		return struct{}{}, err
	})
	return err
}

func (s *Store) SealRecoveryRoster(ctx context.Context, input domain.RecoveryRosterSeal) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if input.ExpectedDestinations < 0 {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if err := activeRecovery(ctx, tx, input.Recovery, false); err != nil {
			return struct{}{}, err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM recovery_destinations WHERE recovery=?", input.Recovery).Scan(&count); err != nil {
			return struct{}{}, err
		}
		if count != input.ExpectedDestinations {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		_, err := tx.ExecContext(ctx, "UPDATE recoveries SET sealed=1 WHERE id=?", input.Recovery)
		return struct{}{}, err
	})
	return err
}

func (s *Store) RecordBarrier(ctx context.Context, input domain.ValidatedBarrierReceipt) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validateRecoveryDestination(input.Destination); err != nil {
		return err
	}
	if err := domain.Token(string(input.Generation)); err != nil {
		return err
	}
	if err := input.Receipt.Validate(); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return recordBarrier(ctx, tx, input)
	})
	return err
}

type inventoryState struct {
	barrier    []byte
	generation domain.AdmissionGeneration
	membership []byte
	cursor     string
	started    bool
	finished   bool
}

type inventoryIdentityRecord struct {
	CompletenessReceipt *domain.Digest
	Destination         domain.RecoveryDestination
	Generation          domain.AdmissionGeneration
	Cursor              string
	NextCursor          string
	Membership          domain.Digest
	Correlations        []domain.Correlation
}

// Membership replay excludes lifecycle observations and local receipt times.
// Those may advance without changing Delegate's canonical membership token.
func inventoryIdentity(page domain.ValidatedInventoryPage) inventoryIdentityRecord {
	identity := inventoryIdentityRecord{CompletenessReceipt: page.CompletenessReceipt, Destination: page.Destination, Generation: page.Generation, Cursor: page.Cursor, NextCursor: page.NextCursor, Membership: page.Membership}
	for _, entry := range page.Entries {
		identity.Correlations = append(identity.Correlations, entry.Correlation)
	}
	return identity
}

func readInventoryState(ctx context.Context, tx *sql.Tx, destination domain.RecoveryDestination) (inventoryState, error) {
	var result inventoryState
	err := tx.QueryRowContext(ctx, "SELECT generation,membership,cursor,started,finished,barrier FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", destination.Recovery, destination.Device, destination.Root).Scan(&result.generation, &result.membership, &result.cursor, &result.started, &result.finished, &result.barrier)
	return result, notFound(err)
}

func (s *Store) ApplyInventoryPage(ctx context.Context, input domain.ValidatedInventoryPage) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validateInventoryPage(input); err != nil {
		return err
	}
	encoded, err := encode(inventoryIdentity(input))
	if err != nil {
		return err
	}
	digest := domain.Hash(encoded)
	_, err = transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return applyValidatedInventoryPage(ctx, tx, input, digest)
	})
	return err
}

func validateInventoryPage(input domain.ValidatedInventoryPage) error {
	if err := validateRecoveryDestination(input.Destination); err != nil {
		return err
	}
	if err := domain.Token(string(input.Generation)); err != nil {
		return err
	}
	if err := input.Membership.Validate(); err != nil {
		return err
	}
	if input.Now.IsZero() || len(input.Entries) > domain.MaxPageLimit || len(input.Cursor) > 4096 || len(input.NextCursor) > 4096 || input.NextCursor != "" && input.NextCursor == input.Cursor {
		return domain.ErrInvalid
	}
	if err := validateFinalInventoryReceipt(input); err != nil {
		return err
	}
	for _, entry := range input.Entries {
		if err := validateInventoryEntry(entry, input.Destination, input.Now); err != nil {
			return err
		}
	}
	return nil
}

func validateInventoryEntry(entry domain.InventoryEntry, destination domain.RecoveryDestination, now time.Time) error {
	if err := entry.Correlation.Validate(); err != nil {
		return err
	}
	if err := entry.Observation.Validate(now); err != nil {
		return err
	}
	if entry.Correlation.Destination.Device != destination.Device || entry.Correlation.Context.Root != destination.Root {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func applyInventoryPage(ctx context.Context, tx *sql.Tx, input domain.ValidatedInventoryPage, state inventoryState, digest domain.Digest) (struct{}, error) {
	if state.finished || state.cursor != input.Cursor || state.started && !bytes.Equal(state.membership, input.Membership[:]) {
		return struct{}{}, domain.Reject(domain.Conflict)
	}
	session, sessionErr := readRecovery(ctx, tx, input.Destination.Recovery)
	if sessionErr != nil {
		return struct{}{}, sessionErr
	}
	for _, entry := range input.Entries {
		if session.kind == domain.RootRecovery {
			if entry.Observation.Kind != domain.Refused {
				return struct{}{}, domain.Reject(domain.EvidenceInvalid)
			}
			continue
		}
		if err := importInventoryEntry(ctx, tx, input, entry); err != nil {
			return struct{}{}, err
		}
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO inventory_pages(recovery,device,root_guard,cursor,digest) VALUES(?,?,?,?,?)", input.Destination.Recovery, input.Destination.Device, input.Destination.Root, input.Cursor, digest[:])
	if err != nil {
		return struct{}{}, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET membership=?,cursor=?,started=1,finished=? WHERE recovery=? AND device=? AND root_guard=?", input.Membership[:], input.NextCursor, input.NextCursor == "", input.Destination.Recovery, input.Destination.Device, input.Destination.Root)
	return struct{}{}, err
}

func importInventoryEntry(ctx context.Context, tx *sql.Tx, page domain.ValidatedInventoryPage, entry domain.InventoryEntry) error {
	var gateway domain.GatewayID
	if err := tx.QueryRowContext(ctx, "SELECT gateway FROM settings WHERE id=1").Scan(&gateway); err != nil {
		return err
	}
	if gateway != entry.Correlation.Gateway {
		return domain.Reject(domain.EvidenceInvalid)
	}
	op, err := readOperation(ctx, tx, entry.Correlation.Operation)
	if err == nil {
		if op.view.Correlation != entry.Correlation {
			return domain.Reject(domain.Conflict)
		}
		if op.view.Observation != nil && op.view.Observation.Kind == domain.Terminal && entry.Observation.Kind == domain.Existing {
			return checkTerminalInventoryPresence(*op.view.Observation, entry.Observation)
		}
		if op.view.Delivery == domain.Prepared || op.view.Delivery == domain.ExpiredUnsent {
			op.view.Delivery = domain.PossibleSend
			op.view.Reserved = true
		}
		_, err = applyObservation(ctx, tx, op, entry.Observation, entry.Observation.Kind != domain.Unknown)
		return err
	}
	var classified *domain.Error
	if !errors.As(err, &classified) || classified.Code != domain.NotFound {
		return err
	}
	return insertRecoveredOperation(ctx, tx, page, entry)
}

// Inventory presence does not reverify or replace a previously proven outcome.
func checkTerminalInventoryPresence(previous, presence domain.DelegateObservation) error {
	if previous.SpecDigest != presence.SpecDigest {
		return domain.Reject(domain.Conflict)
	}
	if presence.Result != nil && (previous.Result == nil || *previous.Result != *presence.Result) {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func insertRecoveredOperation(ctx context.Context, tx *sql.Tx, page domain.ValidatedInventoryPage, entry domain.InventoryEntry) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM operations").Scan(&count); err != nil {
		return err
	}
	if count >= domain.MaxCorrelations {
		return domain.Reject(domain.ResourceLimit)
	}
	owner := domain.PrincipalID("")
	if entry.Correlation.Owner.Kind == domain.Owned {
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM principals WHERE id=?", entry.Correlation.Owner.Principal).Scan(&count); err != nil {
			return err
		}
		if count == 1 {
			owner = entry.Correlation.Owner.Principal
		}
	}
	correlation, err := encode(entry.Correlation)
	if err != nil {
		return err
	}
	observation, err := encode(entry.Observation)
	if err != nil {
		return err
	}
	state := domain.PossibleSend
	reserved := true
	if entry.Observation.Kind == domain.Terminal || entry.Observation.Kind == domain.Refused {
		state = domain.Resolved
		reserved = false
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO operations(id,origin_operation,kind,root_guard,project_guard,task,owner,device,project,correlation,state,created,expires,reserved,observation) VALUES(?,?,'attributed',?,?,?,?,?,?,?,?,?,?,?,?)", entry.Correlation.Operation, entry.Correlation.Operation, entry.Correlation.Context.Root, entry.Correlation.Context.Project, entry.Correlation.Task, nullablePrincipal(owner), entry.Correlation.Destination.Device, entry.Correlation.Destination.Project, correlation, state, page.Now.UTC().Format(timestampLayout), page.Now.UTC().Format(timestampLayout), reserved, observation)
	return err
}

func (s *Store) CompleteInventory(ctx context.Context, input domain.ValidatedCompletenessReceipt) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validateRecoveryDestination(input.Destination); err != nil {
		return err
	}
	if err := domain.Token(string(input.Generation)); err != nil {
		return err
	}
	if err := input.Membership.Validate(); err != nil {
		return err
	}
	if err := input.Receipt.Validate(); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return completeInventory(ctx, tx, input)
	})
	return err
}

// RestartInventory invalidates a failed reopen's completeness proof without
// releasing reservations. Only local admin can explicitly begin another scan.
func (s *Store) RestartInventory(ctx context.Context, destination domain.RecoveryDestination) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validateRecoveryDestination(destination); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if err := activeRecovery(ctx, tx, destination.Recovery, true); err != nil {
			return struct{}{}, err
		}
		if _, err := readInventoryState(ctx, tx, destination); err != nil {
			return struct{}{}, err
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM inventory_pages WHERE recovery=? AND device=? AND root_guard=?", destination.Recovery, destination.Device, destination.Root)
		if err != nil {
			return struct{}{}, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET membership=NULL,cursor='',started=0,finished=0,completeness=NULL,approved=0,reopened=NULL WHERE recovery=? AND device=? AND root_guard=?", destination.Recovery, destination.Device, destination.Root)
		if err != nil {
			return struct{}{}, err
		}
		// Reopen approval covers the complete recovery roster. A changed root
		// invalidates authority for every target, including queued writes.
		_, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET approved=0,reopened=NULL WHERE recovery=?", destination.Recovery)
		if err != nil {
			return struct{}{}, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE recoveries SET revision=revision+1 WHERE id=?", destination.Recovery)
		return struct{}{}, err
	})
	return err
}

func (s *Store) ApproveRecoveryReopen(ctx context.Context, input domain.RecoveryApproval) (domain.ReopenPlan, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.ReopenPlan{}, err
	}
	if input.Now.IsZero() {
		return domain.ReopenPlan{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.ReopenPlan, error) {
		return approveRecoveryReopen(ctx, tx, input)
	})
}

func reopenTargets(ctx context.Context, tx *sql.Tx, recovery domain.RecoveryID) (targets []domain.ReopenTarget, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT d.device,d.root_guard,d.generation,d.completeness,r.revision FROM recovery_destinations d JOIN recoveries r ON r.id=d.recovery WHERE recovery=? ORDER BY device,root_guard", recovery)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		target := domain.ReopenTarget{Destination: domain.RecoveryDestination{Recovery: recovery}}
		var receipt []byte
		if err = rows.Scan(&target.Destination.Device, &target.Destination.Root, &target.Generation, &receipt, &target.Revision); err != nil {
			return nil, err
		}
		if err = validateRecoveryDestination(target.Destination); err != nil {
			return nil, err
		}
		if len(receipt) != len(domain.Digest{}) || target.Generation == "" {
			return nil, domain.Reject(domain.Pending)
		}
		copy(target.Completeness[:], receipt)
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (s *Store) RecordReopen(ctx context.Context, input domain.ValidatedReopenReceipt) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if input.Now.IsZero() {
		return domain.ErrInvalid
	}
	if err := input.Receipt.Validate(); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return recordReopen(ctx, tx, input)
	})
	return err
}

func (s *Store) FinishRecovery(ctx context.Context, input domain.RecoveryFinish) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if domain.RoutingToken(string(input.Recovery)) != nil || input.Now.IsZero() {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return finishRecovery(ctx, tx, input)
	})
	return err
}

func checkRecoveryFinish(ctx context.Context, tx *sql.Tx, input domain.RecoveryFinish) error {
	if err := activeRecovery(ctx, tx, input.Recovery, true); err != nil {
		return err
	}
	var missing int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM recovery_destinations WHERE recovery=? AND (reopened IS NULL OR completeness IS NULL OR approved=0)", input.Recovery).Scan(&missing); err != nil {
		return err
	}
	if missing != 0 {
		return domain.Reject(domain.Pending)
	}
	if err := sessionCoverage(ctx, tx, input.Recovery); err != nil {
		return err
	}
	return requireRecoveryMappings(ctx, tx, input.Recovery, input.Now, true, "")
}

func allowRegularRecoveryEnrollment(ctx context.Context, tx *sql.Tx, device domain.DeviceID, now time.Time) error {
	var sealed bool
	var recovery domain.RecoveryID
	if err := tx.QueryRowContext(ctx, "SELECT r.sealed,s.recovery FROM settings s JOIN recoveries r ON r.id=s.recovery WHERE s.id=1").Scan(&sealed, &recovery); err != nil {
		return err
	}
	if !sealed {
		return domain.Reject(domain.Pending)
	}
	var missing int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM recovery_destinations WHERE recovery=? AND completeness IS NULL", recovery).Scan(&missing); err != nil {
		return err
	}
	if missing != 0 {
		return domain.Reject(domain.Pending)
	}
	if err := requireRoutingRecoveryCoverage(ctx, tx); err != nil {
		return err
	}
	return requireRecoveryMappings(ctx, tx, recovery, now, false, device)
}

func requireRoutingRecoveryCoverage(ctx context.Context, tx *sql.Tx) error {
	err := routingRecoveryCovered(ctx, tx)
	if errors.Is(err, errRoutingPending) {
		return domain.Reject(domain.Pending)
	}
	return err
}

func regularRecoveryCredential(ctx context.Context, tx *sql.Tx, device domain.DeviceID, now time.Time) error {
	cred, err := currentRecoveryCredential(ctx, tx, device, now)
	if err != nil {
		return err
	}
	if cred.Mode != domain.Regular {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

func currentRecoveryCredential(ctx context.Context, tx *sql.Tx, device domain.DeviceID, now time.Time) (domain.Credential, error) {
	var epoch domain.CredentialEpoch
	var generation uint64
	if err := tx.QueryRowContext(ctx, "SELECT epoch FROM settings WHERE id=1").Scan(&epoch); err != nil {
		return domain.Credential{}, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT credential_generation FROM devices WHERE id=?", device).Scan(&generation); err != nil {
		return domain.Credential{}, notFound(err)
	}
	return credential(ctx, tx, domain.CredentialRef{Device: device, Epoch: epoch, Generation: generation}, now)
}

func completeInventory(ctx context.Context, tx *sql.Tx, input domain.ValidatedCompletenessReceipt) (struct{}, error) {
	if err := activeRecovery(ctx, tx, input.Destination.Recovery, true); err != nil {
		return struct{}{}, err
	}
	state, err := readInventoryState(ctx, tx, input.Destination)
	if err != nil {
		return struct{}{}, err
	}
	if state.generation != input.Generation || !state.started || !state.finished || !bytes.Equal(state.membership, input.Membership[:]) {
		return struct{}{}, domain.Reject(domain.Conflict)
	}
	var previous []byte
	if err = tx.QueryRowContext(ctx, "SELECT completeness FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", input.Destination.Recovery, input.Destination.Device, input.Destination.Root).Scan(&previous); err != nil {
		return struct{}{}, err
	}
	if len(previous) > 0 && !bytes.Equal(previous, input.Receipt[:]) {
		return struct{}{}, domain.Reject(domain.Conflict)
	}
	_, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET completeness=? WHERE recovery=? AND device=? AND root_guard=?", input.Receipt[:], input.Destination.Recovery, input.Destination.Device, input.Destination.Root)
	return struct{}{}, err
}

func completeFinalPage(ctx context.Context, tx *sql.Tx, input domain.ValidatedInventoryPage) (struct{}, error) {
	if input.CompletenessReceipt == nil {
		return struct{}{}, nil
	}
	return completeInventory(ctx, tx, domain.ValidatedCompletenessReceipt{Destination: input.Destination, Generation: input.Generation, Membership: input.Membership, Receipt: *input.CompletenessReceipt})
}

func ensureRecoveryIdentityUnused(ctx context.Context, tx *sql.Tx, input domain.RecoveryStart) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM recoveries WHERE id=? OR epoch=?", input.ID, input.Epoch).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return domain.Reject(domain.Conflict)
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM credential_epochs WHERE epoch=?", input.Epoch).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return domain.Reject(domain.Conflict)
	}

	return nil
}

func validateFinalInventoryReceipt(input domain.ValidatedInventoryPage) error {
	if input.CompletenessReceipt == nil {
		return nil
	}
	if input.NextCursor != "" {
		return domain.ErrInvalid
	}
	return input.CompletenessReceipt.Validate()
}

func applyValidatedInventoryPage(ctx context.Context, tx *sql.Tx, input domain.ValidatedInventoryPage, digest domain.Digest) (struct{}, error) {
	if recoveryErr := activeRecovery(ctx, tx, input.Destination.Recovery, true); recoveryErr != nil {
		return struct{}{}, recoveryErr
	}
	state, stateErr := readInventoryState(ctx, tx, input.Destination)
	if stateErr != nil {
		return struct{}{}, stateErr
	}
	if len(state.barrier) != len(domain.Digest{}) {
		return struct{}{}, domain.Reject(domain.Pending)
	}
	if state.generation == "" || state.generation != input.Generation {
		return struct{}{}, domain.Reject(domain.Conflict)
	}
	var prior []byte
	err := tx.QueryRowContext(ctx, "SELECT digest FROM inventory_pages WHERE recovery=? AND device=? AND root_guard=? AND cursor=?", input.Destination.Recovery, input.Destination.Device, input.Destination.Root, input.Cursor).Scan(&prior)
	if err == nil {
		if !bytes.Equal(prior, digest[:]) {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		return completeFinalPage(ctx, tx, input)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return struct{}{}, err
	}
	if _, applyErr := applyInventoryPage(ctx, tx, input, state, digest); applyErr != nil {
		return struct{}{}, applyErr
	}
	return completeFinalPage(ctx, tx, input)
}

func approveRecoveryReopen(ctx context.Context, tx *sql.Tx, input domain.RecoveryApproval) (domain.ReopenPlan, error) {
	if err := activeRecovery(ctx, tx, input.Recovery, true); err != nil {
		return domain.ReopenPlan{}, err
	}
	if err := sessionCoverage(ctx, tx, input.Recovery); err != nil {
		return domain.ReopenPlan{}, err
	}
	if input.Now.IsZero() {
		return domain.ReopenPlan{}, domain.ErrInvalid
	}
	if err := advanceReopenRevision(ctx, tx, input.Recovery); err != nil {
		return domain.ReopenPlan{}, err
	}
	targets, err := reopenTargets(ctx, tx, input.Recovery)
	if err != nil {
		return domain.ReopenPlan{}, err
	}
	for _, target := range targets {
		if err = regularRecoveryCredential(ctx, tx, target.Destination.Device, input.Now); err != nil {
			return domain.ReopenPlan{}, err
		}
	}
	if err = requireRecoveryMappings(ctx, tx, input.Recovery, input.Now, true, ""); err != nil {
		return domain.ReopenPlan{}, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET approved=1 WHERE recovery=?", input.Recovery)
	return domain.ReopenPlan{Recovery: input.Recovery, Targets: targets}, err
}

func advanceReopenRevision(ctx context.Context, tx *sql.Tx, recovery domain.RecoveryID) error {
	var unapproved int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM recovery_destinations WHERE recovery=? AND approved=0", recovery).Scan(&unapproved); err != nil {
		return err
	}
	if unapproved > 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE recoveries SET revision=revision+1 WHERE id=?", recovery); err != nil {
			return err
		}
	}

	return nil
}

func recordBarrier(ctx context.Context, tx *sql.Tx, input domain.ValidatedBarrierReceipt) (struct{}, error) {
	if err := activeRecovery(ctx, tx, input.Destination.Recovery, true); err != nil {
		return struct{}{}, err
	}
	var previous domain.AdmissionGeneration
	var barrier []byte
	err := tx.QueryRowContext(ctx, "SELECT generation,barrier FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", input.Destination.Recovery, input.Destination.Device, input.Destination.Root).Scan(&previous, &barrier)
	if err != nil {
		return struct{}{}, notFound(err)
	}
	if previous == "" || previous != input.Generation {
		return struct{}{}, domain.Reject(domain.Conflict)
	}
	if len(barrier) > 0 {
		if !bytes.Equal(barrier, input.Receipt[:]) {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		return struct{}{}, nil
	}
	_, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET barrier=? WHERE recovery=? AND device=? AND root_guard=?", input.Receipt[:], input.Destination.Recovery, input.Destination.Device, input.Destination.Root)
	return struct{}{}, err
}

func recordReopen(ctx context.Context, tx *sql.Tx, input domain.ValidatedReopenReceipt) (struct{}, error) {
	if err := checkReopenTarget(ctx, tx, input.Target, input.Now); err != nil {
		return struct{}{}, err
	}
	d := input.Target.Destination
	var prior []byte
	if err := tx.QueryRowContext(ctx, "SELECT reopened FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", d.Recovery, d.Device, d.Root).Scan(&prior); err != nil {
		return struct{}{}, notFound(err)
	}
	if len(prior) > 0 && !bytes.Equal(prior, input.Receipt[:]) {
		return struct{}{}, domain.Reject(domain.Conflict)
	}
	_, err := tx.ExecContext(ctx, "UPDATE recovery_destinations SET reopened=? WHERE recovery=? AND device=? AND root_guard=?", input.Receipt[:], d.Recovery, d.Device, d.Root)
	return struct{}{}, err
}

func finishRecovery(ctx context.Context, tx *sql.Tx, input domain.RecoveryFinish) (struct{}, error) {
	id := input.Recovery
	if err := checkRecoveryFinish(ctx, tx, input); err != nil {
		return struct{}{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE root_admissions SET generation=(SELECT generation FROM recovery_destinations d WHERE d.recovery=? AND d.device=root_admissions.device AND d.root_guard=root_admissions.root_guard),state='open' WHERE session=?`, id, id); err != nil {
		return struct{}{}, err
	}
	state, err := readRecovery(ctx, tx, id)
	if err != nil {
		return struct{}{}, err
	}
	if state.kind == domain.RestoreRecovery {
		if _, err = tx.ExecContext(ctx, "UPDATE settings SET blocked=0 WHERE id=1"); err != nil {
			return struct{}{}, err
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE recoveries SET status='finished' WHERE id=?", id)
	return struct{}{}, err
}
