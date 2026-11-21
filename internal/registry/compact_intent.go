package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// readOperationEvidence completes the one row decoder without introducing a
// second authority for requested options. Legacy observation decoding is shared.
func readOperationEvidence(op storedOperation, observation []byte) (storedOperation, error) {
	var err error
	op.view.Observation, err = decodeOperationObservation(observation)
	if err != nil {
		return op, err
	}
	return op, validateCompactOperation(op)
}

func validateCompactOperation(op storedOperation) error {
	if op.view.Correlation.RequestVersion != domain.CompactRequestVersion {
		return nil
	}
	if op.options != nil || op.optionsDigest != nil || op.view.EffectiveOwner != op.view.Correlation.Owner {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if len(op.request) == 0 {
		if op.request != nil || op.view.Delivery == domain.Prepared {
			return domain.Reject(domain.EvidenceInvalid)
		}
		return nil
	}
	request, err := decode[domain.FrozenRequest](op.request)
	if err != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return validateFrozenRequest(op.view.Correlation, request)
}

// Compact tasks retain their root/task route and never require a legacy alias.
// Validate each exemption from stored evidence, streaming one row at a time.
// The caller still enforces the root roster, current credential and reopen proof.
func validateCompactRecoveryMappings(ctx context.Context, tx *sql.Tx, destination domain.RecoveryDestination) (err error) {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM operations WHERE device=? AND root_guard=? AND reserved=1 AND json_extract(correlation,'$.RequestVersion')=4 ORDER BY row_id", destination.Device, destination.Root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var id domain.OperationID
		if err = rows.Scan(&id); err != nil {
			return err
		}
		op, readErr := readOperation(ctx, tx, id)
		if readErr != nil {
			return readErr
		}
		if op.view.Correlation.RequestVersion != domain.CompactRequestVersion {
			return domain.Reject(domain.EvidenceInvalid)
		}
		if err = checkBoundImportOwner(ctx, tx, op.view.Correlation); err != nil {
			return err
		}
		if err = checkCompactRecoveryReceipt(ctx, tx, op, knownSpecDigest(op)); err != nil {
			return err
		}
	}
	return rows.Err()
}

func validateStoredIntent(op storedOperation) error {
	if op.view.Correlation.RequestVersion == domain.CompactRequestVersion {
		return validateCompactOperation(op)
	}
	_, err := storedExecutionOptions(op)
	return err
}

func correlationOrigin(c domain.Correlation) (domain.TaskOrigin, error) {
	if c.RequestVersion == domain.CompactRequestVersion {
		return domain.CompactOrigin(c)
	}
	origin := domain.OriginFromCorrelation(c)
	if err := origin.Validate(); err != nil {
		return domain.TaskOrigin{}, err
	}
	return origin, nil
}

// A known spec may originate in a validated Native task observation. When a
// canonical receipt is also retained, it must corroborate that same identity/spec.
func checkCompactRecoveryReceipt(ctx context.Context, tx *sql.Tx, op storedOperation, spec domain.Digest) error {
	if op.view.Correlation.RequestVersion != domain.CompactRequestVersion {
		return nil
	}
	var data []byte
	if err := tx.QueryRowContext(ctx, "SELECT native_receipt FROM operations WHERE id=?", op.view.Correlation.Operation).Scan(&data); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	receipt, err := decode[domain.NativeTaskReceipt](data)
	if err != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	c := op.view.Correlation
	key := domain.NativeTaskKey{Device: c.Destination.Device, Root: c.Context.Root, Task: c.Task}
	recovered, err := domain.VerifyBoundNativeReceipt(c.Gateway, key, receipt)
	if err != nil || recovered != c || receipt.Binding.SpecDigest != spec {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func validateAdministrativeCompactOperation(ctx context.Context, tx *sql.Tx, row administrativeRow) error {
	if row.view.Correlation == nil || row.view.Correlation.RequestVersion != domain.CompactRequestVersion {
		return nil
	}
	_, err := readOperation(ctx, tx, row.view.Correlation.Operation)
	return err
}

func continuationPredecessor(ctx context.Context, tx *sql.Tx, actor domain.Actor, c domain.Correlation) (domain.RecoveryView, error) {
	parent, err := getContinuationIdentity(ctx, tx, actor, c.Predecessor.Operation)
	if err != nil {
		return domain.RecoveryView{}, err
	}
	p := parent.Correlation
	if c.Predecessor != (domain.ContinuationPredecessor{Operation: p.Operation, Task: p.Task, SpecDigest: parent.SpecDigest, RequestDigest: p.RequestDigest}) || c.Destination.Device != p.Destination.Device || c.Context != p.Context || c.Route.WorkspaceGuard != p.Route.WorkspaceGuard {
		return domain.RecoveryView{}, domain.Reject(domain.EvidenceInvalid)
	}
	return parent, nil
}

// A compact operation carries its immutable route. Protected historical drain
// needs the current authenticated connection, not a reusable legacy alias or
// an open admission namespace. readAdministrativeTask has validated its binding.
func checkCompactAdministrativeDrain(ctx context.Context, tx *sql.Tx, input domain.AdministrativeDrainCheck, view domain.AdministrativeTaskView) error {
	c := *view.Correlation
	if input.Destination != c.Destination {
		return domain.Reject(domain.Conflict)
	}
	if err := checkBoundImportOwner(ctx, tx, c); err != nil {
		return err
	}
	if input.Action == domain.AdministrativeResolve || input.Action == domain.AdministrativeFence {
		return nil
	}
	if view.Binding.SpecDigest == (domain.Digest{}) || input.Action == domain.AdministrativeCancel && view.Cancellation == "" {
		return domain.Reject(domain.Conflict)
	}
	return nil
}
