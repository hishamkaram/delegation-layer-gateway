package registry

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func storedExecutionOptions(op storedOperation) (domain.ExecutionOptions, error) {
	if len(op.options) == 0 && len(op.optionsDigest) == 0 {
		return domain.ExecutionOptions{}, domain.Reject(domain.Pending)
	}
	digest := domain.Hash(op.options)
	if !bytes.Equal(digest[:], op.optionsDigest) {
		return domain.ExecutionOptions{}, domain.Reject(domain.EvidenceInvalid)
	}
	options, err := decode[domain.ExecutionOptions](op.options)
	if err != nil {
		return options, err
	}
	if err = options.Validate(); err != nil {
		return options, err
	}
	return options, nil
}

func validateOptionsAgainstRequest(op storedOperation, request domain.FrozenRequest) error {
	options, err := storedExecutionOptions(op)
	if err != nil {
		return err
	}
	if options != request.Options() {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func knownSpecDigest(op storedOperation) domain.Digest {
	if op.view.Observation == nil {
		return domain.Digest{}
	}
	return op.view.Observation.SpecDigest
}

func admissionsOpen(ctx context.Context, tx *sql.Tx) error {
	var blocked bool
	if err := tx.QueryRowContext(ctx, "SELECT blocked FROM settings WHERE id=1").Scan(&blocked); err != nil {
		return err
	}
	if blocked {
		return domain.Reject(domain.Pending)
	}
	return nil
}

// GetForRecovery exposes only immutable correlation/spec identity. A known
// canonical existing request and retained validated options are mandatory;
// neither task-read privileges nor a brief can substitute for dispatch rights.
func (s *Store) GetForRecovery(ctx context.Context, actor domain.Actor, id domain.OperationID) (domain.RecoveryView, error) {
	if err := actor.Validate(); err != nil {
		return domain.RecoveryView{}, err
	}
	if err := domain.RoutingToken(string(id)); err != nil {
		return domain.RecoveryView{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.RecoveryView, error) {
		op, err := readOperation(ctx, tx, id)
		if err != nil {
			return domain.RecoveryView{}, err
		}
		auth, err := authorizeOperation(ctx, tx, actor, op, domain.TaskDispatch)
		if err != nil {
			return domain.RecoveryView{}, err
		}
		if _, err = checkOpenContext(ctx, tx, op.view.Correlation); err != nil {
			return domain.RecoveryView{}, err
		}
		if op.view.Delivery != domain.PossibleSend || op.view.Cancellation != "" {
			return domain.RecoveryView{}, domain.Reject(domain.Conflict)
		}
		spec := knownSpecDigest(op)
		if spec == (domain.Digest{}) {
			return domain.RecoveryView{}, domain.Reject(domain.Pending)
		}
		options, err := storedExecutionOptions(op)
		if err != nil {
			return domain.RecoveryView{}, err
		}
		if !auth.Grant.Ceiling.AllowsOptions(options) {
			return domain.RecoveryView{}, domain.Reject(domain.Forbidden)
		}
		return domain.RecoveryView{Correlation: op.view.Correlation, SpecDigest: spec}, nil
	})
}

func validateTransmission(input domain.Transmission) error {
	if err := domain.RoutingToken(string(input.Operation)); err != nil {
		return err
	}
	if err := input.Credential.Validate(); err != nil {
		return err
	}
	if err := input.Connection.Validate(); err != nil {
		return err
	}
	if input.Now.IsZero() || input.EncodedFrameBytes < 1 || input.EncodedFrameBytes > domain.MaxFrameBytes {
		return domain.ErrInvalid
	}
	return nil
}

// CheckQueuedAdmission is the final Gateway authorization point before the
// transport write. It does not assert globally instantaneous revocation and
// never releases possibly-sent capacity when a queued frame is rejected.
func (s *Store) CheckQueuedAdmission(ctx context.Context, actor domain.Actor, input domain.Transmission) error {
	if err := actor.Validate(); err != nil {
		return err
	}
	if err := validateTransmission(input); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		op, err := readOperation(ctx, tx, input.Operation)
		if err != nil {
			return struct{}{}, err
		}
		auth, err := authorizeOperation(ctx, tx, actor, op, domain.TaskDispatch)
		if err != nil {
			return struct{}{}, err
		}
		return struct{}{}, checkQueuedAdmission(ctx, tx, input, op, auth)
	})
	return err
}

func checkQueuedAdmission(ctx context.Context, tx *sql.Tx, input domain.Transmission, op storedOperation, auth domain.Authorization) error {
	if op.view.Delivery != domain.PossibleSend || !op.view.Reserved || op.view.Cancellation != "" {
		return domain.Reject(domain.Conflict)
	}
	if err := validateAdmissionDestination(ctx, tx, input, op.view.Correlation); err != nil {
		return err
	}
	options, err := storedExecutionOptions(op)
	if err != nil {
		return err
	}
	if !auth.Grant.Ceiling.AllowsOptions(options) {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

func validateAdmissionDestination(ctx context.Context, tx *sql.Tx, input domain.Transmission, c domain.Correlation) error {
	if input.Credential.Device != c.Destination.Device {
		return domain.Reject(domain.Conflict)
	}
	if err := checkActiveBinding(ctx, tx, c); err != nil {
		return err
	}
	credential, err := checkConnection(ctx, tx, input.Credential, input.Connection, input.Now)
	if err != nil {
		return err
	}
	if credential.Mode != domain.Regular {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}
