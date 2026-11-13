package registry

import (
	"context"
	"database/sql"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func ownedRootTransaction[T any](ctx context.Context, p *OwnedRootPort, fn func(*sql.Tx) (T, error)) (T, error) {
	return transaction(ctx, p.store, func(tx *sql.Tx) (T, error) {
		if _, err := p.check(ctx, tx); err != nil {
			var zero T
			return zero, err
		}
		return fn(tx)
	})
}

func (p *OwnedRootPort) matches(input domain.RootInitializationLookup) bool {
	return input.Validate() == nil && input.RootRoute != nil && *input.RootRoute == p.binding.Route
}

func (p *OwnedRootPort) ReadRootInitializationProgress(ctx context.Context, input domain.RootInitializationLookup) (domain.RootInitializationProgress, error) {
	if !p.matches(input) {
		return domain.RootInitializationProgress{}, domain.Reject(domain.Forbidden)
	}
	return ownedRootTransaction(ctx, p, func(tx *sql.Tx) (domain.RootInitializationProgress, error) {
		return readRootProgress(ctx, tx, p.lookup())
	})
}

func (p *OwnedRootPort) BeginRootInitialization(ctx context.Context, input domain.RootInitializationStart) (domain.RootInitializationProgress, error) {
	if !p.matches(input.Lookup()) || input.Credential != p.binding.Credential || input.Connection != p.binding.Connection {
		return domain.RootInitializationProgress{}, domain.Reject(domain.Forbidden)
	}
	input.Now = p.now()
	return ownedRootTransaction(ctx, p, func(tx *sql.Tx) (domain.RootInitializationProgress, error) {
		return beginRootInitialization(ctx, tx, input, p.lookup())
	})
}

func (p *OwnedRootPort) PrepareRecoveryBarrier(ctx context.Context, input domain.BarrierPreparation) (domain.BarrierPlan, error) {
	if !p.destination(input.Destination) || input.Credential != p.binding.Credential || input.Connection != p.binding.Connection {
		return domain.BarrierPlan{}, domain.Reject(domain.Forbidden)
	}
	input.Now = p.now()
	if err := validateBarrierPreparation(input); err != nil {
		return domain.BarrierPlan{}, err
	}
	return ownedRootTransaction(ctx, p, func(tx *sql.Tx) (domain.BarrierPlan, error) {
		if err := p.checkRecovery(ctx, tx, input.Destination.Recovery); err != nil {
			return domain.BarrierPlan{}, err
		}
		return prepareBarrier(ctx, tx, input)
	})
}

func (p *OwnedRootPort) RecordBarrier(ctx context.Context, input domain.ValidatedBarrierReceipt) error {
	if !p.destination(input.Destination) {
		return domain.Reject(domain.Forbidden)
	}
	if validateRecoveryDestination(input.Destination) != nil || domain.Token(string(input.Generation)) != nil || input.Receipt.Validate() != nil {
		return domain.ErrInvalid
	}
	_, err := ownedRootTransaction(ctx, p, func(tx *sql.Tx) (struct{}, error) {
		if checkErr := p.checkRecovery(ctx, tx, input.Destination.Recovery); checkErr != nil {
			return struct{}{}, checkErr
		}
		return recordBarrier(ctx, tx, input)
	})
	return err
}

func (p *OwnedRootPort) ApplyInventoryPage(ctx context.Context, input domain.ValidatedInventoryPage) error {
	if !p.destination(input.Destination) {
		return domain.Reject(domain.Forbidden)
	}
	// Automatic initialization never imports or attributes historical tasks.
	if len(input.Entries) != 0 || input.CompletenessReceipt == nil {
		return domain.Reject(domain.Conflict)
	}
	input.Now = p.now()
	if err := validateInventoryPage(input); err != nil {
		return err
	}
	encoded, err := encode(inventoryIdentity(input))
	if err != nil {
		return err
	}
	digest := domain.Hash(encoded)
	_, err = ownedRootTransaction(ctx, p, func(tx *sql.Tx) (struct{}, error) {
		if checkErr := p.checkRecovery(ctx, tx, input.Destination.Recovery); checkErr != nil {
			return struct{}{}, checkErr
		}
		return applyValidatedInventoryPage(ctx, tx, input, digest)
	})
	return err
}

func (p *OwnedRootPort) ApproveRecoveryReopen(ctx context.Context, input domain.RecoveryApproval) (domain.ReopenPlan, error) {
	input.Now = p.now()
	return ownedRootTransaction(ctx, p, func(tx *sql.Tx) (domain.ReopenPlan, error) {
		if err := p.checkRecovery(ctx, tx, input.Recovery); err != nil {
			return domain.ReopenPlan{}, err
		}
		return approveRecoveryReopen(ctx, tx, input)
	})
}

func (p *OwnedRootPort) CheckReopen(ctx context.Context, input domain.ReopenCheck) error {
	if !p.destination(input.Target.Destination) || input.Credential != p.binding.Credential || input.Connection != p.binding.Connection {
		return domain.Reject(domain.Forbidden)
	}
	_, err := ownedRootTransaction(ctx, p, func(tx *sql.Tx) (struct{}, error) {
		if err := p.checkRecovery(ctx, tx, input.Target.Destination.Recovery); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, checkReopenTarget(ctx, tx, input.Target, p.now())
	})
	return err
}

func (p *OwnedRootPort) RecordReopen(ctx context.Context, input domain.ValidatedReopenReceipt) error {
	if !p.destination(input.Target.Destination) {
		return domain.Reject(domain.Forbidden)
	}
	if input.Receipt.Validate() != nil {
		return domain.ErrInvalid
	}
	input.Now = p.now()
	_, err := ownedRootTransaction(ctx, p, func(tx *sql.Tx) (struct{}, error) {
		if err := p.checkRecovery(ctx, tx, input.Target.Destination.Recovery); err != nil {
			return struct{}{}, err
		}
		return recordReopen(ctx, tx, input)
	})
	return err
}

func (p *OwnedRootPort) FinishRecovery(ctx context.Context, input domain.RecoveryFinish) error {
	input.Now = p.now()
	_, err := ownedRootTransaction(ctx, p, func(tx *sql.Tx) (struct{}, error) {
		if err := p.checkRecovery(ctx, tx, input.Recovery); err != nil {
			return struct{}{}, err
		}
		return finishRecovery(ctx, tx, input)
	})
	return err
}
