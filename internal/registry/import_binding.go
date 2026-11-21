package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// prepareBoundImportSlot handles a present binding before legacy alias matching.
// Current scopes do not decide immutable historical attribution. The exact
// device-owner link and all writes share the canonical page transaction.
func prepareBoundImportSlot(ctx context.Context, tx *sql.Tx, page domain.ImportedInventoryPage, entry domain.ImportedInventoryEntry, gateway domain.GatewayID) (importSlot, bool, error) {
	var origin *domain.TaskOrigin
	var task domain.TaskID
	if entry.Existing != nil {
		origin, task = &entry.Existing.Receipt.Binding.Origin, entry.Existing.Receipt.Binding.Task
	} else if entry.Refusal != nil {
		origin, task = entry.Refusal.Origin, entry.Refusal.Task
	}
	if origin == nil || origin.Binding == "" {
		return importSlot{}, false, nil
	}
	key := domain.NativeTaskKey{Device: page.Destination.Device, Root: page.Destination.Root, Task: task}
	c, err := verifyBoundImport(gateway, key, entry, *origin)
	if err != nil {
		return importSlot{}, true, err
	}
	if err = checkBoundImportOwner(ctx, tx, c); err != nil {
		return importSlot{}, true, err
	}
	if err = checkPhysicalOrigin(ctx, tx, key, c.Operation); err != nil {
		return importSlot{}, true, err
	}
	slot := importSlot{correlation: &c}
	known, err := readAdministrativeTask(ctx, tx, key)
	if hasCode(err, domain.NotFound) {
		return slot, true, nil
	}
	if err != nil {
		return importSlot{}, true, err
	}
	if known.view.Correlation == nil || *known.view.Correlation != c || known.view.Binding.Origin != *origin {
		return importSlot{}, true, domain.Reject(domain.EvidenceInvalid)
	}
	if entry.Existing != nil {
		if err = validateKnownReceipt(ctx, tx, known, entry.Existing.Receipt); err != nil {
			return importSlot{}, true, err
		}
	}
	slot.known = &known
	return slot, true, nil
}

func verifyBoundImport(gateway domain.GatewayID, key domain.NativeTaskKey, entry domain.ImportedInventoryEntry, origin domain.TaskOrigin) (domain.Correlation, error) {
	if entry.Existing != nil {
		return domain.VerifyBoundNativeReceipt(gateway, key, entry.Existing.Receipt)
	}
	return domain.VerifyOriginBinding(gateway, key, origin)
}

func validateKnownBoundReceipt(ctx context.Context, tx *sql.Tx, c domain.Correlation, receipt domain.NativeTaskReceipt) error {
	key := domain.NativeTaskKey{Device: c.Destination.Device, Root: c.Context.Root, Task: c.Task}
	actual, err := domain.VerifyBoundNativeReceipt(c.Gateway, key, receipt)
	if err != nil || actual != c {
		return domain.Reject(domain.EvidenceInvalid)
	}
	_, err = readOperation(ctx, tx, c.Operation)
	return err
}

func checkBoundImportOwner(ctx context.Context, tx *sql.Tx, c domain.Correlation) error {
	var owner domain.PrincipalID
	err := tx.QueryRowContext(ctx, "SELECT principal FROM device_owners WHERE device=?", c.Destination.Device).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if err != nil {
		return err
	}
	if owner != c.Owner.Principal {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func checkBoundPreparationKey(ctx context.Context, tx *sql.Tx, c domain.Correlation) error {
	var operation domain.OperationID
	err := tx.QueryRowContext(ctx, "SELECT id FROM operations WHERE owner=? AND device=? AND preparation_key=?", c.Owner.Principal, c.Destination.Device, c.Route.RequestID).Scan(&operation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if operation != c.Operation {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func insertBoundOperation(ctx context.Context, tx *sql.Tx, page domain.ImportedInventoryPage, c domain.Correlation, receipt, observation []byte, state domain.DeliveryState, reserved bool) error {
	if err := checkBoundPreparationKey(ctx, tx, c); err != nil {
		return err
	}
	correlation, err := encode(c)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO operations(id,origin_operation,kind,task,owner,device,root_guard,project_guard,project,correlation,preparation_key,native_receipt,state,created,expires,reserved,observation) VALUES(?,?,'attributed',?,?,?,?,?,?,?,?,?,?,?,?,?,?)", c.Operation, c.Operation, c.Task, c.Owner.Principal, c.Destination.Device, c.Context.Root, c.Context.Project, c.Destination.Project, correlation, preparationKey(c), receipt, state, page.Now.UTC().Format(timestampLayout), page.Now.UTC().Format(timestampLayout), reserved, observation)
	return err
}

func applyBoundRefusal(ctx context.Context, tx *sql.Tx, page domain.ImportedInventoryPage, slot importSlot) error {
	observation := domain.DelegateObservation{Kind: domain.Refused, ObservedAt: page.Now}
	if slot.known != nil {
		observation.SpecDigest = slot.known.view.Binding.SpecDigest
		_, err := mergeAdministrativeObservation(ctx, tx, *slot.known, observation)
		return err
	}
	data, err := encode(observation)
	if err != nil {
		return err
	}
	return insertBoundOperation(ctx, tx, page, *slot.correlation, nil, data, domain.Resolved, false)
}
