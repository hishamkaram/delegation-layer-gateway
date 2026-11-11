package registry

import (
	"context"
	"database/sql"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func validateKnownReceipt(ctx context.Context, tx *sql.Tx, row administrativeRow, r domain.NativeTaskReceipt) error {
	if !nativeBindingMatches(row.view.Binding, r.Binding) {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if row.view.Receipt != nil && *row.view.Receipt != r {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if row.view.Correlation == nil {
		return nil
	}
	c := *row.view.Correlation
	_, options, matched, err := domain.AttributeNativeReceipt(c.Gateway, c.Destination.Device, domain.ProjectRegistration{Destination: c.Destination, Context: c.Context}, r)
	if err != nil {
		return err
	}
	if !matched || c.BriefDigest != r.BriefDigest {
		return domain.Reject(domain.EvidenceInvalid)
	}
	op, err := readOperation(ctx, tx, c.Operation)
	if err != nil {
		return err
	}
	if len(op.options) == 0 && len(op.optionsDigest) == 0 {
		return nil
	}
	saved, err := storedExecutionOptions(op)
	if err != nil {
		return err
	}
	if saved != options {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func nativeBindingMatches(saved domain.AdministrativeTaskBinding, actual domain.NativeTaskBinding) bool {
	return saved.Task == actual.Task && saved.Context == actual.Context && saved.Origin == actual.Origin && (saved.SpecDigest == (domain.Digest{}) || saved.SpecDigest == actual.SpecDigest)
}

func hydrateKnownReceipt(ctx context.Context, tx *sql.Tx, row administrativeRow, e domain.CanonicalInventoryExisting) error {
	if _, err := mergeAdministrativeObservation(ctx, tx, row, e.Observation); err != nil {
		return err
	}
	receipt, err := encode(e.Receipt)
	if err != nil {
		return err
	}
	if row.view.Correlation == nil {
		_, err = tx.ExecContext(ctx, "UPDATE operations SET native_receipt=? WHERE row_id=?", receipt, row.rowID)
		return err
	}
	options, matched := e.Receipt.Options.ExecutionOptions()
	if !matched {
		return domain.Reject(domain.EvidenceInvalid)
	}
	data, err := encode(options)
	if err != nil {
		return err
	}
	digest := domain.Hash(data)
	_, err = tx.ExecContext(ctx, "UPDATE operations SET native_receipt=?,execution_options=?,options_sha256=? WHERE row_id=?", receipt, data, digest[:], row.rowID)
	return err
}

func mergeAdministrativeObservation(ctx context.Context, tx *sql.Tx, row administrativeRow, next domain.DelegateObservation) (domain.AdministrativeTaskView, error) {
	view := row.view
	if view.Observation != nil && view.Observation.Kind == domain.Terminal && next.Kind == domain.Existing {
		return view, checkTerminalInventoryPresence(*view.Observation, next)
	}
	next = preserveImmutableObservation(view.Observation, next)
	if err := checkObservationContinuity(view.Observation, next); err != nil {
		return view, err
	}
	if next.Kind == domain.Terminal || next.Kind == domain.Refused {
		view.Reserved = false
		view.Delivery = domain.Resolved
	} else if view.Delivery == domain.Prepared || view.Delivery == domain.ExpiredUnsent {
		view.Reserved = true
		view.Delivery = domain.PossibleSend
	}
	data, err := encode(next)
	if err != nil {
		return view, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE operations SET state=?,reserved=?,observation=?,request=NULL WHERE row_id=?", view.Delivery, view.Reserved, data, row.rowID)
	view.Observation = &next
	view.Binding.SpecDigest = next.SpecDigest
	return view, err
}

func insertCanonicalTask(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, e domain.CanonicalInventoryExisting, slot importSlot) error {
	receipt, err := encode(e.Receipt)
	if err != nil {
		return err
	}
	observation, err := encode(e.Observation)
	if err != nil {
		return err
	}
	key := e.Receipt.Binding
	if slot.correlation == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO operations(origin_operation,kind,task,device,root_guard,project_guard,native_receipt,state,created,expires,reserved,observation) VALUES(?,'unattributed',?,?,?,?,?,?,?,?,1,?)", key.Origin.Operation, key.Task, p.Destination.Device, key.Context.Root, key.Context.Project, receipt, domain.PossibleSend, p.Now.UTC().Format(timestampLayout), p.Now.UTC().Format(timestampLayout), observation)
		return err
	}
	return insertAttributedCanonicalTask(ctx, tx, p, e, slot, receipt, observation)
}

func insertAttributedCanonicalTask(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, e domain.CanonicalInventoryExisting, slot importSlot, receipt, observation []byte) error {
	c := *slot.correlation
	correlation, err := encode(c)
	if err != nil {
		return err
	}
	options, err := encode(slot.options)
	if err != nil {
		return err
	}
	digest := domain.Hash(options)
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM principals WHERE id=?", c.Owner.Principal).Scan(&count); err != nil {
		return err
	}
	var owner *domain.PrincipalID
	if count == 1 {
		owner = &c.Owner.Principal
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO operations(id,origin_operation,kind,task,owner,device,root_guard,project_guard,project,correlation,native_receipt,execution_options,options_sha256,state,created,expires,reserved,observation) VALUES(?,?,'attributed',?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)", c.Operation, c.Operation, c.Task, owner, p.Destination.Device, c.Context.Root, c.Context.Project, c.Destination.Project, correlation, receipt, options, digest[:], domain.PossibleSend, p.Now.UTC().Format(timestampLayout), p.Now.UTC().Format(timestampLayout), observation)
	return err
}

func applyNamespaceRefusal(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, r domain.NamespaceRefusal) error {
	key := domain.NativeTaskKey{Device: p.Destination.Device, Root: p.Destination.Root, Task: r.Task}
	if r.Origin != nil {
		if err := checkPhysicalOrigin(ctx, tx, key, r.Origin.Operation); err != nil {
			return err
		}
	}
	row, err := readAdministrativeTask(ctx, tx, key)
	if hasCode(err, domain.NotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.Origin == nil {
		return nil
	}
	if row.view.Binding.Origin != *r.Origin {
		return domain.Reject(domain.EvidenceInvalid)
	}
	_, err = mergeAdministrativeObservation(ctx, tx, row, domain.DelegateObservation{Kind: domain.Refused, ObservedAt: p.Now, SpecDigest: row.view.Binding.SpecDigest})
	return err
}
