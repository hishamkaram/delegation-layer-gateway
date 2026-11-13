package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func nullablePrincipal(principal domain.PrincipalID) *domain.PrincipalID {
	if principal == "" {
		return nil
	}
	return &principal
}

type administrativeRow struct {
	rowID int64
	view  domain.AdministrativeTaskView
}

func readAdministrativeTask(ctx context.Context, tx *sql.Tx, key domain.NativeTaskKey) (administrativeRow, error) {
	var row administrativeRow
	row.view.Key = key
	var correlation, receipt, observation []byte
	var operation domain.OperationID
	var project domain.ProjectGuard
	var kind string
	err := tx.QueryRowContext(ctx, "SELECT row_id,origin_operation,kind,project_guard,correlation,native_receipt,state,reserved,cancellation,observation FROM operations WHERE device=? AND root_guard=? AND task=?", key.Device, key.Root, key.Task).Scan(&row.rowID, &operation, &kind, &project, &correlation, &receipt, &row.view.Delivery, &row.view.Reserved, &row.view.Cancellation, &observation)
	if err != nil {
		return row, notFound(err)
	}
	if err = decodeAdministrativeCorrelation(&row, correlation, operation, kind); err != nil {
		return row, err
	}
	if err = decodeAdministrativeReceipt(&row, receipt, operation); err != nil {
		return row, err
	}
	if err = decodeAdministrativeObservation(&row, observation); err != nil {
		return row, err
	}
	if row.view.Delivery.Validate() != nil || row.view.Binding.Validate() != nil || row.view.Binding.Context.Project != project || row.view.Correlation == nil && (kind != "unattributed" || row.view.Receipt == nil) {
		return row, domain.Reject(domain.EvidenceInvalid)
	}
	return row, nil
}

func decodeAdministrativeCorrelation(row *administrativeRow, data []byte, operation domain.OperationID, kind string) error {
	if len(data) == 0 {
		return nil
	}
	c, err := decode[domain.Correlation](data)
	if err != nil {
		return err
	}
	key := row.view.Key
	if c.Validate() != nil || c.Destination.Device != key.Device || c.Context.Root != key.Root || c.Task != key.Task || c.Operation != operation || kind != "attributed" {
		return domain.Reject(domain.EvidenceInvalid)
	}
	row.view.Correlation = &c
	row.view.Binding = domain.AdministrativeTaskBinding{Task: c.Task, Context: c.Context, Origin: domain.OriginFromCorrelation(c)}
	return nil
}

func decodeAdministrativeReceipt(row *administrativeRow, data []byte, operation domain.OperationID) error {
	if len(data) == 0 {
		return nil
	}
	r, err := decode[domain.NativeTaskReceipt](data)
	if err != nil {
		return err
	}
	key := row.view.Key
	if r.Validate() != nil || r.Binding.Task != key.Task || r.Binding.Context.Root != key.Root || r.Binding.Origin.Operation != operation {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if row.view.Correlation != nil && (r.Binding.Origin != row.view.Binding.Origin || r.Binding.Context != row.view.Binding.Context || r.BriefDigest != row.view.Correlation.BriefDigest) {
		return domain.Reject(domain.EvidenceInvalid)
	}
	row.view.Receipt = &r
	row.view.Binding = domain.AdministrativeTaskBinding{Task: r.Binding.Task, Context: r.Binding.Context, Origin: r.Binding.Origin, SpecDigest: r.Binding.SpecDigest}
	return nil
}

func decodeAdministrativeObservation(row *administrativeRow, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	o, err := decode[domain.DelegateObservation](data)
	if err != nil {
		return err
	}
	if o.Validate(o.ObservedAt) != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if row.view.Binding.SpecDigest != (domain.Digest{}) && o.SpecDigest != (domain.Digest{}) && row.view.Binding.SpecDigest != o.SpecDigest {
		return domain.Reject(domain.EvidenceInvalid)
	}
	row.view.Observation = &o
	if o.SpecDigest != (domain.Digest{}) {
		row.view.Binding.SpecDigest = o.SpecDigest
	}
	return nil
}

func checkPhysicalOrigin(ctx context.Context, tx *sql.Tx, key domain.NativeTaskKey, operation domain.OperationID) error {
	var device domain.DeviceID
	var root domain.RootGuard
	var task domain.TaskID
	err := tx.QueryRowContext(ctx, "SELECT device,root_guard,task FROM operations WHERE origin_operation=?", operation).Scan(&device, &root, &task)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if device != key.Device || root != key.Root || task != key.Task {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}
