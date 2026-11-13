package registry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func (s *Store) GetAdministrativeTask(ctx context.Context, key domain.NativeTaskKey) (domain.AdministrativeTaskView, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.AdministrativeTaskView{}, err
	}
	if err := key.Validate(); err != nil {
		return domain.AdministrativeTaskView{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.AdministrativeTaskView, error) {
		row, err := readAdministrativeTask(ctx, tx, key)
		return row.view, err
	})
}

func (s *Store) ListAdministrativeTasks(ctx context.Context, input domain.AdministrativeTaskPageRequest) (domain.AdministrativeTaskPage, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.AdministrativeTaskPage{}, err
	}
	if _, err := domain.PageLimit(input.Limit); err != nil {
		return domain.AdministrativeTaskPage{}, err
	}
	after := domain.NativeTaskKey{}
	if input.After != nil {
		if err := input.After.Validate(); err != nil {
			return domain.AdministrativeTaskPage{}, err
		}
		after = *input.After
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.AdministrativeTaskPage, error) {
		keys, err := administrativeTaskKeys(ctx, tx, after, input.Limit+1)
		if err != nil {
			return domain.AdministrativeTaskPage{}, err
		}
		page := domain.AdministrativeTaskPage{}
		if len(keys) > input.Limit {
			keys = keys[:input.Limit]
			next := keys[len(keys)-1]
			page.Next = &next
		}
		for _, key := range keys {
			row, readErr := readAdministrativeTask(ctx, tx, key)
			if readErr != nil {
				return domain.AdministrativeTaskPage{}, readErr
			}
			page.Items = append(page.Items, row.view)
		}
		return page, nil
	})
}

func administrativeTaskKeys(ctx context.Context, tx *sql.Tx, after domain.NativeTaskKey, limit int) (keys []domain.NativeTaskKey, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT device,root_guard,task FROM operations WHERE (device,root_guard,task)>(?,?,?) ORDER BY device,root_guard,task LIMIT ?", after.Device, after.Root, after.Task, limit)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var key domain.NativeTaskKey
		if err = rows.Scan(&key.Device, &key.Root, &key.Task); err != nil {
			return nil, err
		}
		if err = key.Validate(); err != nil {
			return nil, domain.Reject(domain.EvidenceInvalid)
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) BindAdministrativeCancellation(ctx context.Context, key domain.NativeTaskKey, cancellation domain.CancellationID) (domain.AdministrativeTaskView, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.AdministrativeTaskView{}, err
	}
	if key.Validate() != nil || cancellation.Validate() != nil {
		return domain.AdministrativeTaskView{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.AdministrativeTaskView, error) {
		row, err := readAdministrativeTask(ctx, tx, key)
		if err != nil {
			return row.view, err
		}
		if row.view.Cancellation != "" && row.view.Cancellation != cancellation {
			return row.view, domain.Reject(domain.Conflict)
		}
		_, err = tx.ExecContext(ctx, "UPDATE operations SET cancellation=? WHERE row_id=?", cancellation, row.rowID)
		row.view.Cancellation = cancellation
		return row.view, err
	})
}

func (s *Store) CheckAdministrativeDrain(ctx context.Context, input domain.AdministrativeDrainCheck) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validateAdministrativeDrain(input); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		_, err := checkAdministrativeDrain(ctx, tx, input)
		return struct{}{}, err
	})
	return err
}

func validateAdministrativeDrain(input domain.AdministrativeDrainCheck) error {
	if input.Key.Validate() != nil || input.Action.Validate() != nil || input.Destination.Validate() != nil || input.Credential.Validate() != nil || input.Connection.Validate() != nil || input.Now.IsZero() || input.Destination.Device != input.Key.Device || input.Credential.Device != input.Key.Device {
		return domain.ErrInvalid
	}
	return nil
}

func checkAdministrativeDrain(ctx context.Context, tx *sql.Tx, input domain.AdministrativeDrainCheck) (administrativeRow, error) {
	row, err := readAdministrativeTask(ctx, tx, input.Key)
	if err != nil {
		return row, err
	}
	if _, err = checkConnection(ctx, tx, input.Credential, input.Connection, input.Now); err != nil {
		return row, err
	}
	binding, err := readContext(ctx, tx, input.Destination)
	if err != nil {
		return row, err
	}
	if binding != row.view.Binding.Context {
		return row, domain.Reject(domain.Conflict)
	}
	if input.Action == domain.AdministrativeResolve || input.Action == domain.AdministrativeFence {
		return row, nil
	}
	if row.view.Binding.SpecDigest == (domain.Digest{}) || input.Action == domain.AdministrativeCancel && row.view.Cancellation == "" {
		return row, domain.Reject(domain.Conflict)
	}
	return row, checkAdministrativeRoute(ctx, tx, input, binding)
}

func checkAdministrativeRoute(ctx context.Context, tx *sql.Tx, input domain.AdministrativeDrainCheck, binding domain.ContextBinding) error {
	var alias domain.ProjectAlias
	var credentialData, connectionData []byte
	err := tx.QueryRowContext(ctx, "SELECT alias,credential,connection FROM administrative_routes WHERE device=? AND root_guard=? AND project_guard=?", input.Key.Device, binding.Root, binding.Project).Scan(&alias, &credentialData, &connectionData)
	if err != nil {
		return notFound(err)
	}
	credential, err := encode(input.Credential)
	if err != nil {
		return err
	}
	connection, err := encode(input.Connection)
	if err != nil {
		return err
	}
	if alias != input.Destination.Project || !bytes.Equal(credentialData, credential) || !bytes.Equal(connectionData, connection) {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func (s *Store) RecordAdministrativeObservation(ctx context.Context, input domain.AdministrativeObservation) (domain.AdministrativeTaskView, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.AdministrativeTaskView{}, err
	}
	if validateAdministrativeDrain(input.Check) != nil || input.Binding.Validate() != nil || input.Observation.Validate(input.Check.Now) != nil {
		return domain.AdministrativeTaskView{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.AdministrativeTaskView, error) {
		row, err := checkAdministrativeDrain(ctx, tx, input.Check)
		if err != nil {
			return row.view, err
		}
		if row.view.Binding != input.Binding {
			return row.view, domain.Reject(domain.EvidenceInvalid)
		}
		if row.view.Binding.SpecDigest != (domain.Digest{}) && input.Observation.SpecDigest != (domain.Digest{}) && input.Observation.SpecDigest != row.view.Binding.SpecDigest {
			return row.view, domain.Reject(domain.EvidenceInvalid)
		}
		if stop := input.Observation.ConfirmedStop; stop != nil && (input.Check.Action != domain.AdministrativeCancel || row.view.Cancellation == "" || stop.Cancellation != row.view.Cancellation) {
			return row.view, domain.Reject(domain.EvidenceInvalid)
		}
		return mergeAdministrativeObservation(ctx, tx, row, input.Observation)
	})
}
