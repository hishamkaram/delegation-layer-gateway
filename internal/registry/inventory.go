package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func validatePage(actor domain.Actor, after string, limit int) (int, error) {
	if err := actor.Validate(); err != nil {
		return 0, err
	}
	if after != "" {
		if err := domain.Token(after); err != nil {
			return 0, err
		}
	}
	return domain.PageLimit(limit)
}

func (s *Store) ListDevices(ctx context.Context, actor domain.Actor, page domain.DevicePageRequest) (domain.DevicePage, error) {
	limit, err := validatePage(actor, string(page.After), page.Limit)
	if err != nil {
		return domain.DevicePage{}, err
	}
	if !actor.Scopes.Has(domain.InventoryRead) {
		return domain.DevicePage{}, domain.Reject(domain.Forbidden)
	}
	return transaction(ctx, s, func(tx *sql.Tx) (result domain.DevicePage, err error) {
		if err = checkPrincipal(ctx, tx, actor.Principal); err != nil {
			return result, err
		}
		rows, err := tx.QueryContext(ctx, effectiveAccessCTE+`SELECT DISTINCT d.id,d.name,d.revoked,d.credential_generation,d.counter FROM devices d JOIN effective_access g ON g.device=d.id WHERE g.principal=? AND d.revoked=0 AND d.id>? AND EXISTS(SELECT 1 FROM json_each(g.scopes) WHERE value=?) ORDER BY d.id LIMIT ?`, actor.Principal, page.After, domain.InventoryRead, limit+1)
		if err != nil {
			return result, err
		}
		defer func() { err = errors.Join(err, rows.Close()) }()
		for rows.Next() {
			var device domain.Device
			if err = rows.Scan(&device.ID, &device.Name, &device.Revoked, &device.CredentialGeneration, &device.ConnectionCounter); err != nil {
				return result, err
			}
			result.Items = append(result.Items, device)
		}
		if err = rows.Err(); err != nil {
			return result, err
		}
		if len(result.Items) > limit {
			result.Items = result.Items[:limit]
			result.Next = result.Items[limit-1].ID
		}
		return result, nil
	})
}

func (s *Store) ListProjects(ctx context.Context, actor domain.Actor, device domain.DeviceID, page domain.ProjectPageRequest) (domain.ProjectPage, error) {
	limit, err := validatePage(actor, string(page.After), page.Limit)
	if err != nil {
		return domain.ProjectPage{}, err
	}
	if err = domain.CredentialToken(string(device)); err != nil {
		return domain.ProjectPage{}, err
	}
	if !actor.Scopes.Has(domain.InventoryRead) {
		return domain.ProjectPage{}, domain.Reject(domain.Forbidden)
	}
	return transaction(ctx, s, func(tx *sql.Tx) (result domain.ProjectPage, err error) {
		if err = checkPrincipal(ctx, tx, actor.Principal); err != nil {
			return result, err
		}
		rows, err := tx.QueryContext(ctx, effectiveAccessCTE+`SELECT p.alias,p.root_guard,p.project_guard FROM projects p JOIN devices d ON d.id=p.device JOIN effective_access g ON g.device=p.device AND g.project=p.alias WHERE g.principal=? AND p.device=? AND d.revoked=0 AND p.alias>? AND EXISTS(SELECT 1 FROM json_each(g.scopes) WHERE value=?) ORDER BY p.alias LIMIT ?`, actor.Principal, device, page.After, domain.InventoryRead, limit+1)
		if err != nil {
			return result, err
		}
		defer func() { err = errors.Join(err, rows.Close()) }()
		for rows.Next() {
			item := domain.ProjectRegistration{Destination: domain.Destination{Device: device}}
			if err = rows.Scan(&item.Destination.Project, &item.Context.Root, &item.Context.Project); err != nil {
				return result, err
			}
			if err = item.Validate(); err != nil {
				return result, err
			}
			result.Items = append(result.Items, item)
		}
		if err = rows.Err(); err != nil {
			return result, err
		}
		if len(result.Items) > limit {
			result.Items = result.Items[:limit]
			result.Next = result.Items[limit-1].Destination.Project
		}
		return result, nil
	})
}

func (s *Store) ListOperations(ctx context.Context, actor domain.Actor, page domain.OperationPageRequest) (domain.OperationPage, error) {
	limit, err := validatePage(actor, string(page.After), page.Limit)
	if err != nil {
		return domain.OperationPage{}, err
	}
	if !actor.Scopes.Has(domain.TaskRead) && !actor.Scopes.Has(domain.TaskDispatch) {
		return domain.OperationPage{}, domain.Reject(domain.Forbidden)
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.OperationPage, error) {
		if err := checkPrincipal(ctx, tx, actor.Principal); err != nil {
			return domain.OperationPage{}, err
		}
		ids, err := operationIDs(ctx, tx, actor, page, limit)
		if err != nil {
			return domain.OperationPage{}, err
		}
		var result domain.OperationPage
		for _, id := range ids {
			op, readErr := readOperation(ctx, tx, id)
			if readErr != nil {
				return result, readErr
			}
			result.Items = append(result.Items, op.view)
		}
		if len(result.Items) > limit {
			result.Items = result.Items[:limit]
			result.Next = result.Items[limit-1].Correlation.Operation
		}
		return result, nil
	})
}

func operationIDs(ctx context.Context, tx *sql.Tx, actor domain.Actor, page domain.OperationPageRequest, limit int) (ids []domain.OperationID, err error) {
	rows, err := tx.QueryContext(ctx, effectiveAccessCTE+`SELECT o.id FROM operations o JOIN devices d ON d.id=o.device JOIN effective_access g ON g.device=o.device AND g.project=o.project AND g.principal=o.owner WHERE o.owner=? AND o.id>? AND d.revoked=0 AND ((? AND EXISTS(SELECT 1 FROM json_each(g.scopes) WHERE value=?)) OR (? AND o.state IN (?,?) AND EXISTS(SELECT 1 FROM json_each(g.scopes) WHERE value=?))) ORDER BY o.id LIMIT ?`, actor.Principal, page.After, actor.Scopes.Has(domain.TaskRead), domain.TaskRead, actor.Scopes.Has(domain.TaskDispatch), domain.Prepared, domain.ExpiredUnsent, domain.TaskDispatch, limit+1)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var id domain.OperationID
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
