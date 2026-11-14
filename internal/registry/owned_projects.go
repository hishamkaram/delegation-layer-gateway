package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// CheckResolvedProject keeps route registration, immutable pin and current
// connection authorization in one transaction around targeted metadata sends.
func (s *Store) CheckResolvedProject(ctx context.Context, actor domain.Actor, input domain.ProjectResolutionPin, scope domain.Scope) error {
	if input.Pin.Validate() != nil || input.Pin.Handle != domain.ProjectAlias(input.Request) || (scope != domain.InventoryRead && scope != domain.TaskDispatch) {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		resolution, err := checkedProjectResolution(ctx, tx, actor, domain.ProjectResolutionCheck{Request: input.Request, Binding: input.Binding, Now: input.Now}, scope)
		if err != nil {
			return struct{}{}, err
		}
		if !resolution.Registered || resolution.Pin == nil || *resolution.Pin != input.Pin {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		return struct{}{}, nil
	})
	return err
}

// RecordProjectResolutionPin commits the first valid Native identity without
// registering a route. A later route failure cannot erase or replace this pin.
func (s *Store) RecordProjectResolutionPin(ctx context.Context, actor domain.Actor, input domain.ProjectResolutionPin) (domain.ProjectResolution, error) {
	if input.Pin.Validate() != nil {
		return domain.ProjectResolution{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.ProjectResolution, error) {
		check := domain.ProjectResolutionCheck{Request: input.Request, Binding: input.Binding, Now: input.Now}
		result, err := checkedProjectResolution(ctx, tx, actor, check, domain.TaskDispatch)
		if err != nil {
			return result, err
		}
		if input.Pin.Handle != domain.ProjectAlias(result.Request) || input.Pin.Context.Root != result.Root || input.Pin.Workspace != result.Workspace {
			return domain.ProjectResolution{}, domain.Reject(domain.EvidenceInvalid)
		}
		if result.Pin != nil {
			if *result.Pin != input.Pin {
				return domain.ProjectResolution{}, domain.Reject(domain.Conflict)
			}
			return result, nil
		}
		encoded, err := encode(input.Pin)
		if err != nil {
			return domain.ProjectResolution{}, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE project_resolutions SET pin=? WHERE request=? AND pin IS NULL", encoded, input.Request)
		if err != nil {
			return domain.ProjectResolution{}, err
		}
		result, _, err = readProjectResolution(ctx, tx, input.Request)
		return result, err
	})
}

// RegisterResolvedProject derives the existing route only from a saved receipt.
// Raw caller paths, current workspace policy and provider readiness are absent.
func (s *Store) RegisterResolvedProject(ctx context.Context, actor domain.Actor, input domain.ProjectResolutionCheck) (domain.ProjectResolution, error) {
	return transaction(ctx, s, func(tx *sql.Tx) (domain.ProjectResolution, error) {
		result, err := checkedProjectResolution(ctx, tx, actor, input, domain.TaskDispatch)
		if err != nil {
			return result, err
		}
		if result.Pin == nil {
			return domain.ProjectResolution{}, domain.Reject(domain.Pending)
		}
		if result.Registered {
			return result, nil
		}
		if err = registerSavedProject(ctx, tx, result); err != nil {
			return domain.ProjectResolution{}, err
		}
		result, _, err = readProjectResolution(ctx, tx, input.Request)
		return result, err
	})
}

func registerSavedProject(ctx context.Context, tx *sql.Tx, resolution domain.ProjectResolution) error {
	pin := resolution.Pin
	if pin == nil || resolution.Validate() != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	var exists int
	err := tx.QueryRowContext(ctx, "SELECT 1 FROM projects WHERE device=? AND alias=?", resolution.Device, pin.Handle).Scan(&exists)
	if err == nil {
		// An existing alias, even with equal opaque guards, was not registered by
		// this receipt. Never silently adopt a legacy or different route.
		return domain.Reject(domain.Conflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO projects(device,alias,root_guard,project_guard) VALUES(?,?,?,?)", resolution.Device, pin.Handle, pin.Context.Root, pin.Context.Project)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO owned_projects(device,alias,request) VALUES(?,?,?)", resolution.Device, pin.Handle, resolution.Request)
	return err
}

// GetResolvedProject authorizes retained identity without requiring a current
// workspace advertisement. Fresh capabilities remain a separate live query.
func (s *Store) GetResolvedProject(ctx context.Context, actor domain.Actor, destination domain.Destination, scope domain.Scope) (domain.ProjectPin, error) {
	if destination.Validate() != nil || domain.ResolutionID(destination.Project).Validate() != nil || (scope != domain.InventoryRead && scope != domain.TaskDispatch) {
		return domain.ProjectPin{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.ProjectPin, error) {
		if err := resolutionOwner(ctx, tx, actor, destination.Device, scope); err != nil {
			return domain.ProjectPin{}, err
		}
		result, found, err := readProjectResolution(ctx, tx, domain.ResolutionID(destination.Project))
		if err != nil {
			return domain.ProjectPin{}, err
		}
		if !found || result.Principal != actor.Principal || result.Device != destination.Device || result.Pin == nil || !result.Registered {
			return domain.ProjectPin{}, domain.Reject(domain.NotFound)
		}
		return *result.Pin, nil
	})
}
