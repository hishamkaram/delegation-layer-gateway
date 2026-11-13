package registry

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func resolutionOwner(ctx context.Context, tx *sql.Tx, actor domain.Actor, device domain.DeviceID, scope domain.Scope) error {
	input := domain.OwnedDeviceRequest{Actor: actor, Device: device, Scope: scope}
	if err := input.Validate(); err != nil {
		return err
	}
	_, err := authorizeOwnedDevice(ctx, tx, input)
	return err
}

func readProjectResolution(ctx context.Context, tx *sql.Tx, id domain.ResolutionID) (domain.ProjectResolution, bool, error) {
	result := domain.ProjectResolution{Request: id}
	var digest, pin []byte
	var created string
	err := tx.QueryRowContext(ctx, "SELECT principal,device,root_guard,workspace_id,workspace_guard,selector_sha256,pin,created FROM project_resolutions WHERE request=?", id).Scan(&result.Principal, &result.Device, &result.Root, &result.Workspace.ID, &result.Workspace.Guard, &digest, &pin, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if len(digest) != len(result.SelectorDigest) {
		return result, true, domain.Reject(domain.EvidenceInvalid)
	}
	copy(result.SelectorDigest[:], digest)
	result.CreatedAt, err = time.Parse(timestampLayout, created)
	if err != nil {
		return result, true, domain.Reject(domain.EvidenceInvalid)
	}
	if pin != nil {
		decoded, decodeErr := decode[domain.ProjectPin](pin)
		if decodeErr != nil {
			return result, true, decodeErr
		}
		result.Pin = &decoded
	}
	if err = result.Validate(); err != nil {
		return result, true, domain.Reject(domain.EvidenceInvalid)
	}
	result.Registered, err = resolutionRegistered(ctx, tx, result)
	return result, true, err
}

func resolutionRegistered(ctx context.Context, tx *sql.Tx, result domain.ProjectResolution) (bool, error) {
	var device domain.DeviceID
	var alias domain.ProjectAlias
	err := tx.QueryRowContext(ctx, "SELECT device,alias FROM owned_projects WHERE request=?", result.Request).Scan(&device, &alias)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if device != result.Device || alias != domain.ProjectAlias(result.Request) || result.Pin == nil {
		return false, domain.Reject(domain.EvidenceInvalid)
	}
	binding, err := readContext(ctx, tx, domain.Destination{Device: device, Project: alias})
	if err != nil {
		return false, err
	}
	if binding != result.Pin.Context {
		return false, domain.Reject(domain.EvidenceInvalid)
	}
	return true, nil
}

// LookupProjectResolution distinguishes absent correlation from a storage or
// authorization failure. Saved identity never implies current availability.
func (s *Store) LookupProjectResolution(ctx context.Context, actor domain.Actor, device domain.DeviceID, id domain.ResolutionID) (domain.ProjectResolution, bool, error) {
	if id.Validate() != nil {
		return domain.ProjectResolution{}, false, domain.ErrInvalid
	}
	type lookup struct {
		value domain.ProjectResolution
		found bool
	}
	result, err := transaction(ctx, s, func(tx *sql.Tx) (lookup, error) {
		if err := resolutionOwner(ctx, tx, actor, device, domain.TaskDispatch); err != nil {
			return lookup{}, err
		}
		value, found, err := readProjectResolution(ctx, tx, id)
		if err != nil {
			return lookup{}, err
		}
		if found && (value.Principal != actor.Principal || value.Device != device) {
			return lookup{}, domain.Reject(domain.NotFound)
		}
		return lookup{value: value, found: found}, nil
	})
	return result.value, result.found, err
}

func resolutionBinding(ctx context.Context, tx *sql.Tx, actor domain.Actor, binding domain.OwnedRootBinding, scope domain.Scope, now time.Time) error {
	if binding.Validate() != nil || now.IsZero() {
		return domain.ErrInvalid
	}
	if err := resolutionOwner(ctx, tx, actor, binding.Route.Device, scope); err != nil {
		return err
	}
	return resolutionConnection(ctx, tx, binding, now)
}

func resolutionConnection(ctx context.Context, tx *sql.Tx, binding domain.OwnedRootBinding, now time.Time) error {
	if binding.Validate() != nil || now.IsZero() {
		return domain.ErrInvalid
	}
	if err := admissionsOpen(ctx, tx); err != nil {
		return err
	}
	credential, err := checkConnection(ctx, tx, binding.Credential, binding.Connection, now)
	if err != nil {
		return err
	}
	if credential.Mode != domain.Regular {
		return domain.Reject(domain.Forbidden)
	}
	var changed int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM root_admissions WHERE device=? AND root_guard<>?", binding.Route.Device, binding.Route.Root).Scan(&changed); err != nil {
		return err
	}
	if changed != 0 {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func (s *Store) BeginProjectResolution(ctx context.Context, actor domain.Actor, input domain.ProjectResolutionStart) (domain.ProjectResolution, error) {
	if input.Request.Validate() != nil || input.Workspace.Validate() != nil || input.SelectorDigest.Validate() != nil {
		return domain.ProjectResolution{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.ProjectResolution, error) {
		if err := resolutionBinding(ctx, tx, actor, input.Binding, domain.TaskDispatch, input.Now); err != nil {
			return domain.ProjectResolution{}, err
		}
		existing, found, err := readProjectResolution(ctx, tx, input.Request)
		if err != nil {
			return existing, err
		}
		if found {
			if !sameResolution(existing, actor, input) {
				return domain.ProjectResolution{}, domain.Reject(domain.Conflict)
			}
			return existing, nil
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM project_resolutions WHERE device=?", input.Binding.Route.Device).Scan(&count); err != nil {
			return domain.ProjectResolution{}, err
		}
		if count >= protocol.MaxProjectPins {
			return domain.ProjectResolution{}, domain.Reject(domain.ResourceLimit)
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO project_resolutions(request,principal,device,root_guard,workspace_id,workspace_guard,selector_sha256,created) VALUES(?,?,?,?,?,?,?,?)", input.Request, actor.Principal, input.Binding.Route.Device, input.Binding.Route.Root, input.Workspace.ID, input.Workspace.Guard, input.SelectorDigest[:], input.Now.UTC().Format(timestampLayout))
		if err != nil {
			return domain.ProjectResolution{}, err
		}
		result, _, err := readProjectResolution(ctx, tx, input.Request)
		return result, err
	})
}

func sameResolution(existing domain.ProjectResolution, actor domain.Actor, input domain.ProjectResolutionStart) bool {
	return existing.Principal == actor.Principal && existing.Device == input.Binding.Route.Device && existing.Root == input.Binding.Route.Root && existing.Workspace == input.Workspace && existing.SelectorDigest == input.SelectorDigest
}

func checkedProjectResolution(ctx context.Context, tx *sql.Tx, actor domain.Actor, input domain.ProjectResolutionCheck, scope domain.Scope) (domain.ProjectResolution, error) {
	if input.Request.Validate() != nil {
		return domain.ProjectResolution{}, domain.ErrInvalid
	}
	if err := resolutionBinding(ctx, tx, actor, input.Binding, scope, input.Now); err != nil {
		return domain.ProjectResolution{}, err
	}
	result, found, err := readProjectResolution(ctx, tx, input.Request)
	if err != nil {
		return result, err
	}
	if !found || result.Principal != actor.Principal || result.Device != input.Binding.Route.Device {
		return domain.ProjectResolution{}, domain.Reject(domain.NotFound)
	}
	if result.Root != input.Binding.Route.Root {
		return domain.ProjectResolution{}, domain.Reject(domain.Conflict)
	}
	return result, nil
}

func (s *Store) CheckProjectResolution(ctx context.Context, actor domain.Actor, input domain.ProjectResolutionCheck, scope domain.Scope) error {
	if scope != domain.InventoryRead && scope != domain.TaskDispatch {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (domain.ProjectResolution, error) {
		return checkedProjectResolution(ctx, tx, actor, input, scope)
	})
	return err
}
