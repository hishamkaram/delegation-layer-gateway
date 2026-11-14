package registry

import (
	"context"
	"database/sql"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// AcquireProjectMetadata admits only a frozen resolution or targeted inspection,
// using the existing routing census/quotas in the same authorization transaction.
func (s *Store) AcquireProjectMetadata(ctx context.Context, actor domain.Actor, id domain.ResolutionID, scope domain.Scope, input routing.Request) error {
	command, err := validateRoutingRequest(input)
	if err != nil {
		return err
	}
	if id.Validate() != nil || input.ProtocolVersion() != protocol.WireVersion2 || (scope != domain.InventoryRead && scope != domain.TaskDispatch) {
		return domain.ErrInvalid
	}
	_, err = transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if ownerErr := resolutionOwner(ctx, tx, actor, input.Credential.Device, scope); ownerErr != nil {
			return struct{}{}, ownerErr
		}
		resolution, found, readErr := readProjectResolution(ctx, tx, id)
		if readErr != nil {
			return struct{}{}, readErr
		}
		if !found || resolution.Principal != actor.Principal || resolution.Device != input.Credential.Device {
			return struct{}{}, domain.Reject(domain.NotFound)
		}
		binding := domain.OwnedRootBinding{Route: domain.RootRoute{Device: resolution.Device, Root: resolution.Root}, Credential: input.Credential, Connection: routingGeneration(input.Call.Generation)}
		if checkErr := resolutionConnection(ctx, tx, binding, input.Now); checkErr != nil {
			return struct{}{}, checkErr
		}
		return struct{}{}, acquireRouting(ctx, tx, input, func() error { return validateProjectMetadata(ctx, tx, resolution, scope, command) })
	})
	return err
}

func validateProjectMetadata(ctx context.Context, tx *sql.Tx, resolution domain.ProjectResolution, scope domain.Scope, command protocol.Command) error {
	switch command.Operation {
	case protocol.ResolveProject:
		return validateResolveMetadata(ctx, tx, resolution, scope, command)
	case protocol.ContextInspect:
		return validateInspectMetadata(ctx, tx, resolution, command)
	case protocol.Admit, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen:
		return domain.Reject(domain.Forbidden)
	default:
		return domain.Reject(domain.Forbidden)
	}
}

func validateResolveMetadata(ctx context.Context, tx *sql.Tx, resolution domain.ProjectResolution, scope domain.Scope, command protocol.Command) error {
	if scope != domain.TaskDispatch || command.Root != string(resolution.Root) || command.Project != "" {
		return domain.Reject(domain.Forbidden)
	}
	var request protocol.ResolveProjectRequest
	if protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes) != nil || request.Validate() != nil || request.RequestID != string(resolution.Request) || request.WorkspaceID != resolution.Workspace.ID || domain.Hash([]byte(request.RelativePath)) != resolution.SelectorDigest {
		return domain.Reject(domain.EvidenceInvalid)
	}
	var state domain.RootState
	if err := tx.QueryRowContext(ctx, "SELECT state FROM root_admissions WHERE device=? AND root_guard=?", resolution.Device, resolution.Root).Scan(&state); err != nil {
		return notFound(err)
	}
	if state != domain.RootOpen {
		return domain.Reject(domain.Pending)
	}
	return nil
}

func validateInspectMetadata(ctx context.Context, tx *sql.Tx, resolution domain.ProjectResolution, command protocol.Command) error {
	if !resolution.Registered || resolution.Pin == nil || command.Project != string(resolution.Pin.Handle) || command.Root != "" {
		return domain.Reject(domain.NotFound)
	}
	var request protocol.InspectRequest
	if protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes) != nil || request.RootOnly {
		return domain.ErrInvalid
	}
	var gateway domain.GatewayID
	if err := tx.QueryRowContext(ctx, "SELECT gateway FROM settings WHERE id=1").Scan(&gateway); err != nil {
		return err
	}
	if request.GatewayID != string(gateway) {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}
