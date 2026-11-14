package registry

import (
	"context"
	"database/sql"
	"encoding/hex"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// AcquireRouting retains all shared census, replay and quota gates. Only four
// root initialization commands on negotiated wire2 can use this authority.
func (p *OwnedRootPort) AcquireRouting(ctx context.Context, input routing.Request) error {
	command, err := validateRoutingRequest(input)
	if err != nil {
		return err
	}
	if input.ProtocolVersion() != protocol.WireVersion2 || input.Credential != p.binding.Credential || routingGeneration(input.Call.Generation) != p.binding.Connection || command.Project != "" || command.Root != string(p.binding.Route.Root) {
		return domain.Reject(domain.Forbidden)
	}
	_, err = transaction(ctx, p.store, func(tx *sql.Tx) (struct{}, error) {
		if _, checkErr := p.check(ctx, tx); checkErr != nil {
			return struct{}{}, checkErr
		}
		input.Now = p.now()
		return struct{}{}, acquireRouting(ctx, tx, input, func() error { return p.checkCommand(ctx, tx, command) })
	})
	return err
}

func (p *OwnedRootPort) checkCommand(ctx context.Context, tx *sql.Tx, command protocol.Command) error {
	switch command.Operation {
	case protocol.ContextInspect:
		return p.checkRootInspection(command.Body)
	case protocol.OriginBarrier:
		return p.checkRootBarrier(ctx, tx, command.Body)
	case protocol.OriginInventory:
		return p.checkRootInventory(ctx, tx, command.Body)
	case protocol.OriginReopen:
		return p.checkRootReopen(ctx, tx, command.Body)
	case protocol.Admit, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel, protocol.ResolveProject:
		return domain.Reject(domain.Forbidden)
	default:
		return domain.Reject(domain.Forbidden)
	}
}

func (p *OwnedRootPort) checkRootInspection(body []byte) error {
	var input protocol.InspectRequest
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.GatewayID != string(p.gateway) || !input.RootOnly {
		return domain.ErrInvalid
	}
	return nil
}

func (p *OwnedRootPort) checkRootBarrier(ctx context.Context, tx *sql.Tx, body []byte) error {
	var input protocol.OriginBarrierRequest
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.GatewayID != string(p.gateway) || input.ExpectedRoot != string(p.binding.Route.Root) {
		return domain.ErrInvalid
	}
	id := domain.RecoveryID(input.RecoveryID)
	if err := p.checkRecovery(ctx, tx, id); err != nil {
		return err
	}
	var generation, expected string
	if err := tx.QueryRowContext(ctx, "SELECT generation,expected_generation FROM recovery_destinations WHERE recovery=? AND device=? AND root_guard=?", id, p.binding.Route.Device, p.binding.Route.Root).Scan(&generation, &expected); err != nil {
		return notFound(err)
	}
	if generation == "" || input.Generation != generation || input.ExpectedGeneration != expected {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func (p *OwnedRootPort) checkRootInventory(ctx context.Context, tx *sql.Tx, body []byte) error {
	var input protocol.OriginInventoryRequest
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.GatewayID != string(p.gateway) || input.ExpectedRoot != string(p.binding.Route.Root) || input.Limit < 1 || input.Limit > domain.MaxPageLimit {
		return domain.ErrInvalid
	}
	progress, err := readRootProgress(ctx, tx, p.lookup())
	if err != nil {
		return err
	}
	if input.Generation != string(progress.Generation) || input.Cursor != progress.Cursor {
		return domain.Reject(domain.Conflict)
	}
	return p.checkRecovery(ctx, tx, progress.RecoveryID)
}

func (p *OwnedRootPort) checkRootReopen(ctx context.Context, tx *sql.Tx, body []byte) error {
	var input protocol.OriginReopenRequest
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.GatewayID != string(p.gateway) || input.ExpectedRoot != string(p.binding.Route.Root) {
		return domain.ErrInvalid
	}
	if err := p.checkRecovery(ctx, tx, domain.RecoveryID(input.RecoveryID)); err != nil {
		return err
	}
	progress, err := readRootProgress(ctx, tx, p.lookup())
	if err != nil {
		return err
	}
	if progress.Reopen == nil || input.Generation != string(progress.Generation) || input.CompletenessReceipt != hex.EncodeToString(progress.Reopen.Completeness[:]) {
		return domain.Reject(domain.Conflict)
	}
	return checkReopenTarget(ctx, tx, *progress.Reopen, p.now())
}
