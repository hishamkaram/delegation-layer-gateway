package registry

import (
	"context"
	"database/sql"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func routingRestoreState(ctx context.Context, tx *sql.Tx, device domain.DeviceID) (recovery domain.RecoveryID, covered, restoring bool, err error) {
	err = tx.QueryRowContext(ctx, `SELECT s.recovery,
EXISTS(SELECT 1 FROM routing_roster_devices d WHERE d.recovery=s.recovery AND d.device=? AND d.covered=1),
EXISTS(SELECT 1 FROM recoveries r WHERE r.id=s.recovery AND r.kind='restore' AND r.status='active')
FROM settings s WHERE s.id=1`, device).Scan(&recovery, &covered, &restoring)
	return
}

func readRoutingDrainTarget(ctx context.Context, tx *sql.Tx, device domain.DeviceID, now time.Time) (routing.DrainTarget, error) {
	peer, err := readRoutingPeer(ctx, tx, device)
	if err != nil {
		return routing.DrainTarget{}, notFound(err)
	}
	if _, err = checkConnection(ctx, tx, peer.credential, peer.generation, now); err != nil {
		return routing.DrainTarget{}, err
	}
	recovery, covered, _, err := routingRestoreState(ctx, tx, device)
	if err != nil {
		return routing.DrainTarget{}, err
	}
	return routing.DrainTarget{Device: device, Recovery: recovery, Credential: peer.credential, ProcessBoot: peer.boot, Generation: peer.generation, Blocked: peer.blocked, Covered: covered}, nil
}

// ReadRoutingDrainTarget returns current authenticated metadata for an explicit
// operator confirmation. It grants no authority and starts no CLI control.
func (s *Store) ReadRoutingDrainTarget(ctx context.Context, device domain.DeviceID, now time.Time) (routing.DrainTarget, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return routing.DrainTarget{}, err
	}
	if domain.CredentialToken(string(device)) != nil || now.IsZero() {
		return routing.DrainTarget{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (routing.DrainTarget, error) {
		return readRoutingDrainTarget(ctx, tx, device, now)
	})
}

// AttestRoutingDrained accepts a frozen protected operator confirmation of CLI
// joins. It never supplies Delegate task closure or releases task reservations.
func (s *Store) AttestRoutingDrained(ctx context.Context, input routing.Drain) (routing.DrainResult, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return routing.DrainResult{}, err
	}
	if input.ValidateBinding() != nil || input.Now.IsZero() {
		return routing.DrainResult{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (routing.DrainResult, error) {
		return attestRoutingDrained(ctx, tx, input)
	})
}

func attestRoutingDrained(ctx context.Context, tx *sql.Tx, input routing.Drain) (routing.DrainResult, error) {
	target, err := readRoutingDrainTarget(ctx, tx, input.Device, input.Now)
	if err != nil {
		return routing.DrainResult{}, err
	}
	if target.Credential != input.Credential || target.ProcessBoot != input.CurrentBoot || target.Recovery != input.Recovery {
		return routing.DrainResult{}, domain.Reject(domain.Conflict)
	}
	other, err := hasOtherRoutingBoot(ctx, tx, input.Device, input.CurrentBoot)
	if err != nil {
		return routing.DrainResult{}, err
	}
	if target.Recovery != "" && target.Covered && !target.Blocked && !other {
		return routing.DrainResult{Disposition: routing.AlreadySatisfied, Target: target}, nil
	}
	if !target.Blocked || target.Generation != input.Generation {
		return routing.DrainResult{}, domain.Reject(domain.Conflict)
	}
	if err = checkRoutingDrainScope(ctx, tx, input, target); err != nil {
		return routing.DrainResult{}, err
	}
	return commitRoutingDrain(ctx, tx, input, target)
}

func commitRoutingDrain(ctx context.Context, tx *sql.Tx, input routing.Drain, target routing.DrainTarget) (routing.DrainResult, error) {
	query := "UPDATE routing_permits SET state='admin_drained' WHERE device=? AND process_boot<>? AND state='active'"
	arguments := []any{input.Device, input.CurrentBoot}
	if input.Scope == routing.KnownPriorBoot {
		query = "UPDATE routing_permits SET state='admin_drained' WHERE device=? AND process_boot=? AND state='active'"
		arguments = []any{input.Device, input.PriorBoot}
	}
	if _, err := tx.ExecContext(ctx, query, arguments...); err != nil {
		return routing.DrainResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE routing_peers SET blocked=0 WHERE device=?", input.Device); err != nil {
		return routing.DrainResult{}, err
	}
	if err := coverRoutingRosterDevice(ctx, tx, input.Device); err != nil {
		return routing.DrainResult{}, err
	}
	if err := compactRoutingPermits(ctx, tx, input.Device, target.Generation.Counter); err != nil {
		return routing.DrainResult{}, err
	}
	updated, err := readRoutingDrainTarget(ctx, tx, input.Device, input.Now)
	return routing.DrainResult{Disposition: routing.Drained, Target: updated}, err
}

func checkRoutingDrainScope(ctx context.Context, tx *sql.Tx, input routing.Drain, target routing.DrainTarget) error {
	if input.Scope == routing.AllPriorControls {
		return nil
	}
	if target.Recovery != "" && !target.Covered {
		return domain.Reject(domain.Forbidden)
	}
	var unexpected, prior int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(process_boot<>? AND process_boot<>?),0),COALESCE(SUM(process_boot=?),0) FROM routing_permits WHERE device=? AND state='active'", input.PriorBoot, input.CurrentBoot, input.PriorBoot, input.Device).Scan(&unexpected, &prior); err != nil {
		return err
	}
	if unexpected != 0 || prior == 0 {
		return domain.Reject(domain.Conflict)
	}
	return nil
}
