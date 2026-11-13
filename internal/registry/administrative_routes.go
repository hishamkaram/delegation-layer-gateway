package registry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// Registry owns the single current administrative route for a physical context.
// Only protected orchestration calls this after a fresh connector proof.
func (s *Store) BindAdministrativeRoute(ctx context.Context, input domain.AdministrativeRouteBinding) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if input.Destination.Validate() != nil || input.Context.Validate() != nil || input.Credential.Validate() != nil || input.Connection.Validate() != nil || input.Credential.Device != input.Destination.Device || input.Now.IsZero() {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if _, err := checkConnection(ctx, tx, input.Credential, input.Connection, input.Now); err != nil {
			return struct{}{}, err
		}
		binding, err := readContext(ctx, tx, input.Destination)
		if err != nil {
			return struct{}{}, err
		}
		if binding != input.Context {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		return struct{}{}, bindAdministrativeRoute(ctx, tx, input)
	})
	return err
}

func bindAdministrativeRoute(ctx context.Context, tx *sql.Tx, input domain.AdministrativeRouteBinding) error {
	credential, err := encode(input.Credential)
	if err != nil {
		return err
	}
	connection, err := encode(input.Connection)
	if err != nil {
		return err
	}
	var alias domain.ProjectAlias
	var priorCredential, priorConnection []byte
	err = tx.QueryRowContext(ctx, "SELECT alias,credential,connection FROM administrative_routes WHERE device=? AND root_guard=? AND project_guard=?", input.Destination.Device, input.Context.Root, input.Context.Project).Scan(&alias, &priorCredential, &priorConnection)
	if err == nil && alias == input.Destination.Project && bytes.Equal(credential, priorCredential) && bytes.Equal(connection, priorConnection) {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO administrative_routes(device,root_guard,project_guard,alias,credential,connection) VALUES(?,?,?,?,?,?) ON CONFLICT(device,root_guard,project_guard) DO UPDATE SET alias=excluded.alias,credential=excluded.credential,connection=excluded.connection`, input.Destination.Device, input.Context.Root, input.Context.Project, input.Destination.Project, credential, connection)
	if err != nil {
		return err
	}
	return invalidateRouteApproval(ctx, tx, input.Destination.Device, input.Context.Root)
}

func invalidateRouteApproval(ctx context.Context, tx *sql.Tx, device domain.DeviceID, root domain.RootGuard) error {
	var id domain.RecoveryID
	err := tx.QueryRowContext(ctx, `SELECT d.recovery FROM recovery_destinations d JOIN recoveries r ON r.id=d.recovery WHERE d.device=? AND d.root_guard=? AND r.status='active'`, device, root).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE recovery_destinations SET approved=0 WHERE recovery=?", id); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE recoveries SET revision=revision+1 WHERE id=?", id)
	return err
}

// A route is current only on the exact credential and socket generation. This
// query counts reservations, including ownerless and unattributed rows.
func missingDestinationMappings(ctx context.Context, tx *sql.Tx, destination domain.RecoveryDestination) (int, error) {
	var missing int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM operations o
	WHERE o.device=? AND o.root_guard=? AND o.reserved=1 AND NOT EXISTS(
	 SELECT 1 FROM administrative_routes a
	 JOIN devices d ON d.id=a.device
	 JOIN credentials c ON c.device=d.id
	 JOIN settings s ON s.id=1
	 JOIN projects p ON p.device=a.device AND p.alias=a.alias AND p.root_guard=a.root_guard AND p.project_guard=a.project_guard
	 WHERE a.device=o.device AND a.root_guard=o.root_guard AND a.project_guard=o.project_guard
	 AND d.revoked=0 AND c.epoch=s.epoch AND c.generation=d.credential_generation
	 AND json_extract(a.credential,'$.Device')=d.id
	 AND json_extract(a.credential,'$.Epoch')=c.epoch
	 AND json_extract(a.credential,'$.Generation')=c.generation
	 AND json_extract(a.connection,'$.BootEpoch')=d.boot
	 AND json_extract(a.connection,'$.Counter')=d.counter)`, destination.Device, destination.Root).Scan(&missing)
	return missing, err
}

func requireRecoveryMappings(ctx context.Context, tx *sql.Tx, id domain.RecoveryID, now time.Time, regular bool, onlyDevice domain.DeviceID) error {
	destinations, err := recoveryMappingDestinations(ctx, tx, id, onlyDevice)
	if err != nil {
		return err
	}
	for _, destination := range destinations {
		missing, readErr := missingDestinationMappings(ctx, tx, destination)
		if readErr != nil {
			return readErr
		}
		if missing != 0 {
			return domain.Reject(domain.Pending)
		}
		if regular {
			if err = regularRecoveryCredential(ctx, tx, destination.Device, now); err != nil {
				return err
			}
		} else if _, err = currentRecoveryCredential(ctx, tx, destination.Device, now); err != nil {
			return err
		}
	}
	return nil
}

func recoveryMappingDestinations(ctx context.Context, tx *sql.Tx, id domain.RecoveryID, onlyDevice domain.DeviceID) (destinations []domain.RecoveryDestination, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT device,root_guard FROM recovery_destinations WHERE recovery=? AND (?='' OR device=?) ORDER BY device,root_guard", id, onlyDevice, onlyDevice)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		destination := domain.RecoveryDestination{Recovery: id}
		if err = rows.Scan(&destination.Device, &destination.Root); err != nil {
			return nil, err
		}
		destinations = append(destinations, destination)
	}
	return destinations, rows.Err()
}
