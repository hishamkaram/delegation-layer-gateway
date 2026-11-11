package registry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sort"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

var errRoutingPending = errors.New("routing roster pending")

// RegisterRoutingRecoveryRoster records the protected operator's complete prior
// device roster under the existing recovery authority. Missing snapshot IDs are
// retained; the present database cannot prove the prior fleet was smaller.
func (s *Store) RegisterRoutingRecoveryRoster(ctx context.Context, id domain.RecoveryID, devices []domain.DeviceID) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if domain.RoutingToken(string(id)) != nil || len(devices) > routing.MaxRecoveryDevices {
		return domain.ErrInvalid
	}
	roster := append([]domain.DeviceID(nil), devices...)
	sort.Slice(roster, func(i, j int) bool { return roster[i] < roster[j] })
	for i, device := range roster {
		if domain.CredentialToken(string(device)) != nil || i > 0 && roster[i-1] == device {
			return domain.ErrInvalid
		}
	}
	data, encodeErr := encode(roster)
	if encodeErr != nil {
		return encodeErr
	}
	digest := domain.Hash(data)
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return registerRoutingRecoveryRoster(ctx, tx, id, roster, digest)
	})
	return err
}

func validateKnownRoutingRoster(ctx context.Context, tx *sql.Tx, roster []domain.DeviceID) (err error) {
	known := make(map[domain.DeviceID]bool, len(roster))
	for _, device := range roster {
		known[device] = true
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM devices UNION SELECT device FROM routing_permits")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var device domain.DeviceID
		if err = rows.Scan(&device); err != nil {
			return err
		}
		if !known[device] {
			return domain.Reject(domain.EvidenceInvalid)
		}
	}
	return rows.Err()
}

func routingRecoveryCovered(ctx context.Context, tx *sql.Tx) error {
	var id domain.RecoveryID
	if err := tx.QueryRowContext(ctx, "SELECT recovery FROM settings WHERE id=1").Scan(&id); err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	var sealed, missing int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM routing_rosters WHERE recovery=?", id).Scan(&sealed); err != nil {
		return err
	}
	if sealed != 1 {
		return errRoutingPending
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM routing_roster_devices WHERE recovery=? AND covered=0", id).Scan(&missing); err != nil {
		return err
	}
	if missing != 0 {
		return errRoutingPending
	}
	return nil
}

func allowRoutingImport(ctx context.Context, tx *sql.Tx, device domain.DeviceID) error {
	var blocked bool
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT blocked FROM settings WHERE id=1").Scan(&blocked); err != nil {
		return err
	}
	if !blocked {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM routing_roster_devices WHERE recovery=(SELECT recovery FROM settings WHERE id=1) AND device=?", device).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return domain.Reject(domain.Pending)
	}
	return nil
}

func coverRoutingRosterDevice(ctx context.Context, tx *sql.Tx, device domain.DeviceID) error {
	_, err := tx.ExecContext(ctx, "UPDATE routing_roster_devices SET covered=1 WHERE recovery=(SELECT recovery FROM settings WHERE id=1) AND device=?", device)
	return err
}

func registerRoutingRecoveryRoster(ctx context.Context, tx *sql.Tx, id domain.RecoveryID, roster []domain.DeviceID, digest domain.Digest) (struct{}, error) {
	if err := activeRecovery(ctx, tx, id, false); err != nil {
		return struct{}{}, err
	}
	var prior []byte
	readErr := tx.QueryRowContext(ctx, "SELECT digest FROM routing_rosters WHERE recovery=?", id).Scan(&prior)
	if readErr == nil {
		if !bytes.Equal(prior, digest[:]) {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		return struct{}{}, nil
	}
	if !errors.Is(readErr, sql.ErrNoRows) {
		return struct{}{}, readErr
	}
	if err := validateKnownRoutingRoster(ctx, tx, roster); err != nil {
		return struct{}{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO routing_rosters(recovery,digest) VALUES(?,?)", id, digest[:]); err != nil {
		return struct{}{}, err
	}
	for _, device := range roster {
		if _, err := tx.ExecContext(ctx, "INSERT INTO routing_roster_devices(recovery,device) VALUES(?,?)", id, device); err != nil {
			return struct{}{}, err
		}
	}
	return struct{}{}, nil
}
