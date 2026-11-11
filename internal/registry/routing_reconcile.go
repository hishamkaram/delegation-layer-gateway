package registry

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type routingPermit struct {
	credential  domain.CredentialRef
	call        protocol.ControlCall
	boot, state string
}

func readRoutingPermit(ctx context.Context, tx *sql.Tx, device domain.DeviceID, call protocol.ControlCall) (routingPermit, error) {
	var row routingPermit
	var credentialData, callData []byte
	err := tx.QueryRowContext(ctx, "SELECT credential,call,process_boot,state FROM routing_permits WHERE device=? AND connection_boot=? AND connection_counter=? AND request=?", device, call.Generation.BootEpoch, call.Generation.Counter, call.RequestID).Scan(&credentialData, &callData, &row.boot, &row.state)
	if err != nil {
		return row, err
	}
	row.credential, err = decode[domain.CredentialRef](credentialData)
	if err != nil {
		return row, err
	}
	row.call, err = decode[protocol.ControlCall](callData)
	if err == nil && (row.credential.Device != device || row.credential.Validate() != nil || row.call.Validate() != nil || !routing.ValidProcessBoot(row.boot)) {
		err = domain.Reject(domain.EvidenceInvalid)
	}
	return row, err
}

func changeRoutingState(ctx context.Context, tx *sql.Tx, device domain.DeviceID, call protocol.ControlCall, state string) error {
	_, err := tx.ExecContext(ctx, "UPDATE routing_permits SET state=? WHERE device=? AND connection_boot=? AND connection_counter=? AND request=?", state, device, call.Generation.BootEpoch, call.Generation.Counter, call.RequestID)
	return err
}

// ReconcileRouting accepts only a complete fenced handshake for the current
// authenticated generation. It never treats socket closure as control closure.
func (s *Store) ReconcileRouting(ctx context.Context, ref domain.CredentialRef, report protocol.ControlInventory, now time.Time) (routing.Readiness, error) {
	if ref.Validate() != nil || report.Validate() != nil || now.IsZero() {
		return routing.Readiness{}, domain.ErrInvalid
	}
	data, err := encode(report)
	if err != nil {
		return routing.Readiness{}, err
	}
	digest := domain.Hash(data)
	return transaction(ctx, s, func(tx *sql.Tx) (routing.Readiness, error) {
		return reconcileRouting(ctx, tx, ref, report, digest, now)
	})
}

func hasOtherRoutingBoot(ctx context.Context, tx *sql.Tx, device domain.DeviceID, boot string) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM routing_permits WHERE device=? AND process_boot<>? AND state='active'", device, boot).Scan(&count)
	return count != 0, err
}

func reconcileRoutingCalls(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, report protocol.ControlInventory, previousFrontier uint64) error {
	active := make(map[protocol.ControlCall]bool, len(report.Active))
	for _, call := range report.Active {
		if call.Generation.BootEpoch == report.Generation.BootEpoch && call.Generation.Counter >= report.Generation.Counter {
			return domain.Reject(domain.EvidenceInvalid)
		}
		if err := reconcileAdvertisedCall(ctx, tx, ref, report.ProcessBoot, call, previousFrontier); err != nil {
			return err
		}
		active[call] = true
	}
	calls, err := activeRoutingCalls(ctx, tx, ref.Device, report.ProcessBoot)
	if err != nil {
		return err
	}
	for _, call := range calls {
		if call.Generation == report.Generation {
			return domain.Reject(domain.EvidenceInvalid)
		}
		if !active[call] {
			if err = changeRoutingState(ctx, tx, ref.Device, call, "reconciled"); err != nil {
				return err
			}
		}
	}
	return nil
}

func activeRoutingCalls(ctx context.Context, tx *sql.Tx, device domain.DeviceID, boot string) (calls []protocol.ControlCall, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT call FROM routing_permits WHERE device=? AND process_boot=? AND state='active'", device, boot)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var data []byte
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		call, decodeErr := decode[protocol.ControlCall](data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if call.Validate() != nil {
			return nil, domain.Reject(domain.EvidenceInvalid)
		}
		calls = append(calls, call)
	}
	return calls, rows.Err()
}

func (s *Store) CompleteRouting(ctx context.Context, ref domain.CredentialRef, current domain.ConnectionGeneration, completion protocol.ControlCompletion, now time.Time) error {
	if completion.Validate() != nil || ref.Validate() != nil || current.Validate() != nil || now.IsZero() {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return completeRoutingTransaction(ctx, tx, ref, current, completion, now)
	})
	return err
}

// ReleaseUnpublishedRouting is called only by the owner of an actual transport
// buffer that proves no write was possible. Timeout/socket cleanup never calls it.
func (s *Store) ReleaseUnpublishedRouting(ctx context.Context, input routing.Request) error {
	if _, err := validateRoutingRequest(input); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if _, err := checkConnection(ctx, tx, input.Credential, routingGeneration(input.Call.Generation), input.Now); err != nil {
			return struct{}{}, err
		}
		permit, err := readRoutingPermit(ctx, tx, input.Credential.Device, input.Call)
		if err != nil {
			return struct{}{}, notFound(err)
		}
		if permit.credential != input.Credential || permit.boot != input.ProcessBoot || permit.call != input.Call {
			return struct{}{}, domain.Reject(domain.EvidenceInvalid)
		}
		if permit.state == "unpublished" {
			return struct{}{}, nil
		}
		if permit.state != "active" {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		return struct{}{}, changeRoutingState(ctx, tx, input.Credential.Device, input.Call, "unpublished")
	})
	return err
}

func reconcileRouting(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, report protocol.ControlInventory, digest domain.Digest, now time.Time) (routing.Readiness, error) {
	generation := routingGeneration(report.Generation)
	if _, err := checkConnection(ctx, tx, ref, generation, now); err != nil {
		return routing.Readiness{}, err
	}
	prior, err := readRoutingPeer(ctx, tx, ref.Device)
	known := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return routing.Readiness{}, err
	}
	replay, replayErr := routingReportReplay(prior, known, ref, report, digest)
	if replayErr != nil {
		return routing.Readiness{}, replayErr
	}
	if replay {
		return routingStatus(ctx, tx, ref, generation)
	}
	blocked, err := routingCensusBlocked(ctx, tx, ref.Device, prior, known, report.ProcessBoot)
	if err != nil {
		return routing.Readiness{}, err
	}
	if blocked && len(report.Active) != 0 {
		return routing.Readiness{}, domain.Reject(domain.EvidenceInvalid)
	}
	if !blocked {
		if err = reconcileRoutingCalls(ctx, tx, ref, report, prior.generation.Counter); err != nil {
			return routing.Readiness{}, err
		}
		if err = coverRoutingRosterDevice(ctx, tx, ref.Device); err != nil {
			return routing.Readiness{}, err
		}
	}
	if err = saveRoutingPeer(ctx, tx, ref, report, digest, blocked); err != nil {
		return routing.Readiness{}, err
	}
	if err = compactRoutingPermits(ctx, tx, ref.Device, generation.Counter); err != nil {
		return routing.Readiness{}, err
	}
	return routingStatus(ctx, tx, ref, generation)
}

func routingCensusBlocked(ctx context.Context, tx *sql.Tx, device domain.DeviceID, prior routingPeer, known bool, boot string) (bool, error) {
	changed, err := hasOtherRoutingBoot(ctx, tx, device, boot)
	if err != nil {
		return false, err
	}
	if changed || (known && prior.blocked) {
		return true, nil
	}
	_, covered, restoring, err := routingRestoreState(ctx, tx, device)
	if err != nil {
		return false, err
	}
	return restoring && !covered && (!known || prior.boot != boot), nil
}

func routingReportReplay(prior routingPeer, known bool, ref domain.CredentialRef, report protocol.ControlInventory, digest domain.Digest) (bool, error) {
	if !known {
		return false, nil
	}
	if prior.generation != routingGeneration(report.Generation) {
		return false, nil
	}
	if prior.boot != report.ProcessBoot || prior.barrier != report.BarrierID || prior.digest != digest || prior.credential != ref {
		return false, domain.Reject(domain.Conflict)
	}
	return true, nil
}

func reconcileAdvertisedCall(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, boot string, call protocol.ControlCall, previousFrontier uint64) error {
	known, err := readRoutingPermit(ctx, tx, ref.Device, call)
	if errors.Is(err, sql.ErrNoRows) {
		if call.Generation.Counter < previousFrontier {
			return domain.Reject(domain.EvidenceInvalid)
		}
		if err = allowRoutingImport(ctx, tx, ref.Device); err != nil {
			return err
		}
		return insertRoutingPermit(ctx, tx, routing.Request{Credential: ref, ProcessBoot: boot, Call: call})
	}
	if err != nil {
		return err
	}
	if known.call != call || known.boot != boot || known.state != "active" {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func completeRoutingTransaction(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, current domain.ConnectionGeneration, completion protocol.ControlCompletion, now time.Time) (struct{}, error) {
	if _, err := checkConnection(ctx, tx, ref, current, now); err != nil {
		return struct{}{}, err
	}
	peer, err := readRoutingPeer(ctx, tx, ref.Device)
	if err != nil {
		return struct{}{}, notFound(err)
	}
	if peer.generation != current || peer.credential != ref || peer.boot != completion.ProcessBoot || peer.blocked {
		return struct{}{}, domain.Reject(domain.Conflict)
	}
	permit, err := readRoutingPermit(ctx, tx, ref.Device, completion.Call)
	staleTerminal := completion.Call.Generation.Counter < peer.generation.Counter && completion.Disposition != protocol.ControlPending
	if errors.Is(err, sql.ErrNoRows) && staleTerminal {
		return struct{}{}, nil
	}
	if err != nil {
		return struct{}{}, notFound(err)
	}
	// Closed older observations are acknowledged identically before and after
	// compaction. This establishes no historical fingerprint or task closure.
	if permit.state != "active" && staleTerminal {
		return struct{}{}, nil
	}
	return struct{}{}, applyRoutingCompletion(ctx, tx, ref, peer, permit, completion)
}

func applyRoutingCompletion(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, peer routingPeer, permit routingPermit, completion protocol.ControlCompletion) error {
	if permit.call != completion.Call || permit.boot != completion.ProcessBoot || permit.credential != ref {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if completion.Disposition == protocol.ControlPending {
		if permit.state != "active" {
			return domain.Reject(domain.Conflict)
		}
		return nil
	}
	if permit.state != "active" {
		if permit.state == string(completion.Disposition) {
			return nil
		}
		return domain.Reject(domain.Conflict)
	}
	if err := changeRoutingState(ctx, tx, ref.Device, completion.Call, string(completion.Disposition)); err != nil {
		return err
	}
	return compactRoutingPermits(ctx, tx, ref.Device, peer.generation.Counter)
}

func compactRoutingPermits(ctx context.Context, tx *sql.Tx, device domain.DeviceID, frontier uint64) error {
	// Schema 7 constrains every non-active state to a proven closed control.
	_, err := tx.ExecContext(ctx, "DELETE FROM routing_permits WHERE device=? AND connection_counter<? AND state<>'active'", device, frontier)
	return err
}
