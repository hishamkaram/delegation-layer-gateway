package registry

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

const routingSchema = `
CREATE TABLE IF NOT EXISTS routing_peers(device TEXT PRIMARY KEY, credential BLOB NOT NULL, generation BLOB NOT NULL, boot TEXT NOT NULL, barrier TEXT NOT NULL, digest BLOB NOT NULL, blocked INTEGER NOT NULL, claimed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS routing_permits ` + routingPermitDefinition + `;
` + routingActiveIndex + `;
CREATE TABLE IF NOT EXISTS routing_rosters(recovery TEXT PRIMARY KEY, digest BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS routing_roster_devices(recovery TEXT NOT NULL,device TEXT NOT NULL,covered INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(recovery,device));
`

const routingPermitDefinition = `(device TEXT NOT NULL, connection_boot TEXT NOT NULL, connection_counter INTEGER NOT NULL, request TEXT NOT NULL, process_boot TEXT NOT NULL, credential BLOB NOT NULL, call BLOB NOT NULL, protected INTEGER NOT NULL, scan INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','unpublished','reconciled','admin_drained','settled','not_claimed')), PRIMARY KEY(device,connection_boot,connection_counter,request))`

const routingActiveIndex = `CREATE INDEX routing_permits_active ON routing_permits(device,protected,scan) WHERE state='active'`

type routingPeer struct {
	credential       domain.CredentialRef
	generation       domain.ConnectionGeneration
	boot, barrier    string
	digest           domain.Digest
	blocked, claimed bool
}

func routingGeneration(g protocol.Generation) domain.ConnectionGeneration {
	return domain.ConnectionGeneration{BootEpoch: domain.BootEpoch(g.BootEpoch), Counter: g.Counter}
}

func validateRoutingRequest(input routing.Request) (protocol.Command, error) {
	if input.Credential.Validate() != nil || !routing.ValidProcessBoot(input.ProcessBoot) || input.Call.Validate() != nil || input.Now.IsZero() {
		return protocol.Command{}, domain.ErrInvalid
	}
	digest := domain.Hash(input.Payload)
	if hex.EncodeToString(digest[:]) != input.Call.RequestSHA256 {
		return protocol.Command{}, domain.Reject(domain.EvidenceInvalid)
	}
	command, err := protocol.DecodeCommand(protocol.Frame{Type: protocol.Request, Payload: input.Payload})
	if err != nil || command.Operation != input.Call.Operation {
		return command, domain.ErrInvalid
	}
	return command, nil
}

func readRoutingPeer(ctx context.Context, tx *sql.Tx, device domain.DeviceID) (routingPeer, error) {
	var peer routingPeer
	var credentialData, generationData, digest []byte
	err := tx.QueryRowContext(ctx, "SELECT credential,generation,boot,barrier,digest,blocked,claimed FROM routing_peers WHERE device=?", device).Scan(&credentialData, &generationData, &peer.boot, &peer.barrier, &digest, &peer.blocked, &peer.claimed)
	if err != nil {
		return peer, err
	}
	peer.credential, err = decode[domain.CredentialRef](credentialData)
	if err != nil {
		return peer, err
	}
	peer.generation, err = decode[domain.ConnectionGeneration](generationData)
	if err != nil {
		return peer, err
	}
	if len(digest) != len(peer.digest) || peer.credential.Device != device || peer.credential.Validate() != nil || peer.generation.Validate() != nil || !routing.ValidProcessBoot(peer.boot) {
		return peer, domain.Reject(domain.EvidenceInvalid)
	}
	copy(peer.digest[:], digest)
	return peer, nil
}

func saveRoutingPeer(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, report protocol.ControlInventory, digest domain.Digest, blocked bool) error {
	credentialData, err := encode(ref)
	if err != nil {
		return err
	}
	generationData, err := encode(routingGeneration(report.Generation))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO routing_peers(device,credential,generation,boot,barrier,digest,blocked,claimed) VALUES(?,?,?,?,?,?,?,0) ON CONFLICT(device) DO UPDATE SET credential=excluded.credential,generation=excluded.generation,boot=excluded.boot,barrier=excluded.barrier,digest=excluded.digest,blocked=excluded.blocked,claimed=0`, ref.Device, credentialData, generationData, report.ProcessBoot, report.BarrierID, digest[:], blocked)
	return err
}

func routingCounts(ctx context.Context, tx *sql.Tx, device domain.DeviceID) (ordinary, protected, scanOrdinary, scanProtected, deviceScan int, err error) {
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(protected=0),0),COALESCE(SUM(protected=1),0),COALESCE(SUM(protected=0 AND scan=1),0),COALESCE(SUM(protected=1 AND scan=1),0),COALESCE(SUM(device=? AND scan=1),0) FROM routing_permits WHERE state='active'`, device).Scan(&ordinary, &protected, &scanOrdinary, &scanProtected, &deviceScan)
	return
}

func routingStatus(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, generation domain.ConnectionGeneration) (routing.Readiness, error) {
	peer, err := readRoutingPeer(ctx, tx, ref.Device)
	if errors.Is(err, sql.ErrNoRows) {
		return routing.Readiness{Reason: routing.HandshakeRequired, Generation: generation}, nil
	}
	if err != nil {
		return routing.Readiness{}, err
	}
	result := routing.Readiness{ProcessBoot: peer.boot, Generation: generation}
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM routing_permits WHERE device=? AND state='active'", ref.Device).Scan(&result.Outstanding); err != nil {
		return result, err
	}
	if peer.generation != generation || peer.credential != ref {
		result.Reason = routing.HandshakeRequired
		return result, nil
	}
	if peer.blocked {
		result.Reason = routing.ProcessChanged
		return result, nil
	}
	ordinary, protected, scanOrdinary, scanProtected, deviceScan, err := routingCounts(ctx, tx, ref.Device)
	if err != nil {
		return result, err
	}
	if ordinary > routing.MaxOrdinaryPermits || protected > routing.MaxProtectedPermits || scanOrdinary > routing.MaxOrdinaryScans || scanProtected > routing.MaxProtectedScans || deviceScan > routing.MaxDeviceScans {
		result.Reason = routing.CapacityExceeded
		return result, nil
	}
	if err = routingRecoveryCovered(ctx, tx); err != nil {
		if errors.Is(err, errRoutingPending) {
			result.Reason = routing.RecoveryPending
			return result, nil
		}
		return result, err
	}
	result.Ready = true
	return result, nil
}

func (s *Store) CheckRoutingReadiness(ctx context.Context, ref domain.CredentialRef, generation domain.ConnectionGeneration, now time.Time) (routing.Readiness, error) {
	return transaction(ctx, s, func(tx *sql.Tx) (routing.Readiness, error) {
		if _, err := checkConnection(ctx, tx, ref, generation, now); err != nil {
			return routing.Readiness{}, err
		}
		return routingStatus(ctx, tx, ref, generation)
	})
}

func insertRoutingPermit(ctx context.Context, tx *sql.Tx, input routing.Request) error {
	credentialData, err := encode(input.Credential)
	if err != nil {
		return err
	}
	callData, err := encode(input.Call)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO routing_permits(device,connection_boot,connection_counter,request,process_boot,credential,call,protected,scan,state) VALUES(?,?,?,?,?,?,?,?,?,'active')`, input.Credential.Device, input.Call.Generation.BootEpoch, input.Call.Generation.Counter, input.Call.RequestID, input.ProcessBoot, credentialData, callData, input.Call.Operation.ProtectedControl(), input.Call.Operation.ScanConsumer())
	return err
}

func (s *Store) acquireRouting(ctx context.Context, tx *sql.Tx, input routing.Request) error {
	generation := routingGeneration(input.Call.Generation)
	credential, err := checkConnection(ctx, tx, input.Credential, generation, input.Now)
	if err != nil {
		return err
	}
	if credential.Mode == domain.RecoveryOnly && !input.Call.Operation.AllowedRecoveryOnly() {
		return domain.Reject(domain.Forbidden)
	}
	status, err := routingStatus(ctx, tx, input.Credential, generation)
	if err != nil {
		return err
	}
	if err = s.authorizeRoutingReadiness(ctx, input.Call.Operation, status); err != nil {
		return err
	}
	if status.ProcessBoot != input.ProcessBoot {
		return domain.Reject(domain.Conflict)
	}
	var exists int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM routing_permits WHERE device=? AND connection_boot=? AND connection_counter=? AND request=?", input.Credential.Device, input.Call.Generation.BootEpoch, input.Call.Generation.Counter, input.Call.RequestID).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return domain.Reject(domain.Conflict)
	}
	if err = checkRoutingCapacity(ctx, tx, input); err != nil {
		return err
	}
	if err = insertRoutingPermit(ctx, tx, input); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE routing_peers SET claimed=1 WHERE device=?", input.Credential.Device)
	return err
}

func checkRoutingCapacity(ctx context.Context, tx *sql.Tx, input routing.Request) error {
	ordinary, protected, scanOrdinary, scanProtected, deviceScan, err := routingCounts(ctx, tx, input.Credential.Device)
	if err != nil {
		return err
	}
	if input.Call.Operation.ProtectedControl() {
		if protected >= routing.MaxProtectedPermits || input.Call.Operation.ScanConsumer() && scanProtected >= routing.MaxProtectedScans {
			return domain.Reject(domain.ResourceLimit)
		}
	} else if ordinary >= routing.MaxOrdinaryPermits || input.Call.Operation.ScanConsumer() && scanOrdinary >= routing.MaxOrdinaryScans {
		return domain.Reject(domain.ResourceLimit)
	}
	if input.Call.Operation.ScanConsumer() && deviceScan >= routing.MaxDeviceScans {
		return domain.Reject(domain.ResourceLimit)
	}
	return nil
}

// AcquireRouting prepares non-admission controls. Only a newly acquired key may
// enter the transport buffer; duplicate and completed keys never acquire again.
func (s *Store) AcquireRouting(ctx context.Context, input routing.Request) error {
	if _, err := validateRoutingRequest(input); err != nil {
		return err
	}
	if input.Call.Operation == protocol.Admit {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) { return struct{}{}, s.acquireRouting(ctx, tx, input) })
	return err
}

// Full routing coverage precedes every routed CLI control. Fenced census and
// protected local drain attestations establish that coverage without CLI slots.
func (s *Store) authorizeRoutingReadiness(ctx context.Context, operation protocol.Operation, status routing.Readiness) error {
	if !status.Ready {
		return domain.Reject(domain.Pending)
	}
	if operation.Administrative() {
		return s.requireAdmin(ctx)
	}
	return nil
}
