package registry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func selfEnrollmentDigest(input domain.SelfEnrollmentAttempt) (domain.Digest, error) {
	data, err := encode(struct {
		Name               string
		CSR, Key           domain.Digest
		Replace            domain.DeviceID
		ExpectedGeneration uint64
	}{input.Name, input.CSRHash, input.PublicKeyHash, input.ReplaceDevice, input.ExpectedGeneration})
	return domain.Hash(data), err
}

func checkSelfEnrollment(actor domain.Actor, input domain.SelfEnrollmentAttempt) error {
	if actor.Validate() != nil || domain.TaskID(input.Request).Validate() != nil || domain.ValidateDeviceName(input.Name) != nil {
		return domain.ErrInvalid
	}
	if !actor.Scopes.Has(domain.DeviceEnroll) {
		return domain.Reject(domain.Forbidden)
	}
	if input.ReplaceDevice != "" {
		if domain.CredentialToken(string(input.ReplaceDevice)) != nil || input.ExpectedGeneration == 0 || input.ExpectedGeneration >= math.MaxInt64 {
			return domain.ErrInvalid
		}
		if !actor.Scopes.Has(domain.DeviceManage) {
			return domain.Reject(domain.Forbidden)
		}
	} else if input.ExpectedGeneration != 0 {
		return domain.ErrInvalid
	}
	return validateIssuanceAttempt(input.Issuance, input.Serial, input.CSRHash, input.PublicKeyHash, input.Now)
}

// BeginSelfEnrollment receives a verified actor, never administrative authority.
// Request IDs bind the first owner globally; no raw bearer enrollment token is
// minted. Existing issuance remains the sole certificate/generation authority.
func (s *Store) BeginSelfEnrollment(ctx context.Context, actor domain.Actor, input domain.SelfEnrollmentAttempt) (domain.IssuanceIntent, error) {
	if err := checkSelfEnrollment(actor, input); err != nil {
		return domain.IssuanceIntent{}, err
	}
	digest, err := selfEnrollmentDigest(input)
	if err != nil {
		return domain.IssuanceIntent{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.IssuanceIntent, error) {
		policy, err := ownerPolicy(ctx, tx, actor.Principal)
		if err != nil {
			return domain.IssuanceIntent{}, err
		}
		prior, found, err := replaySelfEnrollment(ctx, tx, actor.Principal, input, digest)
		if found || err != nil {
			return prior, err
		}
		device, err := selfEnrollmentDevice(ctx, tx, actor.Principal, input, policy)
		if err != nil {
			return domain.IssuanceIntent{}, err
		}
		attempt := domain.EnrollmentAttempt{CSRHash: input.CSRHash, PublicKeyHash: input.PublicKeyHash, Issuance: input.Issuance, Serial: input.Serial, Now: input.Now}
		intent, err := reserveFreshEnrollment(ctx, tx, attempt, device.ID, domain.Regular, device.CredentialGeneration+1, "self:"+string(input.Request))
		if err != nil {
			return intent, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO self_enrollments(id,principal,digest,device,issuance,expires) VALUES(?,?,?,?,?,?)", input.Request, actor.Principal, digest[:], device.ID, intent.ID, input.Now.Add(domain.EnrollmentTTL).UTC().Format(timestampLayout))
		return intent, err
	})
}

func replaySelfEnrollment(ctx context.Context, tx *sql.Tx, owner domain.PrincipalID, input domain.SelfEnrollmentAttempt, digest domain.Digest) (domain.IssuanceIntent, bool, error) {
	var savedOwner domain.PrincipalID
	var savedDigest []byte
	var issuance domain.IssuanceID
	err := tx.QueryRowContext(ctx, "SELECT principal,digest,issuance FROM self_enrollments WHERE id=?", input.Request).Scan(&savedOwner, &savedDigest, &issuance)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.IssuanceIntent{}, false, nil
	}
	if err != nil {
		return domain.IssuanceIntent{}, false, err
	}
	if owner != savedOwner || !bytes.Equal(savedDigest, digest[:]) {
		return domain.IssuanceIntent{}, true, domain.Reject(domain.Conflict)
	}
	intent, certificate, err := readIntent(ctx, tx, issuance)
	if err != nil {
		return intent, true, err
	}
	device, err := readDevice(ctx, tx, intent.Credential.Device)
	if err != nil {
		return intent, true, err
	}
	if device.Revoked || device.CredentialGeneration != intent.Credential.Generation {
		return intent, true, domain.Reject(domain.Forbidden)
	}
	return intent, true, checkOwnedIssuance(ctx, tx, intent, len(certificate) != 0, input.Now)
}

func selfEnrollmentDevice(ctx context.Context, tx *sql.Tx, principal domain.PrincipalID, input domain.SelfEnrollmentAttempt, policy domain.OwnerPolicy) (domain.Device, error) {
	if input.ReplaceDevice != "" {
		device, err := readDevice(ctx, tx, input.ReplaceDevice)
		if err != nil {
			return device, err
		}
		owner, err := deviceOwner(ctx, tx, device.ID)
		if err != nil {
			return device, err
		}
		if owner != principal || device.Revoked {
			return domain.Device{}, domain.Reject(domain.Forbidden)
		}
		if device.CredentialGeneration != input.ExpectedGeneration || device.Name != input.Name {
			return domain.Device{}, domain.Reject(domain.Conflict)
		}
		if err = requireOwnedDeviceSlot(ctx, tx, principal, device.ID, policy, input.Now); err != nil {
			return domain.Device{}, err
		}
		return device, nil
	}
	return mintOwnedDevice(ctx, tx, principal, input.Name, policy, input.Now)
}

// mintOwnedDevice is the shared atomic new-owner/quota gate for browser and
// private-token bootstrap. Callers keep their issuance in this same transaction.
func mintOwnedDevice(ctx context.Context, tx *sql.Tx, principal domain.PrincipalID, name string, policy domain.OwnerPolicy, now time.Time) (domain.Device, error) {
	if err := requireOwnedDeviceSlot(ctx, tx, principal, "", policy, now); err != nil {
		return domain.Device{}, err
	}
	id, err := mintAdmissionToken()
	if err != nil {
		return domain.Device{}, err
	}
	device := domain.Device{ID: domain.DeviceID(id), Name: name}
	if _, err = tx.ExecContext(ctx, "INSERT INTO devices(id,name) VALUES(?,?)", device.ID, device.Name); err != nil {
		return domain.Device{}, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO device_owners(device,principal) VALUES(?,?)", device.ID, principal)
	return device, err
}

// Count valid credentials and unfinished, unexpired reservations once per
// device. Credential timestamps are decoded as time values, not compared using
// differently formatted RFC3339 text. Expired intents remain replay tombstones.
type ownedDeviceUsage struct {
	count         uint32
	targetCounted bool
}

func readOwnedDeviceUsage(ctx context.Context, tx *sql.Tx, principal domain.PrincipalID, target domain.DeviceID, now time.Time) (usage ownedDeviceUsage, resultErr error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.id,c.value,(EXISTS(SELECT 1 FROM self_enrollments e JOIN issuance i ON i.id=e.issuance WHERE e.device=d.id AND e.expires>? AND i.certificate IS NULL) OR EXISTS(SELECT 1 FROM enrollment e LEFT JOIN issuance i ON i.id=e.issuance WHERE e.device=d.id AND e.expires>? AND i.certificate IS NULL)) FROM device_owners o JOIN devices d ON d.id=o.device LEFT JOIN credentials c ON c.device=d.id WHERE o.principal=? AND d.revoked=0`, now.UTC().Format(timestampLayout), now.UTC().Format(timestampLayout), principal)
	if err != nil {
		return usage, err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	for rows.Next() {
		var device domain.DeviceID
		var data []byte
		var pending bool
		if err = rows.Scan(&device, &data, &pending); err != nil {
			return usage, err
		}
		occupied, occupancyErr := ownedDeviceOccupied(device, data, pending, now)
		if occupancyErr != nil {
			return usage, occupancyErr
		}
		if occupied {
			usage.count++
			usage.targetCounted = usage.targetCounted || device == target
		}
	}
	return usage, rows.Err()
}

func ownedDeviceOccupied(device domain.DeviceID, data []byte, pending bool, now time.Time) (bool, error) {
	if pending {
		return true, nil
	}
	if len(data) == 0 {
		return false, nil
	}
	credential, err := decode[domain.Credential](data)
	if err != nil {
		return false, err
	}
	if credential.Ref.Validate() != nil || credential.Ref.Device != device || credential.NotAfter.IsZero() {
		return false, domain.Reject(domain.EvidenceInvalid)
	}
	return now.Before(credential.NotAfter), nil
}

// Acquiring a previously uncounted device consumes one owner slot. A current
// credential or live bootstrap reservation already holds that same slot.
func requireOwnedDeviceSlot(ctx context.Context, tx *sql.Tx, owner domain.PrincipalID, target domain.DeviceID, policy domain.OwnerPolicy, now time.Time) error {
	usage, err := readOwnedDeviceUsage(ctx, tx, owner, target, now)
	if err != nil {
		return err
	}
	if !usage.targetCounted && usage.count >= policy.MaxDevices {
		return domain.Reject(domain.ResourceLimit)
	}
	return nil
}

func checkOwnedDeviceSlot(ctx context.Context, tx *sql.Tx, device domain.DeviceID, now time.Time) error {
	owner, err := deviceOwner(ctx, tx, device)
	if err != nil || owner == "" {
		return err
	}
	policy, err := ownerPolicy(ctx, tx, owner)
	if err != nil {
		return err
	}
	return requireOwnedDeviceSlot(ctx, tx, owner, device, policy, now)
}

func checkOwnedIssuance(ctx context.Context, tx *sql.Tx, intent domain.IssuanceIntent, committed bool, now time.Time) error {
	if err := checkDeviceOwner(ctx, tx, intent.Credential.Device); err != nil {
		return err
	}
	if committed {
		return nil
	}
	var expires string
	err := tx.QueryRowContext(ctx, "SELECT expires FROM self_enrollments WHERE issuance=?", intent.ID).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return checkOwnedTokenActivation(ctx, tx, intent, now)
	}
	if err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return err
	}
	if !now.Before(deadline) {
		return domain.Reject(domain.Expired)
	}
	return nil
}

func checkOwnedTokenActivation(ctx context.Context, tx *sql.Tx, intent domain.IssuanceIntent, now time.Time) error {
	owner, err := deviceOwner(ctx, tx, intent.Credential.Device)
	if err != nil || owner == "" {
		return err // Legacy unowned token semantics remain unchanged.
	}
	var expires string
	err = tx.QueryRowContext(ctx, "SELECT expires FROM enrollment WHERE issuance=? AND device=?", intent.ID, intent.Credential.Device).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // Certificate renewal has no bootstrap reservation deadline.
	}
	if err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return err
	}
	if !now.Before(deadline) {
		return domain.Reject(domain.Expired)
	}
	return nil
}
