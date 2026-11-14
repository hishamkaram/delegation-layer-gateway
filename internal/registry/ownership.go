package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// These tables extend authorization, not task state. Only Registry writes them.
// Legacy devices have no device_owners row and keep explicit-grant semantics.
const ownershipSchema = `
CREATE TABLE IF NOT EXISTS owner_policies (principal TEXT PRIMARY KEY REFERENCES principals(id), value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS device_owners (device TEXT PRIMARY KEY REFERENCES devices(id), principal TEXT NOT NULL REFERENCES principals(id));
CREATE INDEX IF NOT EXISTS device_owners_principal ON device_owners(principal,device);
CREATE TABLE IF NOT EXISTS self_enrollments (id TEXT PRIMARY KEY, principal TEXT NOT NULL REFERENCES principals(id), digest BLOB NOT NULL, device TEXT NOT NULL REFERENCES devices(id), issuance TEXT NOT NULL UNIQUE REFERENCES issuance(id), expires TEXT NOT NULL);
PRAGMA user_version=8;
`

// Inventory and operation projections share the same mutually exclusive owner
// versus legacy-grant branches. LEFT JOIN preserves zero-project owned devices.
const effectiveAccessCTE = `WITH effective_access AS (
 SELECT g.principal,g.device,g.project,json_extract(g.value,'$.Scopes') AS scopes
 FROM grants g WHERE NOT EXISTS(SELECT 1 FROM device_owners o WHERE o.device=g.device)
 UNION ALL
 SELECT o.principal,o.device,p.alias,json_extract(policy.value,'$.Scopes') AS scopes
 FROM device_owners o JOIN owner_policies policy ON policy.principal=o.principal
 LEFT JOIN projects p ON p.device=o.device
 WHERE json_extract(policy.value,'$.Enabled')=1
) `

func verifyOwnershipSchema(ctx context.Context, tx *sql.Tx) error {
	for _, query := range []string{
		"SELECT principal,value FROM owner_policies LIMIT 0",
		"SELECT device,principal FROM device_owners LIMIT 0",
		"SELECT id,principal,digest,device,issuance,expires FROM self_enrollments LIMIT 0",
	} {
		if err := verifyRegistryQuery(ctx, tx, query); err != nil {
			return err
		}
	}
	return nil
}

// PutOwnerPolicy is private administration; authenticating a user cannot call
// this path or materialize eligibility. Disablement preserves ownership/history.
func (s *Store) PutOwnerPolicy(ctx context.Context, principal domain.PrincipalID, policy domain.OwnerPolicy) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if domain.Token(string(principal)) != nil || policy.Validate() != nil {
		return domain.ErrInvalid
	}
	data, err := encode(policy)
	if err != nil {
		return err
	}
	_, err = transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if checkErr := checkPrincipal(ctx, tx, principal); checkErr != nil {
			return struct{}{}, checkErr
		}
		_, writeErr := tx.ExecContext(ctx, "INSERT INTO owner_policies(principal,value) VALUES(?,?) ON CONFLICT(principal) DO UPDATE SET value=excluded.value", principal, data)
		return struct{}{}, writeErr
	})
	return err
}

func ownerPolicy(ctx context.Context, tx *sql.Tx, principal domain.PrincipalID) (domain.OwnerPolicy, error) {
	if err := checkPrincipal(ctx, tx, principal); err != nil {
		return domain.OwnerPolicy{}, err
	}
	policy, err := readOwnerPolicy(ctx, tx, principal)
	if err != nil {
		return policy, err
	}
	if !policy.Enabled {
		return domain.OwnerPolicy{}, domain.Reject(domain.Forbidden)
	}
	return policy, nil
}

func readOwnerPolicy(ctx context.Context, tx *sql.Tx, principal domain.PrincipalID) (domain.OwnerPolicy, error) {
	var data []byte
	if err := tx.QueryRowContext(ctx, "SELECT value FROM owner_policies WHERE principal=?", principal).Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.OwnerPolicy{}, domain.Reject(domain.Forbidden)
		}
		return domain.OwnerPolicy{}, err
	}
	policy, err := decode[domain.OwnerPolicy](data)
	if err != nil {
		return policy, err
	}
	if policy.Validate() != nil {
		return domain.OwnerPolicy{}, domain.Reject(domain.EvidenceInvalid)
	}
	return policy, nil
}

// ReadOwnerPolicy is a private administrative observation, including disabled
// policies. Public authorization always goes through ownerPolicy instead.
func (s *Store) ReadOwnerPolicy(ctx context.Context, principal domain.PrincipalID) (domain.OwnerPolicy, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.OwnerPolicy{}, err
	}
	if domain.Token(string(principal)) != nil {
		return domain.OwnerPolicy{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.OwnerPolicy, error) {
		return readOwnerPolicy(ctx, tx, principal)
	})
}

// DisableOwnerPolicy preserves ownership, ceilings and task history. A revoked
// principal can still be disabled, so later unrevocation cannot restore access.
func (s *Store) DisableOwnerPolicy(ctx context.Context, principal domain.PrincipalID) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if domain.Token(string(principal)) != nil {
		return domain.ErrInvalid
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		policy, err := readOwnerPolicy(ctx, tx, principal)
		if err != nil {
			return struct{}{}, err
		}
		policy.Enabled = false
		data, err := encode(policy)
		if err != nil {
			return struct{}{}, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE owner_policies SET value=? WHERE principal=?", data, principal)
		return struct{}{}, err
	})
	return err
}

func deviceOwner(ctx context.Context, tx *sql.Tx, device domain.DeviceID) (domain.PrincipalID, error) {
	var owner domain.PrincipalID
	err := tx.QueryRowContext(ctx, "SELECT principal FROM device_owners WHERE device=?", device).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil // Absence means legacy; errors never become legacy fallback.
	}
	return owner, err
}

func checkDeviceOwner(ctx context.Context, tx *sql.Tx, device domain.DeviceID) error {
	owner, err := deviceOwner(ctx, tx, device)
	if err != nil || owner == "" {
		return err
	}
	_, err = ownerPolicy(ctx, tx, owner)
	return err
}

func authorizeOwned(ctx context.Context, tx *sql.Tx, request domain.AuthorizationRequest, owner domain.PrincipalID) (domain.Authorization, error) {
	if owner != request.Actor.Principal {
		return domain.Authorization{}, domain.Reject(domain.NotFound)
	}
	policy, err := ownerPolicy(ctx, tx, owner)
	if err != nil {
		return domain.Authorization{}, err
	}
	if _, err = readContext(ctx, tx, request.Destination); err != nil {
		return domain.Authorization{}, err
	}
	grant, err := domain.OwnerGrant(owner, policy, request)
	return domain.Authorization{Principal: owner, Destination: request.Destination, Grant: grant}, err
}

// RevokeOwnedDevice invalidates Registry authorization atomically. Composition
// disconnects the socket after commit; network cleanup is not a SQL transaction
// and a failed close cannot make the old generation authoritative again.
func (s *Store) RevokeOwnedDevice(ctx context.Context, actor domain.Actor, device domain.DeviceID) error {
	if actor.Validate() != nil || domain.CredentialToken(string(device)) != nil {
		return domain.ErrInvalid
	}
	if !actor.Scopes.Has(domain.DeviceManage) {
		return domain.Reject(domain.Forbidden)
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if _, err := ownerPolicy(ctx, tx, actor.Principal); err != nil {
			return struct{}{}, err
		}
		owner, err := deviceOwner(ctx, tx, device)
		if err != nil {
			return struct{}{}, err
		}
		if owner == "" || owner != actor.Principal {
			return struct{}{}, domain.Reject(domain.NotFound)
		}
		return struct{}{}, changeDeviceRevocation(ctx, tx, device, true)
	})
	return err
}
