package registry

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// ResolvePrincipal materializes only an identity mapping, never a grant. The
// identity adapter must verify issuer/subject before this lookup; existing
// denylist entries are retained and cannot be bypassed by a subsequent login.
func (s *Store) ResolvePrincipal(ctx context.Context, subject domain.ExternalSubject) (domain.Principal, error) {
	if err := subject.Validate(); err != nil {
		return domain.Principal{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.Principal, error) {
		p := domain.Principal{Subject: subject}
		err := tx.QueryRowContext(ctx, "SELECT id,revoked FROM principals WHERE issuer=? AND subject=?", subject.Issuer, subject.Subject).Scan(&p.ID, &p.Revoked)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return p, err
		}
		var entropy [32]byte
		if _, err = rand.Read(entropy[:]); err != nil {
			return p, fmt.Errorf("principal identity: %w", err)
		}
		p.ID = domain.PrincipalID(hex.EncodeToString(entropy[:]))
		_, err = tx.ExecContext(ctx, "INSERT INTO principals(id,issuer,subject) VALUES(?,?,?)", p.ID, subject.Issuer, subject.Subject)
		return p, err
	})
}

func (s *Store) SetPrincipalRevoked(ctx context.Context, id domain.PrincipalID, revoked bool) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := domain.Token(string(id)); err != nil {
		return err
	}
	return s.changePrincipalRevocation(ctx, id, revoked)
}

func (s *Store) changePrincipalRevocation(ctx context.Context, id domain.PrincipalID, revoked bool) error {
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		result, err := tx.ExecContext(ctx, "UPDATE principals SET revoked=? WHERE id=?", revoked, id)
		if err != nil {
			return struct{}{}, err
		}
		count, err := result.RowsAffected()
		if err == nil && count == 0 {
			err = domain.Reject(domain.NotFound)
		}
		return struct{}{}, err
	})
	return err
}

func (s *Store) RegisterDevice(ctx context.Context, input domain.DeviceRegistration) (domain.Device, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.Device{}, err
	}
	if err := domain.CredentialToken(string(input.ID)); err != nil {
		return domain.Device{}, err
	}
	if len(input.Name) > 256 || strings.TrimSpace(input.Name) == "" || !utf8.ValidString(input.Name) {
		return domain.Device{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.Device, error) {
		_, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO devices(id,name) VALUES(?,?)", input.ID, input.Name)
		if err != nil {
			return domain.Device{}, err
		}
		device, err := readDevice(ctx, tx, input.ID)
		if err == nil && device.Name != input.Name {
			err = domain.Reject(domain.Conflict)
		}
		return device, err
	})
}

func readDevice(ctx context.Context, tx *sql.Tx, id domain.DeviceID) (domain.Device, error) {
	device := domain.Device{ID: id}
	err := tx.QueryRowContext(ctx, "SELECT name,revoked,credential_generation,counter FROM devices WHERE id=?", id).Scan(&device.Name, &device.Revoked, &device.CredentialGeneration, &device.ConnectionCounter)
	return device, notFound(err)
}

func (s *Store) RegisterProject(ctx context.Context, input domain.ProjectRegistration) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := input.Validate(); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if _, err := readDevice(ctx, tx, input.Destination.Device); err != nil {
			return struct{}{}, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO projects(device,alias,root_guard,project_guard) VALUES(?,?,?,?)", input.Destination.Device, input.Destination.Project, input.Context.Root, input.Context.Project); err != nil {
			return struct{}{}, err
		}
		binding, err := readContext(ctx, tx, input.Destination)
		if err != nil {
			return struct{}{}, err
		}
		if binding != input.Context {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO root_admissions(device,root_guard) VALUES(?,?)", input.Destination.Device, input.Context.Root)
		return struct{}{}, err
	})
	return err
}

func readContext(ctx context.Context, tx *sql.Tx, destination domain.Destination) (domain.ContextBinding, error) {
	var binding domain.ContextBinding
	err := tx.QueryRowContext(ctx, "SELECT root_guard,project_guard FROM projects WHERE device=? AND alias=?", destination.Device, destination.Project).Scan(&binding.Root, &binding.Project)
	if err != nil {
		return binding, notFound(err)
	}
	return binding, binding.Validate()
}

func (s *Store) SetDeviceRevoked(ctx context.Context, id domain.DeviceID, revoked bool) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := domain.Token(string(id)); err != nil {
		return err
	}
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return struct{}{}, changeDeviceRevocation(ctx, tx, id, revoked)
	})
	return err
}

func changeDeviceRevocation(ctx context.Context, tx *sql.Tx, id domain.DeviceID, revoked bool) error {
	device, err := readDevice(ctx, tx, id)
	if err != nil || device.Revoked == revoked {
		return err
	}
	if device.CredentialGeneration >= math.MaxInt64 {
		return domain.Reject(domain.ResourceLimit)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE devices SET revoked=?,credential_generation=credential_generation+1 WHERE id=?", revoked, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM credentials WHERE device=?", id); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM enrollment WHERE device=?", id)
	return err
}

func validateGrantKey(key domain.GrantKey) error {
	if err := domain.Token(string(key.Principal)); err != nil {
		return err
	}
	return key.Destination.Validate()
}

func (s *Store) PutGrant(ctx context.Context, grant domain.Grant) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := grant.Validate(); err != nil {
		return err
	}
	value, err := encode(grant)
	if err != nil {
		return err
	}
	_, err = transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if principalErr := checkPrincipal(ctx, tx, grant.Key.Principal); principalErr != nil {
			return struct{}{}, principalErr
		}
		device, deviceErr := readDevice(ctx, tx, grant.Key.Destination.Device)
		if deviceErr != nil {
			return struct{}{}, deviceErr
		}
		if device.Revoked {
			return struct{}{}, domain.Reject(domain.Forbidden)
		}
		owner, ownerErr := deviceOwner(ctx, tx, device.ID)
		if ownerErr != nil {
			return struct{}{}, ownerErr
		}
		if owner != "" {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO grants(principal,device,project,value) VALUES(?,?,?,?) ON CONFLICT(principal,device,project) DO UPDATE SET value=excluded.value", grant.Key.Principal, grant.Key.Destination.Device, grant.Key.Destination.Project, value)
		return struct{}{}, err
	})
	return err
}

func (s *Store) RevokeGrant(ctx context.Context, key domain.GrantKey) error {
	if err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validateGrantKey(key); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM grants WHERE principal=? AND device=? AND project=?", key.Principal, key.Destination.Device, key.Destination.Project)
	return err
}

func checkPrincipal(ctx context.Context, tx *sql.Tx, id domain.PrincipalID) error {
	var revoked bool
	err := tx.QueryRowContext(ctx, "SELECT revoked FROM principals WHERE id=?", id).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && revoked) {
		return domain.Reject(domain.Forbidden)
	}
	return err
}

func authorize(ctx context.Context, tx *sql.Tx, request domain.AuthorizationRequest) (domain.Authorization, error) {
	var result domain.Authorization
	if err := request.Validate(); err != nil {
		return result, err
	}
	if err := checkPrincipal(ctx, tx, request.Actor.Principal); err != nil {
		return result, err
	}
	device, err := readDevice(ctx, tx, request.Destination.Device)
	if err != nil {
		return result, err
	}
	if device.Revoked {
		return result, domain.Reject(domain.NotFound)
	}
	owner, err := deviceOwner(ctx, tx, device.ID)
	if err != nil {
		return result, err
	}
	if owner != "" {
		return authorizeOwned(ctx, tx, request, owner)
	}
	var value []byte
	err = tx.QueryRowContext(ctx, "SELECT value FROM grants WHERE principal=? AND device=? AND project=?", request.Actor.Principal, request.Destination.Device, request.Destination.Project).Scan(&value)
	if err != nil {
		return result, notFound(err)
	}
	grant, err := decode[domain.Grant](value)
	if err != nil {
		return result, err
	}
	if grant.Key.Principal != request.Actor.Principal || grant.Key.Destination != request.Destination {
		return result, domain.Reject(domain.EvidenceInvalid)
	}
	if err = grant.Validate(); err != nil {
		return result, err
	}
	if !grant.Scopes.Has(request.Scope) {
		return result, domain.Reject(domain.NotFound)
	}
	return domain.Authorization{Principal: request.Actor.Principal, Destination: request.Destination, Grant: grant}, nil
}

func (s *Store) Authorize(ctx context.Context, request domain.AuthorizationRequest) (domain.Authorization, error) {
	return transaction(ctx, s, func(tx *sql.Tx) (domain.Authorization, error) { return authorize(ctx, tx, request) })
}

func credential(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, now time.Time) (domain.Credential, error) {
	if err := ref.Validate(); err != nil {
		return domain.Credential{}, err
	}
	if now.IsZero() {
		return domain.Credential{}, domain.ErrInvalid
	}
	device, err := readDevice(ctx, tx, ref.Device)
	if err != nil {
		return domain.Credential{}, err
	}
	var epoch domain.CredentialEpoch
	if err = tx.QueryRowContext(ctx, "SELECT epoch FROM settings WHERE id=1").Scan(&epoch); err != nil {
		return domain.Credential{}, err
	}
	if device.Revoked || ref.Epoch != epoch || ref.Generation != device.CredentialGeneration {
		return domain.Credential{}, domain.Reject(domain.Forbidden)
	}
	if err = checkDeviceOwner(ctx, tx, device.ID); err != nil {
		return domain.Credential{}, err
	}
	return readCredential(ctx, tx, ref, now)
}

func readCredential(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, now time.Time) (domain.Credential, error) {
	var value []byte
	if err := tx.QueryRowContext(ctx, "SELECT value FROM credentials WHERE device=? AND epoch=? AND generation=?", ref.Device, ref.Epoch, ref.Generation).Scan(&value); err != nil {
		return domain.Credential{}, notFound(err)
	}
	result, err := decode[domain.Credential](value)
	if err != nil {
		return result, err
	}
	if result.Ref != ref {
		return result, domain.Reject(domain.EvidenceInvalid)
	}
	if err = result.Mode.Validate(); err != nil {
		return result, err
	}
	if err = result.PublicKeyHash.Validate(); err != nil {
		return result, err
	}
	if now.Before(result.NotBefore) || !now.Before(result.NotAfter) {
		return result, domain.Reject(domain.Expired)
	}
	return result, nil
}

func (s *Store) CheckCredential(ctx context.Context, ref domain.CredentialRef, now time.Time) (domain.Credential, error) {
	return transaction(ctx, s, func(tx *sql.Tx) (domain.Credential, error) { return credential(ctx, tx, ref, now) })
}

func (s *Store) NextConnectionGeneration(ctx context.Context, ref domain.CredentialRef, boot domain.BootEpoch, now time.Time) (domain.ConnectionGeneration, error) {
	if err := domain.Token(string(boot)); err != nil {
		return domain.ConnectionGeneration{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.ConnectionGeneration, error) {
		if _, err := credential(ctx, tx, ref, now); err != nil {
			return domain.ConnectionGeneration{}, err
		}
		device, err := readDevice(ctx, tx, ref.Device)
		if err != nil {
			return domain.ConnectionGeneration{}, err
		}
		if device.ConnectionCounter >= math.MaxInt64 {
			return domain.ConnectionGeneration{}, domain.Reject(domain.ResourceLimit)
		}
		_, err = tx.ExecContext(ctx, "UPDATE devices SET counter=counter+1,boot=? WHERE id=?", boot, ref.Device)
		return domain.ConnectionGeneration{BootEpoch: boot, Counter: device.ConnectionCounter + 1}, err
	})
}

func (s *Store) AuthorizeAdministrative(ctx context.Context) error { return s.requireAdmin(ctx) }
