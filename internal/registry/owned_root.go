package registry

import (
	"context"
	"database/sql"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// OwnedRootPort is an immutable, narrowly bound initialization capability.
// Registry rechecks live ownership, credential and connection inside every SQL
// transaction; constructing this port grants no persistent administrative right.
type OwnedRootPort struct {
	store   *Store
	binding domain.OwnedRootBinding
	owner   domain.PrincipalID
	gateway domain.GatewayID
	now     func() time.Time
}

// NewOwnedRootPort accepts only server-authenticated mTLS connection evidence.
// A first root report creates pending admission even when no projects exist.
func NewOwnedRootPort(ctx context.Context, store *Store, binding domain.OwnedRootBinding, now func() time.Time) (*OwnedRootPort, error) {
	if store == nil || binding.Validate() != nil || now == nil || now().IsZero() {
		return nil, domain.ErrInvalid
	}
	p := &OwnedRootPort{store: store, binding: binding, now: now}
	_, err := transaction(ctx, store, func(tx *sql.Tx) (struct{}, error) {
		owner, _, err := authorizeOwnedRoot(ctx, tx, binding, now())
		if err != nil {
			return struct{}{}, err
		}
		p.owner = owner
		if err = tx.QueryRowContext(ctx, "SELECT gateway FROM settings WHERE id=1").Scan(&p.gateway); err != nil {
			return struct{}{}, err
		}
		var others int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM root_admissions WHERE device=? AND root_guard<>?", binding.Route.Device, binding.Route.Root).Scan(&others); err != nil {
			return struct{}{}, err
		}
		if others != 0 {
			return struct{}{}, domain.Reject(domain.Conflict)
		}
		_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO root_admissions(device,root_guard) VALUES(?,?)", binding.Route.Device, binding.Route.Root)
		return struct{}{}, err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *OwnedRootPort) OwnerPrincipal() domain.PrincipalID { return p.owner }
func (p *OwnedRootPort) Binding() domain.OwnedRootBinding   { return p.binding }

func authorizeOwnedRoot(ctx context.Context, tx *sql.Tx, binding domain.OwnedRootBinding, now time.Time) (domain.PrincipalID, domain.Credential, error) {
	if binding.Validate() != nil || now.IsZero() {
		return "", domain.Credential{}, domain.ErrInvalid
	}
	if err := admissionsOpen(ctx, tx); err != nil {
		return "", domain.Credential{}, err
	}
	credential, err := checkConnection(ctx, tx, binding.Credential, binding.Connection, now)
	if err != nil {
		return "", credential, err
	}
	if credential.Mode != domain.Regular {
		return "", credential, domain.Reject(domain.Forbidden)
	}
	owner, err := deviceOwner(ctx, tx, binding.Route.Device)
	if err != nil {
		return "", credential, err
	}
	if owner == "" {
		return "", credential, domain.Reject(domain.Forbidden)
	}
	if _, err = ownerPolicy(ctx, tx, owner); err != nil {
		return "", credential, err
	}
	return owner, credential, nil
}

func (p *OwnedRootPort) check(ctx context.Context, tx *sql.Tx) (domain.Credential, error) {
	owner, credential, err := authorizeOwnedRoot(ctx, tx, p.binding, p.now())
	if err != nil {
		return credential, err
	}
	if owner != p.owner {
		return credential, domain.Reject(domain.Forbidden)
	}
	if err = rootLookup(ctx, tx, p.lookup()); err != nil {
		return credential, err
	}
	return credential, nil
}

func (p *OwnedRootPort) lookup() domain.RootInitializationLookup {
	root := p.binding.Route
	return domain.RootInitializationLookup{RootRoute: &root}
}

func (p *OwnedRootPort) CheckOwnedRoot(ctx context.Context) error {
	_, err := transaction(ctx, p.store, func(tx *sql.Tx) (domain.Credential, error) { return p.check(ctx, tx) })
	return err
}

func (p *OwnedRootPort) CheckConnection(ctx context.Context, ref domain.CredentialRef, generation domain.ConnectionGeneration, _ time.Time) (domain.Credential, error) {
	if ref != p.binding.Credential || generation != p.binding.Connection {
		return domain.Credential{}, domain.Reject(domain.Forbidden)
	}
	return transaction(ctx, p.store, func(tx *sql.Tx) (domain.Credential, error) { return p.check(ctx, tx) })
}

func (p *OwnedRootPort) checkRecovery(ctx context.Context, tx *sql.Tx, id domain.RecoveryID) error {
	if domain.RoutingToken(string(id)) != nil {
		return domain.ErrInvalid
	}
	var session domain.RecoveryID
	if err := tx.QueryRowContext(ctx, "SELECT session FROM root_admissions WHERE device=? AND root_guard=?", p.binding.Route.Device, p.binding.Route.Root).Scan(&session); err != nil {
		return notFound(err)
	}
	if id != session {
		return domain.Reject(domain.Forbidden)
	}
	state, err := readRecovery(ctx, tx, id)
	if err != nil {
		return err
	}
	if state.kind != domain.RootRecovery {
		return domain.Reject(domain.Forbidden)
	}
	var total, matching int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(device=? AND root_guard=?),0) FROM recovery_destinations WHERE recovery=?", p.binding.Route.Device, p.binding.Route.Root, id).Scan(&total, &matching); err != nil {
		return err
	}
	if total != 1 || matching != 1 {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

func (p *OwnedRootPort) destination(input domain.RecoveryDestination) bool {
	return input.Device == p.binding.Route.Device && input.Root == p.binding.Route.Root
}
