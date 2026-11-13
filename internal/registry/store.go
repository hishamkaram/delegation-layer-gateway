// Package registry owns Gateway SQLite state. Delegate observations are caches;
// no registry transaction admits or launches Delegate work.
package registry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	_ "modernc.org/sqlite" // Register the pinned database/sql driver.
)

type (
	AdminAuthorizer interface{ AuthorizeAdmin(context.Context) error }
	Options         struct {
		Gateway domain.GatewayID
		Admin   AdminAuthorizer
	}
)

// Store is the sole mutable authority. Its single connection serializes all
// transactions. Root must acquire the process instance lease before Open.
type Store struct {
	db    *sql.DB
	admin AdminAuthorizer
}

// Fixed-width UTC text preserves chronological ordering in SQLite comparisons.
const timestampLayout = "2006-01-02T15:04:05.000000000Z"

// Open never creates or initializes a database. Gateway is an expected pin;
// private local identity inspection uses ReadIdentity instead.
func Open(ctx context.Context, path string, options Options) (*Store, error) {
	if domain.Token(string(options.Gateway)) != nil {
		return nil, domain.ErrInvalid
	}
	if err := validateRegistryFile(path); err != nil {
		return nil, err
	}
	s, err := connect(ctx, path, options.Admin, false)
	if err != nil {
		return nil, err
	}
	if err = s.validateExisting(ctx, options.Gateway); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func connect(ctx context.Context, path string, admin AdminAuthorizer, readOnly bool) (*Store, error) {
	u := url.URL{Scheme: "file", Path: path}
	query := url.Values{"mode": []string{"rw"}, "_txlock": []string{"immediate"}}
	pragmas := []string{"foreign_keys(1)", "busy_timeout(5000)"}
	if readOnly {
		query.Set("_txlock", "deferred")
		pragmas = append(pragmas, "query_only(ON)")
	} else {
		pragmas = append(pragmas, "journal_mode(WAL)", "synchronous(FULL)", "secure_delete(ON)")
	}
	for _, pragma := range pragmas {
		query.Add("_pragma", pragma)
	}
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("open SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err = db.PingContext(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return &Store{db: db, admin: admin}, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), gateway TEXT NOT NULL, epoch TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, recovery TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS principals (id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, UNIQUE(issuer,subject));
CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, credential_generation INTEGER NOT NULL DEFAULT 0, counter INTEGER NOT NULL DEFAULT 0, boot TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS projects (device TEXT NOT NULL REFERENCES devices(id), alias TEXT NOT NULL, root_guard TEXT NOT NULL, project_guard TEXT NOT NULL, PRIMARY KEY(device,alias));
CREATE TABLE IF NOT EXISTS grants (principal TEXT NOT NULL REFERENCES principals(id), device TEXT NOT NULL, project TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY(principal,device,project), FOREIGN KEY(device,project) REFERENCES projects(device,alias));
CREATE TABLE IF NOT EXISTS enrollment (token BLOB PRIMARY KEY, device TEXT NOT NULL REFERENCES devices(id), mode TEXT NOT NULL, generation INTEGER NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, issuance TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS issuance (id TEXT PRIMARY KEY, replay TEXT NOT NULL UNIQUE, intent BLOB NOT NULL, certificate BLOB);
CREATE TABLE IF NOT EXISTS credentials (device TEXT PRIMARY KEY REFERENCES devices(id), epoch TEXT NOT NULL, generation INTEGER NOT NULL, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS operations (row_id INTEGER PRIMARY KEY, id TEXT UNIQUE, origin_operation TEXT NOT NULL UNIQUE, kind TEXT NOT NULL CHECK(kind IN ('attributed','unattributed')), task TEXT NOT NULL, owner TEXT, device TEXT NOT NULL, root_guard TEXT NOT NULL, project_guard TEXT NOT NULL, project TEXT, correlation BLOB, native_receipt BLOB, request BLOB, execution_options BLOB, options_sha256 BLOB, state TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved IN (0,1)), cancellation TEXT NOT NULL DEFAULT '', observation BLOB, UNIQUE(device,root_guard,task), CHECK((kind='attributed' AND id IS NOT NULL AND id=origin_operation AND project IS NOT NULL AND correlation IS NOT NULL) OR (kind='unattributed' AND id IS NULL AND owner IS NULL AND project IS NULL AND correlation IS NULL AND native_receipt IS NOT NULL)));
CREATE INDEX IF NOT EXISTS operations_recovery ON operations(device,root_guard,reserved);
CREATE TABLE IF NOT EXISTS administrative_routes (device TEXT NOT NULL, root_guard TEXT NOT NULL, project_guard TEXT NOT NULL, alias TEXT NOT NULL, credential BLOB NOT NULL, connection BLOB NOT NULL, PRIMARY KEY(device,root_guard,project_guard));
CREATE INDEX IF NOT EXISTS operations_owner ON operations(owner,id);
CREATE TABLE IF NOT EXISTS recoveries (id TEXT PRIMARY KEY, kind TEXT NOT NULL, epoch TEXT UNIQUE, started TEXT NOT NULL, sealed INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active', revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS root_admissions (device TEXT NOT NULL REFERENCES devices(id), root_guard TEXT NOT NULL, generation TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'pending', session TEXT NOT NULL DEFAULT '', PRIMARY KEY(device,root_guard));
CREATE TABLE IF NOT EXISTS credential_epochs (epoch TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS recovery_destinations (recovery TEXT NOT NULL, device TEXT NOT NULL, root_guard TEXT NOT NULL, generation TEXT NOT NULL DEFAULT '', expected_generation TEXT NOT NULL DEFAULT '', barrier BLOB, membership BLOB, cursor TEXT NOT NULL DEFAULT '', started INTEGER NOT NULL DEFAULT 0, finished INTEGER NOT NULL DEFAULT 0, completeness BLOB, approved INTEGER NOT NULL DEFAULT 0, reopened BLOB, PRIMARY KEY(recovery,device,root_guard));
CREATE TABLE IF NOT EXISTS inventory_pages (recovery TEXT NOT NULL, device TEXT NOT NULL, root_guard TEXT NOT NULL, cursor TEXT NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(recovery,device,root_guard,cursor));
PRAGMA user_version=7;
`

func (s *Store) validateExisting(ctx context.Context, expected domain.GatewayID) error {
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		var version int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return struct{}{}, err
		}
		if version != 7 {
			return struct{}{}, fmt.Errorf("registry schema requires explicit initialization or offline migration: %w", domain.Reject(domain.Conflict))
		}
		if _, err := validateRegistryAuthority(ctx, tx, expected); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, verifyRoutingConstraints(ctx, tx)
	})
	return err
}

func validateRegistryAuthority(ctx context.Context, tx *sql.Tx, expected domain.GatewayID) (domain.GatewayID, error) {
	if err := verifyRegistrySchema(ctx, tx); err != nil {
		return "", err
	}
	if err := verifyRoutingSchema(ctx, tx); err != nil {
		return "", err
	}
	if err := verifyExecutionOptionsSchema(ctx, tx); err != nil {
		return "", err
	}
	var gateway domain.GatewayID
	var epoch domain.CredentialEpoch
	var rows int
	if err := tx.QueryRowContext(ctx, "SELECT gateway,epoch,(SELECT count(*) FROM settings) FROM settings WHERE id=1").Scan(&gateway, &epoch, &rows); err != nil {
		return "", err
	}
	if rows != 1 || domain.Token(string(gateway)) != nil || domain.CredentialToken(string(epoch)) != nil || (expected != "" && gateway != expected) {
		return "", domain.Reject(domain.Conflict)
	}
	var known int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM credential_epochs WHERE epoch=?", epoch).Scan(&known); err != nil {
		return "", err
	}
	if known != 1 {
		return "", domain.Reject(domain.Conflict)
	}
	return gateway, nil
}

// Identity reads the database authority, never a configuration value.
func (s *Store) Identity(ctx context.Context) (domain.GatewayID, error) {
	var gateway string
	if err := s.db.QueryRowContext(ctx, "SELECT gateway FROM settings WHERE id=1").Scan(&gateway); err != nil {
		return "", err
	}
	if domain.Token(gateway) != nil {
		return "", domain.Reject(domain.EvidenceInvalid)
	}
	return domain.GatewayID(gateway), nil
}

func verifyRegistrySchema(ctx context.Context, tx *sql.Tx) error {
	for _, query := range registrySchemaQueries() {
		if err := verifyRegistryQuery(ctx, tx, query); err != nil {
			return err
		}
	}
	return nil
}

func verifyRegistryQuery(ctx context.Context, tx *sql.Tx, query string) (err error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("registry schema is incomplete: %w", err)
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	return rows.Err()
}

func verifyExecutionOptionsSchema(ctx context.Context, tx *sql.Tx) (err error) {
	rows, err := tx.QueryContext(ctx, "SELECT execution_options,options_sha256 FROM operations LIMIT 0")
	if err != nil {
		return fmt.Errorf("registry execution options schema is incomplete: %w", err)
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	return rows.Err()
}

func transaction[T any](ctx context.Context, s *Store, fn func(*sql.Tx) (T, error)) (result T, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin registry transaction: %w", err)
	}
	defer func() {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback registry: %w", rollbackErr))
		}
	}()
	result, err = fn(tx)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(); err != nil {
		return result, fmt.Errorf("commit registry: %w", err)
	}
	return result, nil
}

func (s *Store) requireAdmin(ctx context.Context) error {
	if s.admin == nil {
		return domain.Reject(domain.Forbidden)
	}
	if err := s.admin.AuthorizeAdmin(ctx); err != nil {
		return fmt.Errorf("admin authorization: %w", err)
	}
	return nil
}

func encode[T any](value T) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode registry value: %w", err)
	}
	return data, nil
}

func decode[T any](data []byte) (value T, err error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("decode registry value: %w", err)
	}
	var extra json.RawMessage
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return value, domain.Reject(domain.EvidenceInvalid)
	}
	return value, nil
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Reject(domain.NotFound)
	}
	return err
}

func registrySchemaQueries() []string {
	return []string{
		"SELECT id,gateway,epoch,blocked,recovery FROM settings LIMIT 0",
		"SELECT id,issuer,subject,revoked FROM principals LIMIT 0",
		"SELECT id,name,revoked,credential_generation,counter,boot FROM devices LIMIT 0",
		"SELECT device,alias,root_guard,project_guard FROM projects LIMIT 0",
		"SELECT principal,device,project,value FROM grants LIMIT 0",
		"SELECT token,device,mode,generation,created,expires,issuance FROM enrollment LIMIT 0",
		"SELECT id,replay,intent,certificate FROM issuance LIMIT 0",
		"SELECT device,epoch,generation,value FROM credentials LIMIT 0",
		"SELECT row_id,id,origin_operation,kind,task,owner,device,root_guard,project_guard,project,correlation,native_receipt,request,execution_options,state,created,expires,reserved,cancellation,observation FROM operations LIMIT 0",
		"SELECT device,root_guard,project_guard,alias,credential,connection FROM administrative_routes LIMIT 0",
		"SELECT id,kind,epoch,started,sealed,status,revision FROM recoveries LIMIT 0",
		"SELECT epoch FROM credential_epochs LIMIT 0",
		"SELECT device,root_guard,generation,state,session FROM root_admissions LIMIT 0",
		"SELECT recovery,device,root_guard,generation,expected_generation,barrier,membership,cursor,started,finished,completeness,approved,reopened FROM recovery_destinations LIMIT 0",
		"SELECT recovery,device,root_guard,cursor,digest FROM inventory_pages LIMIT 0",
	}
}
