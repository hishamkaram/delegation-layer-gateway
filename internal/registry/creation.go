package registry

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type CreateOptions struct {
	Admin  AdminAuthorizer
	Random io.Reader
}

// Create exclusively creates a new authority. A failed initialization leaves
// its owned incomplete file in place; Open will never silently initialize it.
func Create(ctx context.Context, path string, options CreateOptions) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, domain.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create registry exclusively: %w", err)
	}
	if err = prepareRegistryFile(file, path); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err = errors.Join(file.Sync(), file.Close(), syncRegistryParent(path)); err != nil {
		return nil, err
	}
	s, err := connect(ctx, path, options.Admin, false)
	if err != nil {
		return nil, err
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	if err = s.createAuthority(ctx, random); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	if err = syncRegistryParent(path); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func prepareRegistryFile(file *os.File, path string) error {
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !registryRegular(opened) || !registryRegular(current) || !os.SameFile(opened, current) {
		return domain.ErrInvalid
	}
	return nil
}

func (s *Store) createAuthority(ctx context.Context, random io.Reader) error {
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		var entropy [64]byte
		if _, err := io.ReadFull(random, entropy[:]); err != nil {
			return struct{}{}, fmt.Errorf("registry identity entropy unavailable: %w", err)
		}
		gateway := hex.EncodeToString(entropy[:32])
		epoch := hex.EncodeToString(entropy[32:])
		if _, err := tx.ExecContext(ctx, schema+routingSchema); err != nil {
			return struct{}{}, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO settings(id,gateway,epoch) VALUES(1,?,?)", gateway, epoch); err != nil {
			return struct{}{}, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO credential_epochs(epoch) VALUES(?)", epoch); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, nil
	})
	return err
}

func validateRegistryFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return domain.ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("registry must already exist: %w", err)
	}
	if !registryRegular(before) {
		return domain.ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	var header [16]byte
	_, readErr := io.ReadFull(file, header[:])
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil {
		return errors.Join(statErr, readErr, closeErr)
	}
	if !registryRegular(opened) || !os.SameFile(before, opened) || string(header[:]) != "SQLite format 3\x00" {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func registryRegular(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && stat.Uid == uint32(os.Geteuid())
}

func syncRegistryParent(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

// ReadIdentity inspects the live WAL database through a normal existing-only
// connection with SQLite query_only enabled. It grants no mutation-capable Store.
func ReadIdentity(ctx context.Context, path string) (result domain.GatewayID, err error) {
	if err = validateRegistryFile(path); err != nil {
		return "", err
	}
	s, err := connect(ctx, path, nil, true)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	if err = s.validateExisting(ctx, ""); err != nil {
		return "", err
	}
	return s.Identity(ctx)
}
