// Package instance owns process-scoped leases for supported Unix deployments.
// The stable lease inode is never unlinked: replacing it would split ownership.
package instance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var (
	ErrBusy    = errors.New("instance already owns lease")
	ErrInvalid = errors.New("invalid instance lease")
)

type Lease struct {
	file *os.File
	once sync.Once
	err  error
}

func Acquire(path string) (*Lease, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open instance lease: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(ErrInvalid, err, file.Close())
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.Join(ErrBusy, file.Close())
		}
		return nil, errors.Join(fmt.Errorf("acquire instance lease: %w", err), file.Close())
	}
	return &Lease{file: file}, nil
}

// Close releases only this open-file description. It does not remove the inode
// or imply closure of any independently owned Delegate task or subprocess.
func (l *Lease) Close() error {
	l.once.Do(func() { l.err = l.file.Close() })
	return l.err
}
