// Package deviceidentity owns connector-local private key and renewal intent
// durability. The Gateway registry remains the credential authority.
package deviceidentity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const (
	MaxStateBytes = 128 << 10
	stateName     = "identity.json"
)

var (
	ErrInvalid   = errors.New("invalid_device_identity")
	ErrBusy      = errors.New("device_identity_in_use")
	ErrAbsent    = errors.New("device_identity_absent")
	ErrConflict  = errors.New("device_identity_conflict")
	ErrUncertain = errors.New("device_identity_commit_uncertain")
	ErrClosed    = errors.New("device_identity_closed")
)

type localError struct{ kind, cause error }

func (e localError) Error() string { return e.kind.Error() }
func (e localError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}
func failed(kind, cause error) error { return localError{kind: kind, cause: cause} }

// Store serializes all mutation under one OS instance lease and mutex. Its
// single atomic bundle is the source of truth for key, certificate and intent.
type Store struct {
	mu        sync.Mutex
	root      *os.Root
	directory *os.File
	lease     *instance.Lease
	state     record
	sequence  uint64
	closeErr  error
	closed    bool
	uncertain bool
}

func Open(directory string) (*Store, error) {
	info, prepareErr := prepareDirectory(directory)
	if prepareErr != nil {
		return nil, prepareErr
	}
	root, dir, pinErr := openPinnedDirectory(directory, info)
	if pinErr != nil {
		return nil, pinErr
	}
	lease, leaseErr := instance.Acquire(filepath.Join(directory, "instance.lock"))
	if leaseErr != nil {
		kind := ErrInvalid
		if errors.Is(leaseErr, instance.ErrBusy) {
			kind = ErrBusy
		}
		return nil, failed(kind, errors.Join(leaseErr, dir.Close(), root.Close()))
	}
	store := &Store{root: root, directory: dir, lease: lease}
	current, currentErr := os.Lstat(directory)
	if currentErr != nil || !os.SameFile(info, current) {
		return nil, failed(ErrInvalid, errors.Join(currentErr, store.Close()))
	}
	if loadErr := store.load(); loadErr != nil {
		return nil, failed(ErrInvalid, errors.Join(loadErr, store.Close()))
	}
	return store, nil
}

func prepareDirectory(directory string) (os.FileInfo, error) {
	if !filepath.IsAbs(directory) {
		return nil, ErrInvalid
	}
	mkdirErr := os.Mkdir(directory, 0o700)
	if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
		return nil, failed(ErrInvalid, mkdirErr)
	}
	if mkdirErr == nil {
		parent, parentErr := os.Open(filepath.Dir(directory))
		if parentErr != nil {
			return nil, failed(ErrInvalid, parentErr)
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if joined := errors.Join(syncErr, closeErr); joined != nil {
			return nil, failed(ErrInvalid, joined)
		}
	}
	info, statErr := os.Lstat(directory)
	if statErr != nil || !private(info, true) {
		return nil, failed(ErrInvalid, statErr)
	}

	return info, nil
}

func openPinnedDirectory(directory string, info os.FileInfo) (*os.Root, *os.File, error) {
	root, openErr := os.OpenRoot(directory)
	if openErr != nil {
		return nil, nil, failed(ErrInvalid, openErr)
	}
	dir, dirErr := root.Open(".")
	if dirErr != nil {
		return nil, nil, failed(ErrInvalid, errors.Join(dirErr, root.Close()))
	}
	opened, openedErr := dir.Stat()
	if openedErr != nil || !os.SameFile(info, opened) {
		return nil, nil, failed(ErrInvalid, errors.Join(openedErr, dir.Close(), root.Close()))
	}

	return root, dir, nil
}

func private(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	expected := os.FileMode(0o600)
	if directory {
		expected = 0o700
	}
	if info.Mode().Perm() != expected || info.IsDir() != directory || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	if !directory && !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && (directory || stat.Nlink == 1)
}

func (s *Store) load() error {
	file, openErr := s.root.OpenFile(stateName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(openErr, os.ErrNotExist) {
		return nil
	}
	if openErr != nil {
		return openErr
	}
	info, statErr := file.Stat()
	if statErr != nil || !private(info, false) || info.Size() > MaxStateBytes {
		return errors.Join(ErrInvalid, statErr, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxStateBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	var state record
	if protocol.DecodeStrict(data, &state, MaxStateBytes) != nil || state.valid() != nil {
		return ErrInvalid
	}
	s.state = state
	return nil
}

func (s *Store) check() error {
	if s.closed {
		return ErrClosed
	}
	if s.uncertain {
		return ErrUncertain
	}
	return nil
}

func (s *Store) commit(next record) error {
	data, encodeErr := protocol.Encode(next, MaxStateBytes)
	if encodeErr != nil {
		return failed(ErrInvalid, encodeErr)
	}
	name, file, createErr := s.temporary()
	if createErr != nil {
		return failed(ErrInvalid, createErr)
	}
	_, writeErr := file.Write(data)
	syncErr := error(nil)
	if writeErr == nil {
		syncErr = file.Sync()
	}
	closeErr := file.Close()
	if combined := errors.Join(writeErr, syncErr, closeErr); combined != nil {
		return failed(ErrInvalid, errors.Join(combined, s.root.Remove(name)))
	}
	if renameErr := s.root.Rename(name, stateName); renameErr != nil {
		return failed(ErrInvalid, errors.Join(renameErr, s.root.Remove(name)))
	}
	s.state = next
	if dirSyncErr := s.directory.Sync(); dirSyncErr != nil {
		s.uncertain = true
		return failed(ErrUncertain, dirSyncErr)
	}
	return nil
}

func (s *Store) temporary() (string, *os.File, error) {
	for range 32 {
		if s.sequence == ^uint64(0) {
			return "", nil, ErrInvalid
		}
		s.sequence++
		name := fmt.Sprintf(".identity-%d.tmp", s.sequence)
		file, openErr := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
		if errors.Is(openErr, os.ErrExist) {
			continue
		}
		return name, file, openErr
	}
	return "", nil, ErrInvalid
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	joined := errors.Join(s.root.Close(), s.directory.Close(), s.lease.Close())
	if joined != nil {
		s.closeErr = failed(ErrInvalid, joined)
	}
	return s.closeErr
}
