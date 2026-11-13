package adminapi

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
)

func privateParent(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return "", fail("invalid_socket_path", nil)
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return "", fail("invalid_socket_parent", err)
	}
	if !ownedDirectory(info) {
		return "", fail("invalid_socket_parent", nil)
	}
	physical, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fail("invalid_socket_parent", err)
	}
	return filepath.Join(physical, filepath.Base(path)), nil
}

func ownedDirectory(info os.FileInfo) bool {
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	// os.FileInfo.Sys is an OS boundary. A checked native stat provides UID;
	// unsupported metadata denies access rather than guessing ownership.
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func socketListener(path string) (*unixListener, *instance.Lease, os.FileInfo, string, error) {
	physical, err := privateParent(path)
	if err != nil {
		return nil, nil, nil, "", err
	}
	lease, err := instance.Acquire(filepath.Join(filepath.Dir(physical), ".admin.lock"))
	if err != nil {
		return nil, nil, nil, "", fail("admin_lease_unavailable", err)
	}
	if _, err = os.Lstat(physical); err == nil {
		return nil, nil, nil, "", fail("socket_path_exists", lease.Close())
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, "", fail("socket_path_unavailable", errors.Join(err, lease.Close()))
	}
	base, err := net.ListenUnix("unix", &net.UnixAddr{Name: physical, Net: "unix"})
	if err != nil {
		return nil, nil, nil, "", fail("socket_listen_failed", errors.Join(err, lease.Close()))
	}
	base.SetUnlinkOnClose(false)
	info, err := os.Lstat(physical)
	if err != nil {
		return nil, nil, nil, "", fail("socket_identity_unavailable", errors.Join(err, base.Close(), lease.Close()))
	}
	if err = os.Chmod(physical, 0o600); err != nil {
		return nil, nil, nil, "", fail("socket_permissions_failed", errors.Join(err, base.Close(), removeOwnedSocket(physical, info), lease.Close()))
	}
	return &unixListener{base: base, connections: make(map[*adminConn]struct{}), slots: make(chan struct{}, 32)}, lease, info, physical, nil
}

func removeOwnedSocket(path string, identity os.FileInfo) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fail("socket_cleanup_unconfirmed", err)
	}
	if identity == nil || !os.SameFile(identity, current) || current.Mode()&os.ModeSocket == 0 {
		return fail("socket_ownership_changed", nil)
	}
	if err = os.Remove(path); err != nil {
		return fail("socket_cleanup_unconfirmed", err)
	}
	return nil
}

type unixListener struct {
	base        *net.UnixListener
	mu          sync.Mutex
	closed      bool
	connections map[*adminConn]struct{}
	slots       chan struct{}
	once        sync.Once
	err         error
}

func (l *unixListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.base.AcceptUnix()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
		default:
			if err = connection.Close(); err != nil {
				return nil, fail("connection_close_failed", err)
			}
			continue
		}
		owned := &adminConn{UnixConn: connection, owner: l}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, errors.Join(net.ErrClosed, owned.Close())
		}
		l.connections[owned] = struct{}{}
		l.mu.Unlock()
		return owned, nil
	}
}

func (l *unixListener) Close() error {
	l.once.Do(func() { l.mu.Lock(); l.closed = true; l.mu.Unlock(); l.err = l.base.Close() })
	return l.err
}
func (l *unixListener) Addr() net.Addr { return l.base.Addr() }
func (l *unixListener) closeConnections() error {
	l.mu.Lock()
	connections := make([]*adminConn, 0, len(l.connections))
	for connection := range l.connections {
		connections = append(connections, connection)
	}
	l.mu.Unlock()
	var failures []error
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

type adminConn struct {
	*net.UnixConn
	owner *unixListener
	once  sync.Once
	err   error
}

func (c *adminConn) Close() error {
	c.once.Do(func() {
		c.err = c.UnixConn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
		<-c.owner.slots
	})
	return c.err
}
