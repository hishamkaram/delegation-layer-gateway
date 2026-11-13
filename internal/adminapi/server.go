package adminapi

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
)

type Server struct {
	listener        *unixListener
	lease           *instance.Lease
	socketIdentity  os.FileInfo
	path            string
	http            *http.Server
	gate            *requestGate
	mu              sync.Mutex
	started, closed bool
	cancel          context.CancelFunc
	acceptDone      chan struct{}
	acceptOnce      sync.Once
	connections     sync.WaitGroup
	closeOnce       sync.Once
	closeError      error
}

// Listen requires an existing private0700 parent owned by the current UID. It
// never removes a pre-existing path, including a stale socket from a crash.
func Listen(path string, handler *Handler) (*Server, error) {
	if handler == nil || handler.options.Authority == nil {
		return nil, fail("invalid_admin_configuration", nil)
	}
	listener, lease, identity, physical, err := socketListener(path)
	if err != nil {
		return nil, err
	}
	s := &Server{listener: listener, lease: lease, socketIdentity: identity, path: physical, gate: &requestGate{}, acceptDone: make(chan struct{})}
	s.http = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0), ConnState: s.connectionState}
	s.http.ConnContext = func(ctx context.Context, connection net.Conn) context.Context {
		owned, ok := connection.(*adminConn)
		if !ok || owned.owner != s.listener {
			return ctx
		}
		return context.WithValue(ctx, privateKey{}, privateProof{marker: handler.options.Authority.marker, gate: s.gate})
	}
	return s, nil
}

func (s *Server) connectionState(_ net.Conn, state http.ConnState) {
	if state == http.StateNew {
		s.connections.Add(1)
	}
	if state == http.StateClosed || state == http.StateHijacked {
		s.connections.Done()
	}
}

// Serve owns and joins its cancellation watcher. Close cancels accepted request
// contexts and joins HTTP handlers/connections before releasing filesystem paths.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return fail("admin_server_unavailable", nil)
	}
	s.started = true
	base, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.http.BaseContext = func(net.Listener) context.Context { return base }
	s.mu.Unlock()
	finished := make(chan struct{})
	watchDone := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			watchDone <- s.Close()
		case <-finished:
			watchDone <- nil
		}
	}()
	serveErr := s.http.Serve(s.listener)
	s.acceptOnce.Do(func() { close(s.acceptDone) })
	close(finished)
	closeErr := s.Close()
	watchErr := <-watchDone
	if errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
		serveErr = nil
	}
	if err := errors.Join(serveErr, closeErr, watchErr); err != nil {
		return fail("admin_server_failed", err)
	}
	return nil
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		started := s.started
		cancel := s.cancel
		s.mu.Unlock()
		s.gate.stop()
		if cancel != nil {
			cancel()
		}
		listenErr := s.listener.Close()
		httpErr := s.http.Close()
		connectionErr := s.listener.closeConnections()
		if !started {
			s.acceptOnce.Do(func() { close(s.acceptDone) })
		}
		<-s.acceptDone // No ConnState(StateNew) additions remain after Serve exits.
		s.gate.pending.Wait()
		s.connections.Wait()
		s.closeError = errors.Join(listenErr, httpErr, connectionErr, removeOwnedSocket(s.path, s.socketIdentity), s.lease.Close())
		if s.closeError != nil {
			s.closeError = fail("admin_cleanup_unconfirmed", s.closeError)
		}
	})
	return s.closeError
}
