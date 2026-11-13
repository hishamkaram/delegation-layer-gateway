// Package httpsserver bounds accepted TLS connections and owns HTTP request
// cleanup. A handler that hijacks a socket must have its separate owner joined
// by composition before Close; HTTP closure alone cannot close WSS sessions.
package httpsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

var ErrUnavailable = errors.New("https_server_unavailable")

type Server struct {
	http             *http.Server
	listener         net.Listener
	mu               sync.Mutex
	serving, closing bool
	cancel           context.CancelFunc
	handlers         sync.WaitGroup
	connections      sync.WaitGroup
	accepted         chan struct{}
	acceptedOnce     sync.Once
	closeOnce        sync.Once
	closeErr         error
}

// New takes ownership of listener only on success. Connection capacity includes
// TLS handshakes and idle connections, independently of request admission.
func New(listener net.Listener, config *tls.Config, handler http.Handler, capacity int, timeout time.Duration) (*Server, error) {
	if listener == nil || config == nil || config.MinVersion < tls.VersionTLS13 || len(config.Certificates) == 0 || handler == nil || capacity < 1 || capacity > 512 || timeout <= 0 || timeout > 305*time.Second {
		return nil, ErrUnavailable
	}
	s := &Server{listener: netutil.LimitListener(listener, capacity), accepted: make(chan struct{})}
	s.http = &http.Server{TLSConfig: config.Clone(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: timeout, WriteTimeout: timeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	s.http.ConnState = s.connectionState
	s.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.begin() {
			http.Error(w, "server_stopping", http.StatusServiceUnavailable)
			return
		}
		defer s.handlers.Done()
		handler.ServeHTTP(w, r)
	})
	return s, nil
}

// Serve emits StateNew before starting a connection goroutine. Closing the
// accept loop fences further additions before Close waits for terminal states.
// A hijacked socket transfers to its separate WSS owner, joined by composition.
func (s *Server) connectionState(_ net.Conn, state http.ConnState) {
	if state == http.StateNew {
		s.connections.Add(1)
	}
	if state == http.StateClosed || state == http.StateHijacked {
		s.connections.Done()
	}
}

func (s *Server) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.handlers.Add(1)
	return true
}

func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.serving || s.closing {
		s.mu.Unlock()
		return ErrUnavailable
	}
	s.serving = true
	owned, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.http.BaseContext = func(net.Listener) context.Context { return owned }
	s.mu.Unlock()
	finished := make(chan struct{})
	watched := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			watched <- s.Close()
		case <-finished:
			watched <- nil
		}
	}()
	serveErr := s.http.ServeTLS(s.listener, "", "")
	s.acceptedOnce.Do(func() { close(s.accepted) })
	close(finished)
	closeErr := s.Close()
	watchErr := <-watched
	if errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
		serveErr = nil
	}
	if errors.Join(serveErr, closeErr, watchErr) != nil {
		return ErrUnavailable
	}
	return nil
}

// Close cancels requests, closes the listener/connections, and waits for actual
// handler returns. It never treats a request deadline as joined cleanup.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		serving := s.serving
		cancel := s.cancel
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		listenerErr := s.listener.Close()
		httpErr := s.http.Close()
		if !serving {
			s.acceptedOnce.Do(func() { close(s.accepted) })
		}
		<-s.accepted
		s.handlers.Wait()
		s.connections.Wait()
		if errors.Is(listenerErr, net.ErrClosed) {
			listenerErr = nil
		}
		if errors.Is(httpErr, net.ErrClosed) || errors.Is(httpErr, http.ErrServerClosed) {
			httpErr = nil
		}
		if errors.Join(listenerErr, httpErr) != nil {
			s.closeErr = ErrUnavailable
		}
	})
	return s.closeErr
}
