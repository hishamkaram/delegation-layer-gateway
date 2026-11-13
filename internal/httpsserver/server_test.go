package httpsserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	return fixture.TLS.Certificates[0], roots
}

func TestTLSConnectionLimitIncludesIdleHandshakesAndReleasesAfterClose(t *testing.T) {
	certificate, roots := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), 1, time.Second)
	if err != nil {
		if closeErr := listener.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		if serveErr := <-done; serveErr != nil {
			t.Error(serveErr)
		}
	}()
	// The first idle TLS connection alone consumes capacity, before an HTTP call.
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "example.com"}
	first, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tls.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}, "tcp", listener.Addr().String(), cfg)
	if err == nil {
		if closeErr := second.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		if closeErr := first.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("second TLS handshake bypassed connection bound")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseCancelsButJoinsRealHandler(t *testing.T) {
	certificate, roots := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server, err := New(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-release
	}), 2, time.Second)
	if err != nil {
		if closeErr := listener.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}}
	defer transport.CloseIdleConnections()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+listener.Addr().String(), nil)
		if requestErr != nil {
			t.Error(requestErr)
			return
		}
		response, doErr := (&http.Client{Transport: transport}).Do(request)
		if doErr == nil {
			if _, readErr := io.Copy(io.Discard, response.Body); readErr != nil {
				t.Error(readErr)
			}
			if closeErr := response.Body.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	<-canceled
	select {
	case closeErr := <-closed:
		t.Fatalf("returned before handler join: %v", closeErr)
	default:
	}
	close(release)
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
	if err = <-served; err != nil {
		t.Fatal(err)
	}
	<-clientDone
	if err = server.Serve(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed server restarted")
	}
}

func TestCloseJoinsIdleTLSConnectionTerminalState(t *testing.T) {
	certificate, _ := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, http.NotFoundHandler(), 1, time.Second)
	if err != nil {
		if closeErr := listener.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	entered, terminal, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	state := server.http.ConnState
	server.http.ConnState = func(connection net.Conn, next http.ConnState) {
		if next == http.StateNew {
			state(connection, next)
			close(entered)
			return
		}
		if next == http.StateClosed {
			close(terminal)
			<-release
		}
		state(connection, next)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(t.Context()) }()
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	<-terminal
	select {
	case closeErr := <-closed:
		t.Fatalf("returned before idle connection terminal join: %v", closeErr)
	default:
	}
	close(release)
	if closeErr := <-closed; closeErr != nil {
		t.Fatal(closeErr)
	}
	if serveErr := <-served; serveErr != nil {
		t.Fatal(serveErr)
	}
}
