package httpsserver

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
)

type timeoutConnectionState struct {
	connection net.Conn
	state      http.ConnState
}

// The HTTPS server owns sockets and their capacity. Guard owns request slots
// until handler return. The test keeps the stalled client open: only automatic
// server expiry may release either resource before the healthy second request.
type slowInputCase struct {
	name           string
	useTLS         bool
	request        string
	serverTimeout  time.Duration
	watchdog       time.Duration
	bodyReadStarts bool
}

func TestStalledInputExpiresAndReleasesConnectionAndRequestCapacity(t *testing.T) {
	cases := []slowInputCase{
		{name: "TLS handshake", serverTimeout: 300 * time.Millisecond, watchdog: 3 * time.Second},
		{
			name: "incomplete WSS headers", useTLS: true,
			request: "GET /device HTTP/1.1\r\nHost: gateway.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
			// The general read timeout exceeds the watchdog, so only the
			// production five-second header bound can pass this case.
			serverTimeout: 20 * time.Second, watchdog: 12 * time.Second,
		},
		{
			name: "incomplete guarded body", useTLS: true,
			request:       "POST /stall HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: 8\r\n\r\nx",
			serverTimeout: 300 * time.Millisecond, watchdog: 3 * time.Second, bodyReadStarts: true,
		},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) { checkStalledInput(t, current) })
	}
}

func checkStalledInput(t *testing.T, current slowInputCase) {
	t.Helper()
	entered := make(chan struct{})
	bodyError := make(chan error, 1)
	guard, err := httpguard.New(httpguard.Options{PublicOrigin: "https://gateway.example", ConcurrentRequests: 1, Timeout: 2 * time.Second, MaxBodyBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	handler := guard.Wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/stall" {
			close(entered)
			_, readErr := io.Copy(io.Discard, request.Body)
			bodyError <- readErr
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	address, clientTLS, states := startTimeoutServer(t, handler, current.serverTimeout)
	stalled := startStalledClient(t, address, clientTLS, current.useTLS)
	first := waitTimeoutState(t, states, http.StateNew, current.watchdog)
	if current.request != "" {
		if sent, writeErr := io.WriteString(stalled, current.request); writeErr != nil || sent != len(current.request) {
			t.Fatalf("partial request write: bytes=%d err=%v", sent, writeErr)
		}
	}
	if current.bodyReadStarts {
		select {
		case <-entered:
		case <-time.After(current.watchdog):
			t.Fatal("partial body never reached guarded handler")
		}
	}
	closed := waitTimeoutState(t, states, http.StateClosed, current.watchdog)
	if closed != first {
		t.Fatal("a different connection closed; stalled connection remains unproven")
	}
	if current.bodyReadStarts {
		readErr := <-bodyError
		var timeout net.Error
		if !errors.As(readErr, &timeout) || !timeout.Timeout() {
			t.Fatalf("stalled body did not end with server read timeout: %v", readErr)
		}
	}
	// Both capacities are one. Do not close stalled or cancel the server first.
	requireHealthyAfterExpiry(t, address, clientTLS)
}

func startStalledClient(t *testing.T, address string, config *tls.Config, useTLS bool) net.Conn {
	t.Helper()
	var connection net.Conn
	var err error
	if useTLS {
		connection, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, config)
	} else {
		connection, err = net.DialTimeout("tcp", address, time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return connection
}

func requireHealthyAfterExpiry(t *testing.T, address string, config *tls.Config) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/healthy", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "gateway.example"
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("expired connection still holds capacity: %v", err)
	}
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Error(closeErr)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("expired request still holds admission: status=%d", response.StatusCode)
	}
}

func startTimeoutServer(t *testing.T, handler http.Handler, timeout time.Duration) (string, *tls.Config, <-chan timeoutConnectionState) {
	t.Helper()
	certificate, roots := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, handler, 1, timeout)
	if err != nil {
		if closeErr := listener.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	states := make(chan timeoutConnectionState, 8)
	ownedState := server.http.ConnState
	server.http.ConnState = func(connection net.Conn, state http.ConnState) {
		select {
		case states <- timeoutConnectionState{connection: connection, state: state}:
		default:
			t.Error("connection state observation capacity exhausted")
		}
		ownedState(connection, state)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(t.Context()) }()
	t.Cleanup(func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		if serveErr := <-served; serveErr != nil {
			t.Error(serveErr)
		}
	})
	return listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "example.com"}, states
}

func waitTimeoutState(t *testing.T, states <-chan timeoutConnectionState, wanted http.ConnState, watchdog time.Duration) net.Conn {
	t.Helper()
	timer := time.NewTimer(watchdog)
	defer timer.Stop()
	for {
		select {
		case observed := <-states:
			if observed.state == wanted {
				return observed.connection
			}
		case <-timer.C:
			t.Fatalf("server did not reach %v without client close or explicit shutdown", wanted)
		}
	}
}
