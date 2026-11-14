package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestServerParentCancellationStopsAndJoinsEstablishedSession(t *testing.T) {
	f := newFixture(t, Settings{HeartbeatInterval: time.Hour, OfflineTimeout: 2 * time.Hour})
	client := f.dial(t)
	s, err := f.hub.current("device-one")
	if err != nil {
		t.Fatal(err)
	}
	f.hub.cancel()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatal("server parent cancellation did not reach its established socket owner")
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.hub.Close(); err != nil {
		t.Fatal(err)
	}
	f.hub.mu.Lock()
	remaining := len(f.hub.sessions)
	f.hub.mu.Unlock()
	if remaining != 0 {
		t.Fatal("server parent cancellation retained an unjoined session")
	}
}

func TestStoppedInboundClosesConnectionInstalledAfterStop(t *testing.T) {
	f := newFixture(t, Settings{})
	peer, err := f.hub.RegisterPeer(f.certificate, f.store.value.Ref, f.store.value)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := peer.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	deadline, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	requireError(t, f.hub.DisconnectContext(deadline, "device-one"), ErrExpired)
	// Borrow an unclaimed SDK endpoint, not a running Client's connection. The
	// closing guard runs before any protocol read and must take/close it even
	// though the registered inbound resource was stopped before installation.
	conn, joinPeer := unclaimedSocket(t)
	established, runErr := peer.Run(t.Context(), t.Context(), conn, nil)
	if established || !errors.Is(runErr, ErrOffline) {
		t.Fatal("stopped inbound resource accepted a later connection", runErr)
	}
	if err = peer.Close(); err != nil {
		t.Fatal(err)
	}
	joinPeer()
	replacement, err := f.hub.RegisterPeer(f.certificate, f.store.value.Ref, f.store.value)
	if err != nil {
		t.Fatal("stopped inbound resource retained its slot after actual close", err)
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

// A bare SDK peer owns no Gateway handshake or execution. The accepted endpoint
// is transferred to the test's inbound owner before any transport read starts.
func unclaimedSocket(t *testing.T) (*websocket.Conn, func()) {
	t.Helper()
	owner, cancelOwner := context.WithCancel(context.WithoutCancel(t.Context()))
	accepted := make(chan *websocket.Conn)
	handlerDone := make(chan struct{})
	var handlerStarted atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerStarted.Store(true)
		defer close(handlerDone)
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.Subprotocol}})
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case accepted <- conn:
		case <-owner.Done():
			reportPeerClose(t, conn.CloseNow())
		}
	}))
	t.Cleanup(func() {
		cancelOwner()
		server.Close()
		if handlerStarted.Load() {
			select {
			case <-handlerDone:
			case <-time.After(5 * time.Second):
				t.Error("bare SDK peer handler did not join")
			}
		}
	})
	client, response, err := websocket.Dial(t.Context(), "wss"+strings.TrimPrefix(server.URL, "https"), &websocket.DialOptions{HTTPClient: server.Client(), Subprotocols: []string{protocol.Subprotocol}})
	if response != nil && response.Body != nil {
		err = errors.Join(err, response.Body.Close())
	}
	if err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	<-handlerDone
	readContext, cancelRead := context.WithCancel(context.WithoutCancel(t.Context()))
	peer := &bareSocketPeer{client: client, cancel: cancelRead, result: make(chan error, 1), done: make(chan struct{})}
	go func() { defer close(peer.done); _, _, readErr := client.Read(readContext); peer.result <- readErr }()
	joinPeer := func() { peer.join(t) }
	t.Cleanup(func() { reportPeerClose(t, conn.CloseNow()); joinPeer() })
	return conn, joinPeer
}

type bareSocketPeer struct {
	client *websocket.Conn
	cancel context.CancelFunc
	result chan error
	done   chan struct{}
	once   sync.Once
}

func (p *bareSocketPeer) join(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		select {
		case readErr := <-p.result:
			if readErr == nil {
				t.Error("bare peer read succeeded instead of observing socket closure")
			}
		case <-time.After(5 * time.Second):
			p.cancel()
			reportPeerClose(t, p.client.CloseNow())
			<-p.result
			t.Error("inbound owner did not close its newly installed socket")
		}
		<-p.done
		p.cancel()
		reportPeerClose(t, p.client.CloseNow())
	})
}

func reportPeerClose(t *testing.T, err error) {
	t.Helper()
	if err != nil && !onlyClosedError(err) {
		// Abruptly stopping the test endpoint can prevent this bare peer's TLS
		// close notification. Retain that diagnostic; read EOF and its join are
		// the fixture's separate closure evidence, not a nil-error assumption.
		t.Logf("bare SDK peer close diagnostic: %v", err)
	}
}

func TestCancelledHandshakeRetainsOriginalDeadlineAndObservedCloseFault(t *testing.T) {
	f := newRoutedFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	peer := handshakeGatedPeer{censusPeer: newCensusPeer(), acknowledged: make(chan struct{}), release: release}
	fault := errors.New("close diagnostic after cancelled routing handshake")
	observer := &diagnosticCloseTransport{next: f.http.Transport, failure: fault}
	clientHTTP := *f.http
	clientHTTP.Transport = observer
	var client *Client
	var dialErr error
	dialDone := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		unblock()
		<-dialDone
		if client != nil {
			if closeErr := client.Close(); closeErr != nil && !errors.Is(closeErr, fault) {
				t.Error(closeErr)
			}
		}
	})
	go func() {
		defer close(dialDone)
		client, dialErr = Dial(ctx, ClientConfig{
			URL: "wss" + strings.TrimPrefix(f.server.URL, "https"), GatewayID: f.gateway, Certificate: f.certificate,
			Capabilities: protocol.CapabilityReport{ObservedAt: f.clock.now(), Projects: []protocol.ProjectCapability{{Alias: "project-one", Ready: false}}}, Routing: peer,
		}, &clientHTTP, f.clock.now)
	}()
	select {
	case <-peer.acknowledged:
	case <-dialDone:
		t.Fatal("handshake did not reach its owned routing gate", dialErr)
	case <-ctx.Done():
		t.Fatal("routing handshake gate timed out")
	}
	cancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled original handshake context did not stop Dial")
	}
	if client != nil || !errors.Is(dialErr, context.Canceled) || !errors.Is(dialErr, fault) || !observer.closed.Load() {
		t.Fatal("cancelled handshake lost its close diagnostic or socket ownership", dialErr)
	}
	waitRetired(t, f.hub)
}

func TestJoinedParentHookRetainsRunningCallbackUntilReturn(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var finished atomic.Bool
	join := joinedAfterFunc(parent, func() { close(entered); <-release; finished.Store(true) })
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { unblock(); join() })
	cancel()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("parent stop callback did not start")
	}
	joined := make(chan bool, 1)
	callerDone := make(chan struct{})
	go func() { defer close(callerDone); join(); joined <- finished.Load() }()
	t.Cleanup(func() { unblock(); join(); <-callerDone })
	select {
	case <-joined:
		t.Fatal("hook cleanup returned while its owner callback was held")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	select {
	case complete := <-joined:
		if !complete {
			t.Fatal("hook reported a join before its owner callback completed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("released parent callback did not join")
	}
}
