package devicehub

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func TestConnectionFailureWithoutVerifiedIdentity(t *testing.T) {
	f := newFixture(t, Settings{})
	var events []ConnectionObservation
	f.hub.config.ConnectionObserved = func(event ConnectionObservation) { events = append(events, event) }
	out := httptest.NewRecorder()
	f.hub.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "https://gateway.example/device", nil))
	if out.Code != http.StatusForbidden || len(events) != 1 {
		t.Fatalf("invalid registration: status %d observations %d", out.Code, len(events))
	}
	event := events[0]
	if event.State != ConnectionFailed || event.Credential != (domain.CredentialRef{}) || event.Generation != (domain.ConnectionGeneration{}) || event.Duration < 0 {
		t.Fatal("unverified registration acquired an authenticated identity")
	}
}

type observedConnection struct {
	value     ConnectionObservation
	locksFree bool
	joined    bool
}

func observeConnectionLocks(f *fixture, value ConnectionObservation) bool {
	h := f.hub
	if !h.mu.TryLock() {
		return false
	}
	h.mu.Unlock()
	done := make(chan error, 1)
	f.probes.Add(1)
	go func() { defer f.probes.Done(); _, err := h.Snapshot(value.Credential.Device); done <- err }()
	select {
	case err := <-done:
		return err == nil || errors.Is(err, transport.ErrOffline)
	case <-time.After(time.Second):
		return false
	}
}

func observed(f *fixture, value ConnectionObservation) observedConnection {
	snapshot, err := f.hub.Snapshot(value.Credential.Device)
	if err != nil {
		return observedConnection{value: value, locksFree: observeConnectionLocks(f, value)}
	}
	return observedConnection{value: value, locksFree: observeConnectionLocks(f, value), joined: snapshot.Joined}
}

func nextConnection(t *testing.T, events <-chan observedConnection) observedConnection {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("connection observation did not arrive")
		return observedConnection{}
	}
}

func TestConnectionObservationsBindJoinedSessionOutsideMutexes(t *testing.T) {
	f := newFixture(t, Settings{})
	events := make(chan observedConnection, 2)
	f.hub.config.ConnectionObserved = func(value ConnectionObservation) {
		events <- observed(f, value)
	}
	client := f.dial(t)
	established := nextConnection(t, events)
	if established.value.State != ConnectionEstablished || !established.locksFree || established.value.Credential != f.store.value.Ref || established.value.Generation != client.Generation() {
		t.Fatal("established observation lost verified binding or held an owner mutex")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	closed := nextConnection(t, events)
	if closed.value.State != ConnectionClosed || !closed.locksFree || closed.value.Credential != established.value.Credential || closed.value.Generation != established.value.Generation || closed.value.Duration < established.value.Duration {
		t.Fatal("closed observation lost the original connection or held an owner mutex")
	}
	if !closed.joined {
		t.Fatal("closed observation preceded the original socket worker join")
	}
}

func openUnfinishedHandshake(t *testing.T, f *fixture, ctx context.Context) *websocket.Conn {
	t.Helper()
	conn, response, err := websocket.Dial(ctx, f.config().URL, &websocket.DialOptions{HTTPClient: f.http, Subprotocols: []string{protocol.Subprotocol}})
	if response != nil && response.Body != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := conn.CloseNow(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Error(closeErr)
		}
	})
	if _, _, err = conn.Read(ctx); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestConnectionFailedHandshakeNeverAdvertisesEstablishedOrClosed(t *testing.T) {
	f := newFixture(t, Settings{})
	events := make(chan observedConnection, 3)
	f.hub.config.ConnectionObserved = func(value ConnectionObservation) {
		events <- observed(f, value)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn := openUnfinishedHandshake(t, f, ctx)
	if f.hub.ActiveConnections() != 0 {
		t.Fatal("unfinished handshake was counted as an active connection")
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	event := nextConnection(t, events)
	if event.value.State != ConnectionFailed || !event.locksFree || event.value.Credential != f.store.value.Ref || event.value.Generation.Validate() != nil {
		t.Fatal("failed verified handshake lost binding or became a ready connection")
	}
	if err := f.hub.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
		t.Fatal("failed handshake produced additional established/closed observations")
	default:
	}
}

func TestActiveConnectionsCountsOnlyReadyUnclosedOwner(t *testing.T) {
	f := newFixture(t, Settings{})
	if f.hub.ActiveConnections() != 0 {
		t.Fatal("empty Hub counted an active connection")
	}
	f.dial(t)
	if f.hub.ActiveConnections() != 1 {
		t.Fatal("ready connection was not counted")
	}
	if err := f.hub.DisconnectContext(t.Context(), "device-one"); err != nil {
		t.Fatal(err)
	}
	if f.hub.ActiveConnections() != 0 {
		t.Fatal("closed connection retained an active gauge slot")
	}
	if err := f.hub.Close(); err != nil {
		t.Fatal(err)
	}
	if f.hub.ActiveConnections() != 0 {
		t.Fatal("closed Hub advertised an active connection")
	}
}

func TestConnectionFailureCallbackRemainsJoinedByHubClose(t *testing.T) {
	f := newFixture(t, Settings{})
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f.hub.config.ConnectionObserved = func(value ConnectionObservation) {
		if value.State == ConnectionFailed {
			close(entered)
			<-release
		}
	}
	handlerDone, closeDone := make(chan struct{}), make(chan struct{})
	closeStarted := false
	t.Cleanup(func() {
		unblock()
		<-handlerDone
		if closeStarted {
			<-closeDone
		}
	})
	go func() {
		defer close(handlerDone)
		f.hub.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://gateway.example/device", nil))
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("failed registration callback did not enter")
	}
	closeStarted = true
	var closeErr error
	go func() { closeErr = f.hub.Close(); close(closeDone) }()
	<-f.hub.ctx.Done()
	select {
	case <-closeDone:
		t.Fatal("Hub.Close escaped the active failure callback")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Hub.Close did not join the released failure callback")
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}
