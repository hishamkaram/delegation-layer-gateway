package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type diagnosticCloseTransport struct {
	next           http.RoundTripper
	failure        error
	client         atomic.Pointer[Client]
	closed         atomic.Bool
	closedCanceled atomic.Bool
}

func (t *diagnosticCloseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		return response, err
	}
	body, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		return nil, errors.Join(errors.New("fixture upgrade body is not writable"), response.Body.Close())
	}
	response.Body = &diagnosticCloseBody{ReadWriteCloser: body, owner: t}
	return response, nil
}

type diagnosticCloseBody struct {
	io.ReadWriteCloser
	owner *diagnosticCloseTransport
}

func (b *diagnosticCloseBody) Close() error {
	if client := b.owner.client.Load(); client != nil && client.session.ctx.Err() != nil {
		b.owner.closedCanceled.Store(true)
	}
	err := b.ReadWriteCloser.Close()
	if err == nil || errors.Is(err, net.ErrClosed) {
		b.owner.closed.Store(true)
	}
	return errors.Join(err, b.owner.failure)
}

func TestExplicitCloseOwnsSocketBeforeCancellingReaders(t *testing.T) {
	f := newFixture(t, Settings{HeartbeatInterval: time.Hour, OfflineTimeout: 2 * time.Hour})
	injected := errors.New("diagnostic after upgraded socket close")
	client, observer := dialDiagnosticClient(t, f, t.Context(), injected)
	watchdog, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := f.hub.WaitReady(watchdog, "device-one"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if closeErr := client.Close(); !errors.Is(closeErr, injected) {
			t.Fatal("close lost its actual observed diagnostic", closeErr)
		}
	}
	if !observer.closed.Load() || observer.closedCanceled.Load() {
		t.Fatal("session cancellation raced ahead of its owned physical socket close")
	}
	select {
	case <-client.session.done:
	default:
		t.Fatal("close returned before its session workers joined")
	}
}

func TestParentCancellationAndDeadlineJoinPhysicalSocket(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) { assertParentSocketJoin(t, mode, nil) })
	}
}

func TestParentStopOwnsDiagnosticBeforeReaderCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			assertParentSocketJoin(t, mode, errors.New("diagnostic on same-parent shutdown"))
		})
	}
}

func assertParentSocketJoin(t *testing.T, mode string, fault error) {
	t.Helper()
	f := newFixture(t, Settings{HeartbeatInterval: time.Hour, OfflineTimeout: 2 * time.Hour})
	// Establishing the fixture's CA/listener precedes this finite owner
	// lifetime. The deadline path exercises an actual context deadline.
	owner, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	t.Cleanup(cancel)
	client, observer := dialDiagnosticClient(t, f, owner, fault)
	if err := f.hub.WaitReady(owner, "device-one"); err != nil {
		t.Fatal(err)
	}
	if mode == "cancel" {
		cancel()
	}
	<-owner.Done()
	want := context.Canceled
	if mode == "deadline" {
		want = context.DeadlineExceeded
	}
	if !errors.Is(owner.Err(), want) {
		t.Fatal("fixture did not end through the selected parent cause")
	}
	assertParentSocketClose(t, client, observer, fault)
}

func assertParentSocketClose(t *testing.T, client *Client, observer *diagnosticCloseTransport, fault error) {
	t.Helper()
	// Parent cancellation alone must stop and join the session. Calling Close
	// first would let a detached session without its parent hook pass this test.
	select {
	case <-client.session.done:
	case <-time.After(5 * time.Second):
		t.Fatal("parent cancellation did not stop and join its socket owner")
	}
	closeErr := client.Close()
	if fault == nil {
		if closeErr != nil {
			t.Fatal("normal externally cancelled close failed", closeErr)
		}
	} else if !errors.Is(closeErr, fault) {
		t.Fatal("parent cancellation hid the actual close diagnostic", closeErr)
	}
	if !observer.closed.Load() || observer.closedCanceled.Load() {
		t.Fatal("parent bypassed socket ownership before cancelling its reader")
	}
	select {
	case <-client.session.done:
	default:
		t.Fatal("external cancellation returned before its workers joined")
	}
}

func dialDiagnosticClient(t *testing.T, f *fixture, ctx context.Context, failure error) (*Client, *diagnosticCloseTransport) {
	t.Helper()
	observer := &diagnosticCloseTransport{next: f.http.Transport, failure: failure}
	clientHTTP := *f.http
	clientHTTP.Transport = observer
	client, err := Dial(ctx, f.config(), &clientHTTP, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	observer.client.Store(client)
	t.Cleanup(func() {
		closeErr := client.Close()
		if failure == nil {
			if closeErr != nil {
				t.Error(closeErr)
			}
		} else if !errors.Is(closeErr, failure) {
			t.Error("close did not preserve its observed diagnostic", closeErr)
		}
	})
	return client, observer
}

func TestObservedCloseErrorsPreserveIndependentDiagnostics(t *testing.T) {
	injected := errors.New("independent close failure")
	for _, test := range []struct {
		name string
		err  error
		keep bool
	}{
		{name: "nil"},
		{name: "closed", err: net.ErrClosed},
		{name: "wrapped-closed", err: fmt.Errorf("socket close: %w", net.ErrClosed)},
		{name: "single-join-closed", err: errors.Join(net.ErrClosed, nil)},
		{name: "independent", err: injected, keep: true},
		{name: "mixed-closed", err: errors.Join(net.ErrClosed, injected), keep: true},
		{name: "wrapped-mixed", err: fmt.Errorf("socket close: %w", errors.Join(net.ErrClosed, injected)), keep: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &session{}
			s.recordCloseError(test.err)
			actual := s.closeFailure()
			if test.keep {
				if !errors.Is(actual, injected) || !errors.Is(actual, test.err) {
					t.Fatal("observed diagnostic disappeared behind an already-closed cause")
				}
			} else if actual != nil {
				t.Fatal("a sole benign close cause became a diagnostic", actual)
			}
		})
	}
}
