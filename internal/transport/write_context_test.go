package transport

import (
	"context"
	"sync"
	"testing"
	"time"
)

type requestAuthorityKey struct{}

func TestWriteContextPreservesRequestAuthorityAndBothLifetimes(t *testing.T) {
	for _, parent := range []string{"request", "socket", "cleanup"} {
		t.Run(parent, func(t *testing.T) {
			socket, stopSocket := context.WithCancel(t.Context())
			defer stopSocket()
			request, stopRequest := context.WithCancel(context.WithValue(t.Context(), requestAuthorityKey{}, "originating-proof"))
			defer stopRequest()
			s := &session{ctx: socket, settings: Settings{WriteTimeout: time.Second}}
			call, cleanup := s.writeContext(request)
			defer cleanup()
			if call.Value(requestAuthorityKey{}) != "originating-proof" || socket.Value(requestAuthorityKey{}) != nil {
				t.Fatal("request authority lost or promoted to socket")
			}
			switch parent {
			case "request":
				stopRequest()
			case "socket":
				stopSocket()
			case "cleanup":
				cleanup()
			}
			select {
			case <-call.Done():
			case <-time.After(time.Second):
				t.Fatal("write outlived its owner")
			}
			// context.CancelFunc permits repeated and concurrent cleanup. The socket
			// cancellation callback must be joined or stopped on every path.
			var joined sync.WaitGroup
			joined.Go(cleanup)
			joined.Go(cleanup)
			joined.Wait()
		})
	}
}

func TestWriteContextCannotExtendRequestDeadline(t *testing.T) {
	socket, stop := context.WithCancel(t.Context())
	defer stop()
	deadline := time.Now().Add(time.Hour)
	request, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	s := &session{ctx: socket, settings: Settings{WriteTimeout: 2 * time.Hour}}
	call, cleanup := s.writeContext(request)
	defer cleanup()
	got, ok := call.Deadline()
	if !ok || !got.Equal(deadline) {
		t.Fatal("socket write extended request deadline")
	}
}
