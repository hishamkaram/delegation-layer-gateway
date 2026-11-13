package transport

import "testing"

func TestActiveConnectionsExcludeClosingSessionBeforeOwnerRetires(t *testing.T) {
	f := newFixture(t, Settings{})
	f.dial(t)
	s, err := f.hub.current("device-one")
	if err != nil {
		t.Fatal(err)
	}
	s.stop(fail(ErrOffline, nil))
	if f.hub.ActiveConnections() != 0 {
		t.Fatal("closing connection retained an active gauge slot")
	}
	waitClosed(t, s)
}
