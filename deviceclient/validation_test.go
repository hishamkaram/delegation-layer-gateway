package deviceclient

import "testing"

func TestLocalProfilePathsCannotChangeDuringJSONEncoding(t *testing.T) {
	if localPath("/" + string([]byte{0xff})) {
		t.Fatal("invalid UTF-8 path could be replaced silently by JSON encoding")
	}
}
