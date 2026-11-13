package testsupport

import (
	"os"
	"path/filepath"
	"testing"
)

// PrivateSocketDirectory owns a short private fixture directory independently
// of TMPDIR and test-name length. Call it before registering listener/store
// cleanup so their joins run first. Failed tests retain their evidence.
func PrivateSocketDirectory(t testing.TB) string {
	t.Helper()
	// Linux and Darwin provide /tmp; resolving it also handles Darwin's alias.
	parent, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(parent, "gw-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Socket fixture evidence retained: %s", directory)
			return
		}
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			t.Errorf("remove socket fixture: %v", removeErr)
		}
	})
	return directory
}
