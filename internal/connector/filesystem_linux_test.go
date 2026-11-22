//go:build linux

package connector

import "testing"

func TestFilesystemReadPreservesNonUTF8PathAndCreatesNoPins(t *testing.T) {
	testFilesystemReadPreservesExactBytesAndCreatesNoPins(t, string([]byte{'f', 255}))
}
