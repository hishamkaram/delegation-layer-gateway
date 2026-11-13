package instance

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExclusiveLeaseAndStableInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := first.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, duplicateErr := Acquire(path); !errors.Is(duplicateErr, ErrBusy) {
		if duplicate != nil {
			t.Error(duplicate.Close())
		}
		t.Fatalf("second owner: %v", duplicateErr)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := second.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("lease inode replaced: %v", err)
	}
}

func TestLeaseRejectsSymlinkAndPublicMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public.lock")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if lease, err := Acquire(path); err == nil {
		t.Error(lease.Close())
		t.Fatal("public lease accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if lease, err := Acquire(link); err == nil {
		t.Error(lease.Close())
		t.Fatal("symlink lease accepted")
	}
}
