package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const maxConfigBytes = 256 << 10

func absolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
func privateFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func privateRead(path string, limit int64) ([]byte, error) {
	if !absolute(path) {
		return nil, problem(exitUsage, "private_input_invalid", nil)
	}
	before, err := os.Lstat(path)
	if err != nil || !privateFile(before) || before.Size() > limit {
		return nil, problem(exitUsage, "private_input_invalid", err)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, problem(exitUsage, "private_input_invalid", err)
	}
	opened, statErr := file.Stat()
	if statErr != nil || !privateFile(opened) || !os.SameFile(before, opened) {
		return nil, problem(exitUsage, "private_input_invalid", errors.Join(statErr, file.Close()))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > limit {
		return nil, problem(exitUsage, "private_input_invalid", errors.Join(readErr, closeErr))
	}
	return data, nil
}

type outputFile struct {
	file             *os.File
	path             string
	identity, parent os.FileInfo
	directory        *os.File
}

func privateParent(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func prepareOutput(path string) (*outputFile, error) {
	if !absolute(path) {
		return nil, problem(exitUsage, "private_output_invalid", nil)
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !privateParent(info) {
		return nil, problem(exitUsage, "private_output_invalid", err)
	}
	directory, err := os.OpenFile(parent, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, problem(exitUsage, "private_output_invalid", err)
	}
	opened, err := directory.Stat()
	if err != nil || !privateParent(opened) || !os.SameFile(info, opened) {
		return nil, problem(exitUsage, "private_output_invalid", errors.Join(err, directory.Close()))
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, problem(exitUsage, "private_output_unavailable", errors.Join(err, directory.Close()))
	}
	identity, err := file.Stat()
	owned := &outputFile{file: file, path: path, identity: identity, parent: opened, directory: directory}
	if err != nil || !privateFile(identity) || owned.samePath() != nil {
		return nil, problem(exitCleanup, "output_cleanup_unconfirmed", errors.Join(err, owned.close()))
	}
	if err = errors.Join(file.Sync(), directory.Sync()); err != nil {
		return nil, problem(exitCleanup, "output_cleanup_unconfirmed", errors.Join(err, owned.close()))
	}
	return owned, nil
}

func (o *outputFile) samePath() error {
	parent, err := os.Lstat(filepath.Dir(o.path))
	if err != nil || !privateParent(parent) || !os.SameFile(o.parent, parent) {
		return errors.New("output_namespace_changed")
	}
	current, err := os.Lstat(o.path)
	if err != nil || !privateFile(current) || !os.SameFile(o.identity, current) {
		return errors.New("output_namespace_changed")
	}
	return nil
}

func (o *outputFile) write(data []byte) error {
	if err := o.samePath(); err != nil {
		return problem(exitCleanup, "credential_output_unconfirmed", err)
	}
	if _, err := o.file.Write(data); err != nil {
		return problem(exitCleanup, "credential_output_unconfirmed", err)
	}
	if err := errors.Join(o.file.Sync(), o.directory.Sync(), o.samePath()); err != nil {
		return problem(exitCleanup, "credential_output_unconfirmed", err)
	}
	return nil
}
func (o *outputFile) close() error { return errors.Join(o.file.Close(), o.directory.Close()) }
