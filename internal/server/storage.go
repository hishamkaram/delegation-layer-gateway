package server

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
)

func privateDirectory(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func validateStorage(cfg config.Gateway) error {
	for _, parent := range []string{filepath.Dir(cfg.Database), filepath.Dir(cfg.AdminSocket), cfg.AuditDirectory} {
		if !privateDirectory(parent) {
			return ErrUnavailable
		}
	}
	for _, path := range []string{cfg.Database, cfg.Database + "-wal", cfg.Database + "-shm", cfg.Database + "-journal"} {
		if err := privateExistingFile(path); err != nil {
			return err
		}
	}
	return nil
}

func privateExistingFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return ErrUnavailable
	}
	return nil
}
