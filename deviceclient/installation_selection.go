package deviceclient

import (
	"context"
	"errors"
	"os"
)

// ProfileMigrationSource reads old/current local source identity without
// credentials or mutation, including when the saved executable is missing.
func ProfileMigrationSource(ctx context.Context, directory string) (source LocalContextInfo, result error) {
	if ctx == nil || ctx.Err() != nil {
		return source, ErrConfiguration
	}
	store, err := openProfileMode(directory, false, false, true)
	if err != nil {
		return source, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrPersistence, closeErr))
		}
	}()
	if store.value == nil {
		return source, ErrProfile
	}
	if err = store.directory.Sync(); err != nil {
		return source, failed(ErrPersistence, err)
	}
	return profileLocalContext(*store.value), nil
}

// UpdateInstallationSelection is the explicit source handoff after Native's
// installation owner has quiesced the connector and verified the selected
// installed binary's public capabilities and the original Native root identity.
// The profile lock fences source CAS; the identity lease excludes a live SDK
// connector producer. Neither lease proves Native task closure or stops tasks.
func UpdateInstallationSelection(ctx context.Context, directory string, expected, selected InstallationSelection) (result error) {
	if ctx == nil || ctx.Err() != nil {
		return ErrConfiguration
	}
	if err := checkInstallationSelection(expected, selected); err != nil {
		return err
	}
	store, err := openProfile(directory, false, true)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrPersistence, closeErr))
		}
	}()
	if store.value == nil {
		return ErrProfile
	}
	p := *store.value
	current := InstallationSelection{DelegateExecutable: p.DelegateExecutable, DelegateRoot: p.DelegateRoot, DelegateRootContext: p.DelegateRootContext}
	if current != expected {
		return ErrConflict
	}
	identity, err := migrationIdentityLease(directory)
	if err != nil {
		return err
	}
	if identity != nil {
		defer func() {
			if closeErr := identity.Close(); closeErr != nil {
				result = errors.Join(result, failed(ErrPersistence, closeErr))
			}
		}()
	}
	if err = ctx.Err(); err != nil {
		return failed(ErrPersistence, err)
	}
	p.DelegateExecutable = selected.DelegateExecutable
	return store.savePartition(p, true)
}

func checkInstallationSelection(expected, selected InstallationSelection) error {
	if !localPath(selected.DelegateExecutable) || selected.DelegateRoot != expected.DelegateRoot || selected.DelegateRootContext != expected.DelegateRootContext {
		return ErrConfiguration
	}
	executable, err := os.Stat(selected.DelegateExecutable)
	if err != nil || !executable.Mode().IsRegular() || executable.Mode().Perm()&0o111 == 0 {
		return ErrConfiguration
	}
	return nil
}
