package deviceclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
)

// LocalContext reads the exact selected Native installation/root identity for
// local inspection. The caller must use the saved opaque root token unchanged.
func LocalContext(ctx context.Context, directory string) (value LocalContextInfo, result error) {
	if ctx == nil {
		return value, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return value, failed(ErrProfile, err)
	}
	store, err := openProfile(directory, false, false)
	if err != nil {
		return value, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrProfile, closeErr))
		}
	}()
	if store.value == nil {
		return value, ErrProfile
	}
	p := store.value
	return LocalContextInfo{DelegateExecutable: p.DelegateExecutable, DelegateRoot: p.DelegateRoot, DelegateRootContext: p.DelegateRootContext, Providers: clonePolicies(p.Providers)}, nil
}

// RuntimeInactive briefly owns the identity file lease. True proves only that
// no current local identity owner prevented this acquisition; it proves neither
// Delegate task/CLI closure nor that another runtime cannot start afterward.
// It acquires no service-directory flock or profile file lease.
func RuntimeInactive(ctx context.Context, directory string) (inactive bool, result error) {
	if ctx == nil {
		return false, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return false, failed(ErrProfile, err)
	}
	profile, err := openProfile(directory, false, false)
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := profile.Close(); closeErr != nil {
			inactive = false
			result = errors.Join(result, failed(ErrProfile, closeErr))
		}
	}()
	if profile.value == nil {
		return false, ErrProfile
	}
	identityPath := filepath.Join(directory, "identity")
	if _, err = os.Lstat(identityPath); err != nil {
		return false, failed(ErrProfile, err)
	}
	store, err := deviceidentity.Open(identityPath)
	if errors.Is(err, deviceidentity.ErrBusy) {
		return false, nil
	}
	if err != nil {
		return false, failed(ErrProfile, err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			inactive = false
			result = errors.Join(result, failed(ErrProfile, closeErr))
		}
	}()
	if err = enrolledLocalIdentity(store); err != nil {
		return false, err
	}

	if err = ctx.Err(); err != nil {
		return false, failed(ErrProfile, err)
	}
	return true, nil
}

func enrolledLocalIdentity(store *deviceidentity.Store) error {
	intent, err := store.EnrollmentIntent()
	if errors.Is(err, deviceidentity.ErrAbsent) {
		return ErrEnrollment
	}
	if err != nil {
		return failed(ErrProfile, err)
	}
	if !intent.Completed {
		return ErrEnrollment
	}
	if _, _, err = store.CredentialMetadata(); err != nil {
		return failed(ErrProfile, err)
	}
	return nil
}

// openExistingIdentity never creates an unenrolled identity directory as a
// side effect of runtime/revocation inspection. Busy remains actionable.
func openExistingIdentity(directory string) (*deviceidentity.Store, error) {
	path := filepath.Join(directory, "identity")
	if _, err := os.Lstat(path); err != nil {
		return nil, failed(ErrProfile, err)
	}
	store, err := deviceidentity.Open(path)
	if errors.Is(err, deviceidentity.ErrBusy) {
		return nil, failed(ErrBusy, err)
	}
	if err != nil {
		return nil, failed(ErrProfile, err)
	}
	return store, nil
}
