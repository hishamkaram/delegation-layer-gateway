package deviceclient

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// ProfileMigrationPreview contains counts and public Gateway identity only.
// Source paths, Native tokens and credentials never enter migration diagnostics.
type ProfileMigrationPreview struct {
	FromVersion        int    `json:"from_version"`
	ToVersion          int    `json:"to_version"`
	GatewayID          string `json:"gateway_id"`
	Workspaces         int    `json:"workspaces"`
	DisabledWorkspaces int    `json:"disabled_workspaces"`
	Pins               int    `json:"pins"`
	ExecutionPolicies  int    `json:"execution_policies"`
}

type ProfileMigrationOptions struct {
	ProfileDirectory             string
	AcceptExecutionPolicyRemoval bool
}

func (ProfileMigrationOptions) String() string     { return "gateway_profile_migration_options" }
func (o ProfileMigrationOptions) GoString() string { return o.String() }

// Obsolete policy bytes are decoded only by explicit migration. They carry no
// authority and are discarded without interpreting Native execution choices.
type legacyProfileDocument struct {
	profile
	Providers  []json.RawMessage       `json:"providers"`
	Workspaces []legacyWorkspaceRecord `json:"workspaces"`
}

type legacyWorkspaceRecord struct {
	workspaceRecord
	Providers []json.RawMessage `json:"providers"`
}

func decodeProfileDocument(data []byte, version int) (profile, ProfileMigrationPreview, error) {
	var current profile
	preview := ProfileMigrationPreview{FromVersion: version, ToVersion: 3}
	switch version {
	case 2:
		var legacy legacyProfileDocument
		if protocol.DecodeStrict(data, &legacy, maxProfileBytes) != nil {
			return current, preview, ErrProfile
		}
		current = legacy.profile
		current.Version = 3
		preview.ExecutionPolicies = 1 + len(legacy.Workspaces)
		current.Workspaces = make([]workspaceRecord, 0, len(legacy.Workspaces))
		for _, workspace := range legacy.Workspaces {
			current.Workspaces = append(current.Workspaces, workspace.workspaceRecord)
		}
	case 3:
		if protocol.DecodeStrict(data, &current, maxProfileBytes) != nil {
			return current, preview, ErrProfile
		}
	default:
		return current, preview, ErrMigrationRequired
	}
	preview.GatewayID, preview.Workspaces, preview.Pins = current.Descriptor.GatewayID, len(current.Workspaces), len(current.Pins)
	for _, workspace := range current.Workspaces {
		if !workspace.Enabled {
			preview.DisabledWorkspaces++
		}
	}
	return current, preview, nil
}

func PreviewProfileMigration(ctx context.Context, directory string) (ProfileMigrationPreview, error) {
	return migrateProfile(ctx, ProfileMigrationOptions{ProfileDirectory: directory}, false)
}

// MigrateProfile publishes schema 3 under the profile and existing identity
// leases. It never changes or reenrolls credentials and never retargets roots.
// Callers quiesce old writers before invoking this supported offline transition.
func MigrateProfile(ctx context.Context, options ProfileMigrationOptions) (ProfileMigrationPreview, error) {
	return migrateProfile(ctx, options, true)
}

func migrateProfile(ctx context.Context, options ProfileMigrationOptions, apply bool) (preview ProfileMigrationPreview, result error) {
	if ctx == nil || ctx.Err() != nil {
		return preview, ErrConfiguration
	}
	store, err := openProfileMode(options.ProfileDirectory, false, apply, true)
	if err != nil {
		return preview, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrPersistence, closeErr))
		}
	}()
	if store.value == nil || store.migration == nil {
		return preview, ErrProfile
	}
	preview = *store.migration
	if !apply {
		return preview, nil
	}
	if preview.FromVersion == preview.ToVersion {
		if syncErr := store.directory.Sync(); syncErr != nil {
			return preview, failed(ErrPersistence, syncErr)
		}
		return preview, nil
	}
	if preview.ExecutionPolicies != 0 && !options.AcceptExecutionPolicyRemoval {
		return preview, ErrMigrationAcceptanceRequired
	}
	return preview, publishProfileMigration(ctx, options.ProfileDirectory, store)
}

func publishProfileMigration(ctx context.Context, directory string, store *profileStore) (result error) {
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
	return store.savePartition(*store.value, true)
}

// The profile lease fences Connect, the sole identity creator. OpenRuntime uses
// existing-only identity access, so absence needs no synthetic identity store.
func migrationIdentityLease(directory string) (*deviceidentity.Store, error) {
	if _, err := os.Lstat(filepath.Join(directory, "identity")); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, failed(ErrProfile, err)
	}
	return openExistingIdentity(directory)
}
