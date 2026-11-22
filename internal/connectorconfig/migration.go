package connectorconfig

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

var (
	ErrMigrationRequired           = errors.New("connector_configuration_migration_required")
	ErrMigrationAcceptanceRequired = errors.New("connector_execution_policy_removal_acceptance_required")
)

type MigrationPreview struct {
	FromVersion       int `json:"from_version"`
	ToVersion         int `json:"to_version"`
	Projects          int `json:"projects"`
	ExecutionPolicies int `json:"execution_policies"`
}

type legacyDocument struct {
	document
	Projects []legacyProjectDocument `json:"projects"`
}
type legacyProjectDocument struct {
	projectDocument
	Providers []json.RawMessage `json:"providers"`
}

func migrationDocument(path string) (document, MigrationPreview, error) {
	data, err := privateRead(path, MaxConfigBytes)
	if err != nil {
		return document{}, MigrationPreview{}, err
	}
	var header struct {
		Version int `json:"schema_version"`
	}
	if json.Unmarshal(data, &header) != nil {
		return document{}, MigrationPreview{}, ErrInvalid
	}
	preview := MigrationPreview{FromVersion: header.Version, ToVersion: 2}
	var current document
	switch header.Version {
	case 1:
		var legacy legacyDocument
		if protocol.DecodeStrict(data, &legacy, MaxConfigBytes) != nil {
			return current, preview, ErrInvalid
		}
		current = legacy.document
		current.Version = 2
		current.Projects = make([]projectDocument, 0, len(legacy.Projects))
		for _, project := range legacy.Projects {
			current.Projects = append(current.Projects, project.projectDocument)
		}
		preview.ExecutionPolicies = len(legacy.Projects)
	case 2:
		if protocol.DecodeStrict(data, &current, MaxConfigBytes) != nil {
			return current, preview, ErrInvalid
		}
	default:
		return current, preview, ErrMigrationRequired
	}
	preview.Projects = len(current.Projects)
	return current, preview, nil
}

func PreviewMigration(path string) (MigrationPreview, error) {
	_, preview, err := migrationDocument(path)
	return preview, err
}

// Migrate is explicit offline configuration cutover. The caller quiesces the
// old connector; this lock serializes supported migration writers. Only policy
// fields and schema version change; credential/root/source references persist.
func Migrate(ctx context.Context, path string, acceptExecutionPolicyRemoval bool) (preview MigrationPreview, result error) {
	if ctx == nil || ctx.Err() != nil {
		return preview, ErrInvalid
	}
	if _, _, err := migrationDocument(path); err != nil {
		return preview, err
	}
	lease, err := instance.Acquire(path + ".migration.lock")
	if err != nil {
		return preview, err
	}
	defer func() { result = errors.Join(result, lease.Close()) }()
	current, preview, err := migrationDocument(path)
	if err != nil {
		return preview, err
	}
	if preview.FromVersion == preview.ToVersion {
		return preview, syncMigrationDirectory(path)
	}
	if preview.ExecutionPolicies != 0 && !acceptExecutionPolicyRemoval {
		return preview, ErrMigrationAcceptanceRequired
	}
	identity, err := existingMigrationIdentity(current.IdentityDirectory)
	if err != nil {
		return preview, err
	}
	if identity != nil {
		defer func() { result = errors.Join(result, identity.Close()) }()
	}
	data, err := protocol.Encode(current, MaxConfigBytes)
	if err != nil {
		return preview, ErrInvalid
	}
	return preview, publishMigration(ctx, path, data)
}

func publishMigration(ctx context.Context, path string, data []byte) (result error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	var entropy [16]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return err
	}
	name := ".connector-migration-" + hex.EncodeToString(entropy[:]) + ".tmp"
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := root.Remove(name); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			result = errors.Join(result, cleanupErr)
		}
	}()
	_, writeErr := file.Write(data)
	if err = errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = root.Rename(name, filepath.Base(path)); err != nil {
		return err
	}
	return syncMigrationRoot(root)
}

// A retry may observe a rename whose directory sync previously failed. Confirm
// that publication before acknowledging the already-current schema as durable.
func syncMigrationDirectory(path string) (result error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	return syncMigrationRoot(root)
}

func syncMigrationRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func existingMigrationIdentity(directory string) (*deviceidentity.Store, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrInvalid
	}
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return deviceidentity.Open(directory)
}
