package mcpadapter

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type FilesystemTools interface {
	ObserveFilesystem(context.Context, domain.Actor, domain.DeviceID, protocol.Operation, protocol.FilesystemRequest) (gateway.MetadataObservation[protocol.FilesystemResponse], error)
	metadataChecker
}

type filesystemOutput struct {
	protocol.FilesystemResponse
	source gateway.MetadataSource
}

func (o filesystemOutput) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	return a.options.Filesystem.CheckMetadataObservation(ctx, actor, o.source, nil)
}

type DirectoryInput struct {
	DeviceID           string `json:"device_id"`
	ScopeID            string `json:"scope_id"`
	RelativePath       string `json:"relative_path,omitempty"`
	RelativePathBase64 string `json:"relative_path_base64,omitempty"`
	Cursor             string `json:"cursor,omitempty"`
	Limit              int    `json:"limit,omitempty"`
}

type FileReadInput struct {
	DeviceID           string `json:"device_id"`
	ScopeID            string `json:"scope_id"`
	RelativePath       string `json:"relative_path,omitempty"`
	RelativePathBase64 string `json:"relative_path_base64,omitempty"`
	Offset             int64  `json:"offset,omitempty"`
	Limit              int    `json:"limit,omitempty"`
	ExpectedVersion    string `json:"expected_version,omitempty"`
}

type FileInspectInput struct {
	DeviceID           string `json:"device_id"`
	ScopeID            string `json:"scope_id"`
	RelativePath       string `json:"relative_path,omitempty"`
	RelativePathBase64 string `json:"relative_path_base64,omitempty"`
}

func (a *Adapter) registerFilesystemTools() error {
	if a.options.Filesystem == nil {
		return nil
	}
	scopes := []domain.Scope{domain.TaskDispatch, domain.TaskRead}
	hints := toolHints{ReadOnly: true, Idempotent: true, AllScopes: true}
	return errors.Join(
		register(a, "list_directory", "Browse a real directory on the explicit device inside an approved workspace or automatic OS temporary scope. Includes hidden entries and Git candidates. Pages are live observations; continue next_cursor. No project alias or registration is needed.", scopes, hints, a.listDirectory),
		register(a, "read_file", "Read the requested file range in a selected approved workspace or OS temporary scope. Returns exact bytes as base64 and UTF-8 text where valid. Continue next_offset until EOF; expected_version detects ordinary metadata changes, not an atomic snapshot.", scopes, hints, a.readFile),
		register(a, "inspect_git", "Inspect rooted structural Git evidence for a selected directory. A candidate or partial marker is not validated repository identity. Selection does not require Git. No Git command or task is executed.", scopes, hints, a.inspectGit),
	)
}

func (a *Adapter) listDirectory(ctx context.Context, actor domain.Actor, input DirectoryInput) (filesystemOutput, error) {
	return a.readFilesystem(ctx, actor, input.DeviceID, protocol.ListDirectory, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: input.ScopeID, RelativePath: input.RelativePath, RelativePathBase64: input.RelativePathBase64}, Cursor: input.Cursor, Limit: input.Limit})
}

func (a *Adapter) readFile(ctx context.Context, actor domain.Actor, input FileReadInput) (filesystemOutput, error) {
	return a.readFilesystem(ctx, actor, input.DeviceID, protocol.ReadFile, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: input.ScopeID, RelativePath: input.RelativePath, RelativePathBase64: input.RelativePathBase64}, Offset: input.Offset, Limit: input.Limit, ExpectedVersion: input.ExpectedVersion})
}

func (a *Adapter) inspectGit(ctx context.Context, actor domain.Actor, input FileInspectInput) (filesystemOutput, error) {
	return a.readFilesystem(ctx, actor, input.DeviceID, protocol.InspectGit, protocol.FilesystemRequest{Selection: protocol.FileSelection{ScopeID: input.ScopeID, RelativePath: input.RelativePath, RelativePathBase64: input.RelativePathBase64}})
}

func (a *Adapter) readFilesystem(ctx context.Context, actor domain.Actor, device string, operation protocol.Operation, request protocol.FilesystemRequest) (filesystemOutput, error) {
	if domain.CredentialToken(device) != nil || request.ValidateFor(operation) != nil {
		return filesystemOutput{}, domain.ErrInvalid
	}
	if err := a.authorizeFilesystem(ctx, actor, device); err != nil {
		return filesystemOutput{}, err
	}
	observed, err := a.options.Filesystem.ObserveFilesystem(ctx, actor, domain.DeviceID(device), operation, request)
	if err != nil {
		return filesystemOutput{}, err
	}
	if observed.Value.ValidateFor(operation, request) != nil || !metadataSourceMatches(observed.Source, domain.DeviceID(device), operation) {
		return filesystemOutput{}, domain.Reject(domain.EvidenceInvalid)
	}
	return filesystemOutput{FilesystemResponse: observed.Value, source: observed.Source}, nil
}

func (a *Adapter) authorizeFilesystem(ctx context.Context, actor domain.Actor, device string) error {
	authority, err := a.options.Registry.AuthorizeOwnedDevice(ctx, domain.OwnedDeviceRequest{Actor: actor, Device: domain.DeviceID(device), Scope: domain.TaskDispatch})
	if err != nil {
		return err
	}
	if !actor.Scopes.Has(domain.TaskRead) || !authority.Policy.Scopes.Has(domain.TaskRead) {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

// These values carry only public routing IDs. Registry remains the current
// authority; recheck after both Native output and the final encoding/audit gate.
func (i DirectoryInput) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	return a.authorizeFilesystem(ctx, actor, i.DeviceID)
}

func (i FileReadInput) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	return a.authorizeFilesystem(ctx, actor, i.DeviceID)
}

func (i FileInspectInput) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	return a.authorizeFilesystem(ctx, actor, i.DeviceID)
}
