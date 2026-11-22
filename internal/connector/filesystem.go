package connector

import (
	"context"
	"errors"
	"slices"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Local filesystem DTOs consume Native's public CLI. Raw local approval tokens
// and directory paths never enter the wire response or public diagnostics.
type cliFilesystemScope struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Directory string `json:"directory"`
}

type cliFilesystemResult struct {
	protocol.FilesystemResponse
	Scopes *struct {
		Scopes []cliFilesystemScope `json:"scopes"`
	} `json:"scopes,omitempty"`
}

type filesystemScope struct {
	Kind              string `json:"kind"`
	Directory         string `json:"directory,omitempty"`
	ExpectedWorkspace string `json:"expected_workspace,omitempty"`
}

type cliFilesystemRequest struct {
	ExpectedRoot       string          `json:"expected_root"`
	Scope              filesystemScope `json:"scope"`
	RelativePath       string          `json:"relative_path,omitempty"`
	RelativePathBase64 string          `json:"relative_path_base64,omitempty"`
	Cursor             string          `json:"cursor,omitempty"`
	Limit              int             `json:"limit,omitempty"`
	Offset             int64           `json:"offset,omitempty"`
	ExpectedVersion    string          `json:"expected_version,omitempty"`
}

func (a *Adapter) decodeFilesystem(ctx context.Context, r request) (request, error) {
	var input protocol.FilesystemRequest
	if protocol.DecodeStrict(r.command.Body, &input, 64<<10) != nil || input.ValidateFor(r.command.Operation) != nil {
		return request{}, ErrEvidence
	}
	snapshot, err := r.config.ProjectStore.Snapshot(ctx)
	if err != nil {
		return request{}, err
	}
	if !validRootSnapshot(snapshot) || protocol.WireContextGuard(snapshot.RootContext) != r.command.Root {
		return request{}, ErrConflict
	}
	r.project = Project{Root: snapshot.RootDirectory, RootToken: snapshot.RootContext}
	r.filesystem = &input
	if r.command.Operation != protocol.FilesystemScopes {
		scope, err := selectFilesystemScope(snapshot, input.Selection.ScopeID)
		if err != nil {
			return request{}, err
		}
		r.filesystemScope = scope
	}
	return r, nil
}

func selectFilesystemScope(snapshot WorkspaceSnapshot, id string) (filesystemScope, error) {
	switch id {
	case protocol.UserTempScope:
		return filesystemScope{Kind: "user_temp"}, nil
	case protocol.SharedTempScope:
		return filesystemScope{Kind: "shared_temp"}, nil
	}
	for _, workspace := range snapshot.Workspaces {
		if workspace.ID == id && workspace.Enabled {
			return filesystemScope{Kind: "workspace", Directory: workspace.Directory, ExpectedWorkspace: workspace.NativeContext}, nil
		}
	}
	return filesystemScope{}, ErrConflict
}

func (r request) filesystemStartGuard(ctx context.Context) (func() error, error) {
	lease, err := r.config.ProjectStore.Lock(ctx)
	if err != nil {
		return nil, err
	}
	if err = r.checkFilesystemSnapshot(lease.Snapshot()); err != nil {
		return nil, errors.Join(err, lease.Close())
	}
	return lease.Close, nil
}

func (r request) checkFilesystemSnapshot(snapshot WorkspaceSnapshot) error {
	if snapshot.RootDirectory != r.project.Root || snapshot.RootContext != r.project.RootToken {
		return ErrConflict
	}
	if r.command.Operation == protocol.FilesystemScopes {
		return nil
	}
	scope, err := selectFilesystemScope(snapshot, r.filesystem.Selection.ScopeID)
	if err != nil {
		return err
	}
	if scope != r.filesystemScope {
		return ErrConflict
	}
	return nil
}

func (a *Adapter) executeFilesystem(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	root, err := a.verifiedRoot(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if !slices.Contains(root.Features, protocol.FeatureFilesystem) {
		return failed(r.command.Operation, ErrUnsupported)
	}
	response, err := a.runFilesystem(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if response.Failure != nil {
		return nativeFailureReply(r.command.Operation, response.Failure)
	}
	if response.exitCode != 0 || response.Filesystem == nil {
		return failed(r.command.Operation, ErrEvidence)
	}
	result, err := normalizedFilesystemResponse(r.command.Operation, response.Filesystem)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if result.ValidateFor(r.command.Operation, *r.filesystem) != nil {
		return failed(r.command.Operation, ErrEvidence)
	}
	return a.publishMetadata(ctx, r, result)
}

func filesystemAction(operation protocol.Operation) (string, error) {
	switch operation {
	case protocol.FilesystemScopes:
		return "scopes", nil
	case protocol.ListDirectory:
		return "list", nil
	case protocol.ReadFile:
		return "read", nil
	case protocol.InspectFile:
		return "inspect", nil
	case protocol.InspectGit:
		return "git", nil
	case protocol.ProviderModels, protocol.SelectProject, protocol.ContextInspect, protocol.Admit, protocol.Continue, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen, protocol.ResolveProject:
		return "", ErrEvidence
	default:
		return "", ErrEvidence
	}
}

func normalizedFilesystemResponse(operation protocol.Operation, response *cliFilesystemResult) (protocol.FilesystemResponse, error) {
	result := response.FilesystemResponse
	if operation != protocol.FilesystemScopes {
		return result, nil
	}
	if response.Scopes == nil {
		return result, ErrEvidence
	}
	result.Scopes = &protocol.FilesystemScopesResult{Scopes: []protocol.FilesystemScope{}}
	for _, scope := range response.Scopes.Scopes {
		id := ""
		switch scope.Kind {
		case "user_temp":
			id = protocol.UserTempScope
		case "shared_temp":
			id = protocol.SharedTempScope
		default:
			return result, ErrEvidence
		}
		result.Scopes.Scopes = append(result.Scopes.Scopes, protocol.FilesystemScope{ID: id, Kind: scope.Kind, Name: id})
	}
	return result, nil
}

func (a *Adapter) runFilesystem(ctx context.Context, r request, owner *controlOwner) (cliResponse, error) {
	input := r.filesystem
	selection := cliFilesystemRequest{ExpectedRoot: r.project.RootToken, Scope: r.filesystemScope, RelativePath: input.Selection.RelativePath, RelativePathBase64: input.Selection.RelativePathBase64, Cursor: input.Cursor, Limit: input.Limit, Offset: input.Offset, ExpectedVersion: input.ExpectedVersion}
	if r.command.Operation == protocol.FilesystemScopes {
		selection.Scope = filesystemScope{}
	}
	data, err := protocol.Encode(selection, MaxWorkspaceStdoutBytes)
	if err != nil {
		return cliResponse{}, ErrEvidence
	}
	file, err := owner.file("filesystem.json", data)
	if err != nil {
		return cliResponse{}, err
	}
	action, err := filesystemAction(r.command.Operation)
	if err != nil {
		return cliResponse{}, err
	}
	call, err := r.common(ctx, "filesystem", action, "--request", file)
	if err != nil {
		return cliResponse{}, err
	}
	call.directory = owner.temporary
	call.startGuard = r.filesystemStartGuard
	return a.run(ctx, call)
}
