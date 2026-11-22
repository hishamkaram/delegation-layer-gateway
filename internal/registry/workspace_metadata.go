package registry

import (
	"context"
	"database/sql"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func validateWorkspaceScopes(scopes domain.ScopeSet) error {
	if len(scopes) == 0 || scopes.Validate() != nil || !scopes.Has(domain.TaskDispatch) {
		return domain.ErrInvalid
	}
	for _, scope := range scopes {
		if !scope.IsTask() {
			return domain.ErrInvalid
		}
	}
	return nil
}

func checkWorkspaceMetadata(ctx context.Context, tx *sql.Tx, actor domain.Actor, scopes domain.ScopeSet, binding domain.OwnedRootBinding, now time.Time) error {
	if err := validateWorkspaceScopes(scopes); err != nil {
		return err
	}
	for _, scope := range scopes {
		if err := resolutionOwner(ctx, tx, actor, binding.Route.Device, scope); err != nil {
			return err
		}
	}
	return resolutionConnection(ctx, tx, binding, now)
}

// CheckWorkspaceMetadata rechecks all requested scopes and current connection
// authority before releasing metadata or bytes observed from Native.
func (s *Store) CheckWorkspaceMetadata(ctx context.Context, actor domain.Actor, scopes domain.ScopeSet, binding domain.OwnedRootBinding, now time.Time) error {
	_, err := transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		return struct{}{}, checkWorkspaceMetadata(ctx, tx, actor, scopes, binding, now)
	})
	return err
}

// AcquireWorkspaceMetadata uses the existing durable routing pool. It creates no
// project pin, preparation or task and requires read+dispatch for filesystem I/O.
func (s *Store) AcquireWorkspaceMetadata(ctx context.Context, actor domain.Actor, scopes domain.ScopeSet, input routing.Request) error {
	command, err := validateRoutingRequest(input)
	if err != nil {
		return err
	}
	if input.ProtocolVersion() != protocol.WireVersion2 {
		return domain.ErrInvalid
	}
	binding := domain.OwnedRootBinding{Route: domain.RootRoute{Device: input.Credential.Device, Root: domain.RootGuard(command.Root)}, Credential: input.Credential, Connection: routingGeneration(input.Call.Generation)}
	if binding.Validate() != nil || command.Project != "" {
		return domain.ErrInvalid
	}
	if err = validateWorkspaceCommand(scopes, command); err != nil {
		return err
	}
	_, err = transaction(ctx, s, func(tx *sql.Tx) (struct{}, error) {
		if checkErr := checkWorkspaceMetadata(ctx, tx, actor, scopes, binding, input.Now); checkErr != nil {
			return struct{}{}, checkErr
		}
		return struct{}{}, acquireRouting(ctx, tx, input, func() error { return nil })
	})
	return err
}

func validateWorkspaceCommand(scopes domain.ScopeSet, command protocol.Command) error {
	if command.Operation == protocol.ProviderModels {
		var request protocol.ModelQuery
		if !scopes.Has(domain.TaskDispatch) || protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes) != nil || request.Validate() != nil {
			return domain.ErrInvalid
		}
		return nil
	}
	if command.Operation == protocol.SelectProject {
		var request protocol.SelectionRequest
		if protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes) != nil || request.Validate() != nil {
			return domain.ErrInvalid
		}
		return nil
	}
	if !command.Operation.Filesystem() || !scopes.Has(domain.TaskRead) {
		return domain.ErrInvalid
	}
	var request protocol.FilesystemRequest
	if protocol.DecodeStrict(command.Body, &request, protocol.MaxFrameBytes) != nil || request.ValidateFor(command.Operation) != nil {
		return domain.ErrInvalid
	}
	return nil
}
