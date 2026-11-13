package mcpadapter

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (a *Adapter) registerTools() error {
	read := toolHints{ReadOnly: true, Idempotent: true}
	execute := toolHints{Idempotent: true, Destructive: true}
	inventory := []domain.Scope{domain.InventoryRead}
	observe := []domain.Scope{domain.TaskRead}
	dispatch := []domain.Scope{domain.TaskDispatch}
	return errors.Join(
		register(a, "list_devices", "List authorized devices. Online, Delegate compatibility, and provider authentication are separate dated facts.", inventory, read, a.devices),
		register(a, "list_projects", "List authorized project aliases on the explicitly selected device; never returns local paths.", inventory, read, a.projects),
		register(a, "get_capabilities", "Inspect dated providers, supported selections and effective dispatch ceilings for one device and project.", inventory, read, a.capabilities),
		register(a, "prepare_dispatch", "Prepare one immutable request for an explicit device and project. Starts nothing. Retain the returned operation ID before confirming.", dispatch, toolHints{}, a.prepare),
		register(a, "dispatch_task", "Confirm an existing prepared operation. Reuse its handle after retries; an unknown admission never authorizes a replacement task.", dispatch, execute, a.dispatch),
		register(a, "list_operations", "Recover authorized operation handles without briefs. Dispatch-only access lists drafts; task-read access permits current authorized observations.", []domain.Scope{domain.TaskRead, domain.TaskDispatch}, read, a.operations),
		register(a, "resolve_operation", "Passively resolve the same operation. Never starts, resumes or fences a task.", observe, read, a.resolve),
		register(a, "get_task_status", "Read bounded task metadata and closure evidence. Accepted publication does not imply execution closure.", observe, read, a.status),
		register(a, "recover_admission", "Explicitly resume only matching existing prepared work using its original task and canonical spec identity. Never creates an absent task.", dispatch, execute, a.recover),
		register(a, "collect_result", "Collect an accepted immutable result descriptor. Execution may still be closing; use read_result_chunk for verified bytes.", observe, read, a.collect),
		register(a, "read_result_chunk", "Read at most 65536 accepted bytes after whole-result verification. Each range costs a full bounded scan; authorization is rechecked before output.", observe, read, a.readResult),
		register(a, "cancel_task", "Cancel an authorized operation with a stable cancellation ID. Requested stop, definitely-unsent draft and confirmed termination remain separate facts.", []domain.Scope{domain.TaskCancel}, execute, a.cancel),
		a.registerWorkspaceTools(),
	)
}

func (a *Adapter) prepare(ctx context.Context, actor domain.Actor, input PrepareInput) (Prepared, error) {
	request := domain.FrozenRequest{Provider: domain.ProviderID(input.Provider), Permission: domain.Permission(input.Permission), BudgetSeconds: input.BudgetSeconds, Brief: input.Brief, Model: selection(input.Model), Effort: selection(input.Effort)}
	prepared, err := a.options.Operations.Prepare(ctx, actor, domain.Destination{Device: domain.DeviceID(input.DeviceID), Project: domain.ProjectAlias(input.ProjectAlias)}, request)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{OperationID: string(prepared.Correlation.Operation), TaskID: string(prepared.Correlation.Task), ExpiresAt: prepared.ExpiresAt}, nil
}

func selection(value *string) domain.Selection {
	if value == nil {
		return domain.Selection{Kind: domain.NativeDefault}
	}
	return domain.Selection{Kind: domain.Explicit, Value: *value}
}

func (a *Adapter) dispatch(ctx context.Context, actor domain.Actor, input OperationInput) (Operation, error) {
	result, err := a.options.Operations.Dispatch(ctx, actor, domain.OperationID(input.OperationID))
	return publicOperation(result.Operation), err
}

func (a *Adapter) resolve(ctx context.Context, actor domain.Actor, input OperationInput) (Operation, error) {
	view, err := a.options.Operations.Resolve(ctx, actor, domain.OperationID(input.OperationID))
	return publicOperation(view), err
}

func (a *Adapter) status(ctx context.Context, actor domain.Actor, input OperationInput) (Operation, error) {
	view, err := a.options.Operations.Status(ctx, actor, domain.OperationID(input.OperationID))
	return publicOperation(view), err
}

func (a *Adapter) recover(ctx context.Context, actor domain.Actor, input OperationInput) (Operation, error) {
	view, err := a.options.Operations.Recover(ctx, actor, domain.OperationID(input.OperationID))
	return publicOperation(view), err
}

func (a *Adapter) collect(ctx context.Context, actor domain.Actor, input OperationInput) (Operation, error) {
	view, err := a.options.Operations.Collect(ctx, actor, domain.OperationID(input.OperationID))
	return publicOperation(view), err
}

func (a *Adapter) cancel(ctx context.Context, actor domain.Actor, input CancelInput) (Cancellation, error) {
	result, err := a.options.Operations.Cancel(ctx, actor, domain.OperationID(input.OperationID), domain.CancellationID(input.CancellationID))
	return Cancellation{OperationID: string(result.Operation), CancellationID: string(result.Cancellation), DefinitelyUnsent: result.DefinitelyUnsent, ClosureConfirmed: result.ClosureConfirmed}, err
}

func (a *Adapter) readResult(ctx context.Context, actor domain.Actor, input RangeInput) (protocol.ResultRange, error) {
	return a.options.Operations.ReadResult(ctx, actor, domain.OperationID(input.OperationID), input.Descriptor, input.Offset, input.Limit)
}

func (a *Adapter) operations(ctx context.Context, actor domain.Actor, input PageInput) (OperationPage, error) {
	page, err := a.options.Registry.ListOperations(ctx, actor, domain.OperationPageRequest{After: domain.OperationID(input.Cursor), Limit: input.Limit})
	if err != nil {
		return OperationPage{}, err
	}
	result := OperationPage{Operations: make([]Operation, 0, len(page.Items)), NextCursor: string(page.Next)}
	for _, operation := range page.Items {
		result.Operations = append(result.Operations, publicOperation(operation))
	}
	return result, nil
}

func publicOperation(view domain.OperationView) Operation {
	result := Operation{OperationID: string(view.Correlation.Operation), TaskID: string(view.Correlation.Task), DeviceID: string(view.Correlation.Destination.Device), ProjectAlias: string(view.Correlation.Destination.Project), Delivery: string(view.Delivery), CreatedAt: view.CreatedAt, ExpiresAt: view.ExpiresAt, Reserved: view.Reserved, CancellationID: string(view.Cancellation)}
	if view.Observation == nil {
		return result
	}
	observation := view.Observation
	result.Observation = &Observation{Kind: string(observation.Kind), ObservedAt: observation.ObservedAt, ClosurePending: string(observation.ClosurePending)}
	if observation.Result != nil {
		result.Observation.Result = &protocol.Descriptor{SHA256: hex.EncodeToString(observation.Result.Digest[:]), Length: observation.Result.Bytes}
	}
	if observation.Closure != nil {
		result.Observation.Closure = &protocol.ExecutionClosure{Kind: string(observation.Closure.Kind), ReferenceSHA256: hex.EncodeToString(observation.Closure.Reference[:])}
	}
	return result
}
