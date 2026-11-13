package adminapi

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

const MaxResponseBytes = 64 << 10

func (h *Handler) beginRecovery(ctx context.Context, input RecoveryInput) (RecoverySession, error) {
	if err := input.Validate(); err != nil {
		return RecoverySession{}, err
	}
	if h.options.Recoveries == nil {
		return RecoverySession{}, domain.Reject(domain.Pending)
	}
	session, err := h.options.Recoveries.Begin(ctx, domain.RecoveryID(input.RecoveryID))
	return recoverySession(session), err
}

func recoverySession(s domain.RecoverySession) RecoverySession {
	return RecoverySession{RecoveryID: string(s.ID), Kind: s.Kind, StartedAt: s.StartedAt, RosterSealed: s.RosterSealed}
}

func (h *Handler) registerRecoveryRoot(ctx context.Context, input RecoveryRootInput) (Mutation, error) {
	if err := input.Validate(); err != nil {
		return Mutation{}, err
	}
	if h.options.Recoveries == nil {
		return Mutation{}, domain.Reject(domain.Pending)
	}
	err := h.options.Recoveries.Register(ctx, domain.RecoveryDestination{Recovery: domain.RecoveryID(input.RecoveryID), Device: domain.DeviceID(input.DeviceID), Root: domain.RootGuard(input.RootGuard)})
	return Mutation{Committed: err == nil}, err
}

func (h *Handler) registerRoutingRecoveryRoster(ctx context.Context, input RecoveryRosterInput) (Mutation, error) {
	if err := input.Validate(); err != nil {
		return Mutation{}, err
	}
	if h.options.Recoveries == nil {
		return Mutation{}, domain.Reject(domain.Pending)
	}
	err := h.options.Recoveries.RegisterRoutingRoster(ctx, domain.RecoveryID(input.RecoveryID), input.DeviceIDs)
	return Mutation{Committed: err == nil}, err
}

func (h *Handler) sealRecovery(ctx context.Context, input RecoverySealInput) (Mutation, error) {
	if err := input.Validate(); err != nil {
		return Mutation{}, err
	}
	if h.options.Recoveries == nil {
		return Mutation{}, domain.Reject(domain.Pending)
	}
	err := h.options.Recoveries.Seal(ctx, domain.RecoveryRosterSeal{Recovery: domain.RecoveryID(input.RecoveryID), ExpectedDestinations: *input.ExpectedDestinations})
	return Mutation{Committed: err == nil}, err
}

func (h *Handler) recoveryProgress(ctx context.Context, input RecoveryProgressInput) (RecoveryProgress, error) {
	if err := input.Validate(); err != nil {
		return RecoveryProgress{}, err
	}
	if h.options.Recoveries == nil {
		return RecoveryProgress{}, domain.Reject(domain.Pending)
	}
	request := domain.RecoveryProgressRequest{Recovery: domain.RecoveryID(input.RecoveryID), Limit: min(input.Limit, maxAdministrativePageItems)}
	if input.After != nil {
		request.After = &domain.RecoveryDestinationCursor{Device: domain.DeviceID(input.After.DeviceID), Root: domain.RootGuard(input.After.RootGuard)}
	}
	page, err := h.options.Recoveries.Progress(ctx, request)
	if err != nil {
		return RecoveryProgress{}, err
	}
	result := RecoveryProgress{Session: recoverySession(page.Session), Status: page.Status, Revision: page.Revision, Destinations: make([]RecoveryDestination, 0, len(page.Destinations))}
	for _, destination := range page.Destinations {
		result.Destinations = append(result.Destinations, recoveryDestination(destination))
	}
	if page.Next != nil {
		result.Next = &RecoveryCursor{DeviceID: string(page.Next.Device), RootGuard: string(page.Next.Root)}
	}
	return boundedMetadata(result)
}

func recoveryDestination(p domain.RecoveryDestinationProgress) RecoveryDestination {
	result := RecoveryDestination{RecoveryID: string(p.Destination.Recovery), DeviceID: string(p.Destination.Device), RootGuard: string(p.Destination.Root), Stage: p.Stage, Cursor: p.Cursor, MissingMappings: p.MissingMappings, ReopenRecorded: p.RecordedReopen != nil}
	if p.Barrier != nil {
		result.Generation, result.ExpectedGeneration = string(p.Barrier.Generation), string(p.Barrier.ExpectedGeneration)
	}
	if p.Membership != nil {
		result.MembershipSHA256 = hex.EncodeToString(p.Membership[:])
	}
	if p.Completeness != nil {
		result.CompletenessSHA256 = hex.EncodeToString(p.Completeness[:])
	}
	if p.Reopen != nil {
		result.ApprovalRevision = p.Reopen.Revision
	}
	return result
}

func (h *Handler) advanceRecovery(ctx context.Context, input RecoveryAdvanceInput) (RecoveryDestination, error) {
	if err := input.Validate(); err != nil {
		return RecoveryDestination{}, err
	}
	if h.options.Recoveries == nil {
		return RecoveryDestination{}, domain.Reject(domain.Pending)
	}
	progress, err := h.options.Recoveries.Advance(ctx, recovery.RestoreAdvance{Recovery: domain.RecoveryID(input.RecoveryID), Route: domain.Destination{Device: domain.DeviceID(input.DeviceID), Project: domain.ProjectAlias(input.ProjectAlias)}, Root: domain.RootGuard(input.RootGuard)})
	return recoveryDestination(progress), err
}

func (h *Handler) finishRecovery(ctx context.Context, input RecoveryInput) (Mutation, error) {
	if err := input.Validate(); err != nil {
		return Mutation{}, err
	}
	if h.options.Recoveries == nil {
		return Mutation{}, domain.Reject(domain.Pending)
	}
	err := h.options.Recoveries.Finish(ctx, domain.RecoveryID(input.RecoveryID))
	return Mutation{Committed: err == nil}, err
}

func (h *Handler) listAdministrativeTasks(ctx context.Context, input TaskPageInput) (AdministrativeTaskPage, error) {
	if err := input.Validate(); err != nil {
		return AdministrativeTaskPage{}, err
	}
	if h.options.Tasks == nil {
		return AdministrativeTaskPage{}, domain.Reject(domain.Pending)
	}
	request := domain.AdministrativeTaskPageRequest{Limit: min(input.Limit, maxAdministrativePageItems)}
	if input.After != nil {
		key := input.After.Domain()
		request.After = &key
	}
	page, err := h.options.Tasks.List(ctx, request)
	if err != nil {
		return AdministrativeTaskPage{}, err
	}
	result := AdministrativeTaskPage{Items: make([]AdministrativeTaskSummary, 0, len(page.Items))}
	for _, task := range page.Items {
		result.Items = append(result.Items, taskSummary(task))
	}
	if page.Next != nil {
		next := taskKey(*page.Next)
		result.Next = &next
	}
	return boundedMetadata(result)
}

func taskKey(key domain.NativeTaskKey) TaskKey {
	return TaskKey{DeviceID: string(key.Device), RootGuard: string(key.Root), TaskID: string(key.Task)}
}

func taskSummary(task domain.AdministrativeTaskView) AdministrativeTaskSummary {
	result := AdministrativeTaskSummary{Key: taskKey(task.Key), Attributed: task.Correlation != nil, Delivery: task.Delivery, Reserved: task.Reserved, CancellationID: string(task.Cancellation), SpecSHA256: optionalDigest(task.Binding.SpecDigest)}
	if task.Correlation != nil {
		result.OperationID = string(task.Correlation.Operation)
	}
	if task.Observation != nil {
		result.ObservationKind = task.Observation.Kind
		observedAt := task.Observation.ObservedAt
		result.ObservedAt = &observedAt
	}
	return result
}

func (h *Handler) getAdministrativeTask(ctx context.Context, input TaskKey) (AdministrativeTask, error) {
	if err := input.Validate(); err != nil {
		return AdministrativeTask{}, err
	}
	if h.options.Tasks == nil {
		return AdministrativeTask{}, domain.Reject(domain.Pending)
	}
	view, err := h.options.Tasks.Get(ctx, input.Domain())
	return administrativeTask(view), err
}

func (h *Handler) drainAdministrativeTask(ctx context.Context, input TaskDrainInput) (AdministrativeTask, error) {
	if err := input.Validate(); err != nil {
		return AdministrativeTask{}, err
	}
	if h.options.Tasks == nil {
		return AdministrativeTask{}, domain.Reject(domain.Pending)
	}
	request := recovery.DrainRequest{Key: (TaskKey{DeviceID: input.DeviceID, RootGuard: input.RootGuard, TaskID: input.TaskID}).Domain(), Route: domain.Destination{Device: domain.DeviceID(input.DeviceID), Project: domain.ProjectAlias(input.ProjectAlias)}, Action: input.Action, Cancellation: domain.CancellationID(input.CancellationID)}
	view, err := h.options.Tasks.Control(ctx, request)
	return administrativeTask(view), err
}

func administrativeTask(view domain.AdministrativeTaskView) AdministrativeTask {
	origin := view.Binding.Origin
	result := AdministrativeTask{Key: taskKey(view.Key), Attributed: view.Correlation != nil, ProjectGuard: string(view.Binding.Context.Project), Origin: protocol.Origin{GatewayID: string(origin.Gateway), AdmissionGeneration: string(origin.AdmissionGeneration), OperationID: string(origin.Operation), PrincipalRef: string(origin.Principal), RequestSHA256: optionalDigest(origin.RequestDigest)}, SpecSHA256: optionalDigest(view.Binding.SpecDigest), Delivery: view.Delivery, Reserved: view.Reserved, CancellationID: string(view.Cancellation)}
	if view.Correlation != nil {
		result.OriginalProjectAlias = string(view.Correlation.Destination.Project)
	}
	if view.Receipt != nil {
		options := view.Receipt.Options
		result.Receipt = &TaskReceipt{BriefSHA256: optionalDigest(view.Receipt.BriefDigest), Provider: string(options.Provider), Permission: options.Permission, BudgetNanoseconds: options.BudgetNanoseconds, Model: protocol.Selection{Kind: string(options.Model.Kind), Value: options.Model.Value}, Effort: protocol.Selection{Kind: string(options.Effort.Kind), Value: options.Effort.Value}}
	}
	if view.Observation != nil {
		result.Observation = taskObservation(*view.Observation)
	}
	return result
}

func taskObservation(observation domain.DelegateObservation) *TaskObservation {
	result := &TaskObservation{Kind: observation.Kind, ObservedAt: observation.ObservedAt, SpecSHA256: optionalDigest(observation.SpecDigest), ClosurePending: observation.ClosurePending}
	if observation.Result != nil {
		result.Result = &protocol.Descriptor{SHA256: optionalDigest(observation.Result.Digest), Length: observation.Result.Bytes}
	}
	if observation.Closure != nil {
		result.Closure = &protocol.ExecutionClosure{Kind: string(observation.Closure.Kind), ReferenceSHA256: optionalDigest(observation.Closure.Reference)}
	}
	if observation.ConfirmedStop != nil {
		result.StopCancellation = string(observation.ConfirmedStop.Cancellation)
	}
	return result
}

func optionalDigest(digest domain.Digest) string {
	if digest == (domain.Digest{}) {
		return ""
	}
	return hex.EncodeToString(digest[:])
}

func (h *Handler) listRoutingPermits(ctx context.Context, input PermitPageInput) (RoutingPermitPage, error) {
	if err := input.Validate(); err != nil {
		return RoutingPermitPage{}, err
	}
	if h.options.Permits == nil {
		return RoutingPermitPage{}, domain.Reject(domain.Pending)
	}
	request := routing.PermitPageRequest{Limit: min(input.Limit, maxAdministrativePageItems)}
	if input.After != nil {
		request.After = &routing.PermitCursor{Device: domain.DeviceID(input.After.DeviceID), Connection: domain.ConnectionGeneration{BootEpoch: domain.BootEpoch(input.After.BootEpoch), Counter: input.After.Counter}, Request: input.After.RequestID}
	}
	page, err := h.options.Permits.ListRoutingPermits(ctx, request)
	if err != nil {
		return RoutingPermitPage{}, err
	}
	result := RoutingPermitPage{Items: make([]RoutingPermit, 0, len(page.Items))}
	for _, permit := range page.Items {
		result.Items = append(result.Items, RoutingPermit{DeviceID: string(permit.Device), ProcessBoot: permit.ProcessBoot, Call: permit.Call, Protected: permit.Protected, Scan: permit.Scan})
	}
	if page.Next != nil {
		result.Next = &PermitCursor{DeviceID: string(page.Next.Device), BootEpoch: string(page.Next.Connection.BootEpoch), Counter: page.Next.Connection.Counter, RequestID: page.Next.Request}
	}
	return boundedMetadata(result)
}

// Page reads can fail before sending an oversized response. Their original
// cursor remains usable with a smaller requested limit.
func boundedMetadata[T any](value T) (T, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value, err
	}
	if len(encoded) > MaxResponseBytes {
		return value, domain.Reject(domain.ResourceLimit)
	}
	return value, nil
}

func (h *Handler) refreshProject(ctx context.Context, input RootInput) (protocol.ProjectCapability, error) {
	lookup, err := rootLookup(input)
	if err != nil {
		return protocol.ProjectCapability{}, err
	}
	if h.options.Projects == nil {
		return protocol.ProjectCapability{}, domain.Reject(domain.Pending)
	}
	report, _, err := h.options.Projects.Inspect(ctx, lookup.Route, lookup.ExpectedContext)
	return report, err
}
