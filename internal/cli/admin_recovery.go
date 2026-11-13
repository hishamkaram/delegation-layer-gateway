package cli

import (
	"context"
	"io"
	"net/http"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func recoveryAdminAction(ctx context.Context, socket, action, output string, data []byte, stdout io.Writer) (bool, error) {
	switch action {
	case "begin-recovery":
		return true, adminRequest[adminapi.RecoveryInput, adminapi.RecoverySession](ctx, socket, http.MethodPost, "/v1/recovery/begin", data, output, false, stdout, validRecoverySession)
	case "register-recovery-root":
		return true, adminRequest[adminapi.RecoveryRootInput, adminapi.Mutation](ctx, socket, http.MethodPost, "/v1/recovery/register-root", data, output, false, stdout, validMutation[adminapi.RecoveryRootInput])
	case "register-routing-recovery-roster":
		return true, adminRequest[adminapi.RecoveryRosterInput, adminapi.Mutation](ctx, socket, http.MethodPost, "/v1/recovery/routing-roster", data, output, false, stdout, validMutation[adminapi.RecoveryRosterInput])
	case "seal-recovery":
		return true, adminRequest[adminapi.RecoverySealInput, adminapi.Mutation](ctx, socket, http.MethodPost, "/v1/recovery/seal", data, output, false, stdout, validMutation[adminapi.RecoverySealInput])
	case "recovery-progress":
		return true, adminRequest[adminapi.RecoveryProgressInput, adminapi.RecoveryProgress](ctx, socket, http.MethodPost, "/v1/recovery/progress", data, output, false, stdout, validRecoveryProgress)
	case "advance-recovery":
		return true, adminRequest[adminapi.RecoveryAdvanceInput, adminapi.RecoveryDestination](ctx, socket, http.MethodPost, "/v1/recovery/advance", data, output, false, stdout, validRecoveryAdvance)
	case "finish-recovery":
		return true, adminRequest[adminapi.RecoveryInput, adminapi.Mutation](ctx, socket, http.MethodPost, "/v1/recovery/finish", data, output, false, stdout, validMutation[adminapi.RecoveryInput])
	case "list-administrative-tasks":
		return true, adminRequest[adminapi.TaskPageInput, adminapi.AdministrativeTaskPage](ctx, socket, http.MethodPost, "/v1/tasks/list", data, output, false, stdout, validAdministrativeTaskPage)
	case "get-administrative-task":
		return true, adminRequest[adminapi.TaskKey, adminapi.AdministrativeTask](ctx, socket, http.MethodPost, "/v1/tasks/get", data, output, false, stdout, validAdministrativeTask)
	case "drain-administrative-task":
		return true, adminRequest[adminapi.TaskDrainInput, adminapi.AdministrativeTask](ctx, socket, http.MethodPost, "/v1/tasks/drain", data, output, false, stdout, validAdministrativeDrain)
	case "list-routing-permits":
		return true, adminRequest[adminapi.PermitPageInput, adminapi.RoutingPermitPage](ctx, socket, http.MethodPost, "/v1/routing/permits", data, output, false, stdout, validRoutingPermitPage)
	case "refresh-project":
		return true, adminRequest[adminapi.RootInput, protocol.ProjectCapability](ctx, socket, http.MethodPost, "/v1/projects/refresh", data, output, false, stdout, validProjectRefresh)
	default:
		return false, nil
	}
}

func validRecoverySession(input adminapi.RecoveryInput, output adminapi.RecoverySession) bool {
	return output.Validate() == nil && output.RecoveryID == input.RecoveryID && output.Kind == domain.RestoreRecovery
}

func validRecoveryProgress(input adminapi.RecoveryProgressInput, output adminapi.RecoveryProgress) bool {
	if output.Validate() != nil || len(output.Destinations) > input.Limit || (input.RecoveryID != "" && output.Session.RecoveryID != input.RecoveryID) {
		return false
	}
	previous := input.After
	for _, destination := range output.Destinations {
		cursor := adminapi.RecoveryCursor{DeviceID: destination.DeviceID, RootGuard: destination.RootGuard}
		if previous != nil && !recoveryCursorBefore(*previous, cursor) {
			return false
		}
		previous = &cursor
	}
	return output.Next == nil || (len(output.Destinations) > 0 && previous != nil && *output.Next == *previous)
}

func recoveryCursorBefore(left, right adminapi.RecoveryCursor) bool {
	return left.DeviceID < right.DeviceID || (left.DeviceID == right.DeviceID && left.RootGuard < right.RootGuard)
}

func validRecoveryAdvance(input adminapi.RecoveryAdvanceInput, output adminapi.RecoveryDestination) bool {
	return output.Validate() == nil && output.RecoveryID == input.RecoveryID && output.DeviceID == input.DeviceID && output.RootGuard == input.RootGuard
}

func validAdministrativeTaskPage(input adminapi.TaskPageInput, output adminapi.AdministrativeTaskPage) bool {
	if len(output.Items) > input.Limit {
		return false
	}
	previous := input.After
	for _, item := range output.Items {
		if item.Validate() != nil || (previous != nil && !taskKeyBefore(*previous, item.Key)) {
			return false
		}
		key := item.Key
		previous = &key
	}
	return output.Next == nil || (len(output.Items) > 0 && previous != nil && *output.Next == *previous)
}

func taskKeyBefore(left, right adminapi.TaskKey) bool {
	if left.DeviceID != right.DeviceID {
		return left.DeviceID < right.DeviceID
	}
	if left.RootGuard != right.RootGuard {
		return left.RootGuard < right.RootGuard
	}
	return left.TaskID < right.TaskID
}

func validAdministrativeTask(input adminapi.TaskKey, output adminapi.AdministrativeTask) bool {
	return output.Validate() == nil && input == output.Key
}

func validAdministrativeDrain(input adminapi.TaskDrainInput, output adminapi.AdministrativeTask) bool {
	key := adminapi.TaskKey{DeviceID: input.DeviceID, RootGuard: input.RootGuard, TaskID: input.TaskID}
	return validAdministrativeTask(key, output) && (input.Action != domain.AdministrativeCancel || input.CancellationID == output.CancellationID)
}

func validRoutingPermitPage(input adminapi.PermitPageInput, output adminapi.RoutingPermitPage) bool {
	if len(output.Items) > input.Limit {
		return false
	}
	previous := input.After
	for _, item := range output.Items {
		completion := protocol.ControlCompletion{ProcessBoot: item.ProcessBoot, Call: item.Call, Disposition: protocol.ControlPending}
		if completion.Validate() != nil || domain.CredentialToken(item.DeviceID) != nil || item.Protected != item.Call.Operation.ProtectedControl() || item.Scan != item.Call.Operation.ScanConsumer() {
			return false
		}
		cursor := adminapi.PermitCursor{DeviceID: item.DeviceID, BootEpoch: item.Call.Generation.BootEpoch, Counter: item.Call.Generation.Counter, RequestID: item.Call.RequestID}
		if previous != nil && !permitCursorBefore(*previous, cursor) {
			return false
		}
		previous = &cursor
	}
	return output.Next == nil || (len(output.Items) > 0 && previous != nil && *output.Next == *previous)
}

func permitCursorBefore(left, right adminapi.PermitCursor) bool {
	if left.DeviceID != right.DeviceID {
		return left.DeviceID < right.DeviceID
	}
	if left.BootEpoch != right.BootEpoch {
		return left.BootEpoch < right.BootEpoch
	}
	if left.Counter != right.Counter {
		return left.Counter < right.Counter
	}
	return left.RequestID < right.RequestID
}

func validProjectRefresh(input adminapi.RootInput, output protocol.ProjectCapability) bool {
	return output.Validate() == nil && output.Alias == input.ProjectAlias && output.Context == (protocol.ContextBinding{Root: input.RootGuard, Project: input.ProjectGuard})
}
