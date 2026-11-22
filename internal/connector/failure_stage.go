package connector

import "github.com/hishamkaram/delegation-layer-gateway/internal/protocol"

// Adapter owns this one compatibility projection after decoding the route and
// settling CLI cleanup. Service supplies the validated negotiated version. New
// Native error codes must never acquire a different meaning on legacy readers.
func projectControlReply(reply protocol.Reply, version int, operation protocol.Operation, routeVersion int) protocol.Reply {
	if reply.Error == nil || !legacyFailureContract(version, operation, routeVersion) {
		return reply
	}
	if !legacyFailureCode(reply.Error.Code) {
		return failed(reply.Operation, ErrPending)
	}
	failure := *reply.Error
	failure.Stage = ""
	reply.Error = &failure
	return reply
}

func legacyFailureContract(version int, operation protocol.Operation, routeVersion int) bool {
	if version == protocol.Version {
		return true
	}
	return routeVersion == 0 && !operation.Filesystem() && operation != protocol.SelectProject && operation != protocol.ProviderModels
}

// Frozen from 8937a4a:internal/protocol/peer.go. Extending the current protocol
// must not extend the accepted error vocabulary of previous v1/v2 Gateways.
func legacyFailureCode(code string) bool {
	switch code {
	case "unauthenticated", "forbidden", "not_found", "device_offline", "device_not_ready", "conflict", "expired", "pending", "admission_unknown", "permanently_refused", "context_mismatch", "incompatible_delegate", "resource_limit", "result_unavailable", "evidence_invalid", "timeout", "result_verification_timeout", "protocol_error":
		return true
	default:
		return false
	}
}

func nativeFailureReply(operation protocol.Operation, native *cliFailure) protocol.Reply {
	// Filesystem declares a boolean. Task/model failures instead declare a
	// fixed public next action; omission of a boolean is not a Native false.
	retryable := native.NextAction == "retry_later"
	if native.Retryable != nil {
		retryable = *native.Retryable
	}
	failure := protocol.Failure{Code: native.Code, Retryable: retryable, Stage: safeNativeStage(native.Stage)}
	if failure.Validate() != nil {
		return failed(operation, ErrEvidence)
	}
	return protocol.Reply{Operation: operation, Error: &failure}
}

// Only fixed stages from the inspected Native task/filesystem contracts may
// leave the local boundary. Unknown Native diagnostics remain local.
func safeNativeStage(stage string) string {
	switch stage {
	case "prepare-model-discovery", "open-state", "close-state", "close-supervisor":
		return stage
	case "request", "root", "observe", "context", "cursor", "directory_scan", "file_kind", "file_link", "file_open", "file_read", "git_inspect", "list_options", "metadata", "metadata_read", "observation_options", "operation", "range", "read_options", "response_encoding", "root_guard", "scope", "scope_identity", "scopes", "scopes_options", "selector", "temp_lookup", "temp_scope", "version", "workspace_guard", "dispatch", "wait", "collect", "context-inspect", "context-initialize", "task-namespace", "verify-result", "validate-request", "prepare-provider", "finalize-provider", "select-provider", "validate-profile", "record-runtime-capability", "prepare-supervisor-executables", "prepare-supervisor-options", "start-supervisor", "inspect-provider", "prepare-task-submission", "resolve-runner", "resolve-state-root", "prepare-workspace", "resolve-predecessor", "load-predecessor", "load-continuation-session", "validate-continuation", "resolve-continuation-supervisor", "resolve-continuation-provider", "check-continuation-capability":
		return stage
	default:
		return ""
	}
}
