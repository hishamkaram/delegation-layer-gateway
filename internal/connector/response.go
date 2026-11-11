package connector

import (
	"encoding/json"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Consumer-owned DTOs follow the inspected public v1 envelope. Legacy diagnostic
// fields are bounded opaque JSON, deliberately discarded rather than forwarded.
type cliResponse struct {
	exitCode               int
	SchemaVersion          int             `json:"schema_version"`
	Command                string          `json:"command"`
	RootID                 string          `json:"root_id,omitempty"`
	TaskID                 string          `json:"task_id,omitempty"`
	TaskRecord             string          `json:"task_record,omitempty"`
	Status                 string          `json:"status,omitempty"`
	Admission              string          `json:"admission"`
	Liveness               string          `json:"liveness"`
	Publication            string          `json:"publication"`
	Connector              *cliConnector   `json:"connector,omitempty"`
	Outcome                *cliOutcome     `json:"outcome,omitempty"`
	Payload                *cliDescriptor  `json:"payload,omitempty"`
	Stop                   *cliStop        `json:"stop,omitempty"`
	Failure                *cliFailure     `json:"failure,omitempty"`
	Pending                *cliPending     `json:"pending,omitempty"`
	Error                  string          `json:"error,omitempty"`
	ErrorTruncated         bool            `json:"error_truncated,omitempty"`
	Capability             json.RawMessage `json:"capability,omitempty"`
	Raw                    json.RawMessage `json:"raw,omitempty"`
	Diagnostics            json.RawMessage `json:"diagnostics,omitempty"`
	Supervisor             json.RawMessage `json:"supervisor,omitempty"`
	SupervisorControl      json.RawMessage `json:"supervisor_control,omitempty"`
	SupervisorOwner        json.RawMessage `json:"supervisor_owner,omitempty"`
	Stops                  json.RawMessage `json:"stops,omitempty"`
	EvidenceSHA256         string          `json:"evidence_sha256,omitempty"`
	LastProviderOutputAt   string          `json:"last_provider_output_at,omitempty"`
	ProviderOutputActivity json.RawMessage `json:"provider_output_activity,omitempty"`
	Wait                   json.RawMessage `json:"wait,omitempty"`
	Interaction            json.RawMessage `json:"interaction,omitempty"`
	Delivery               json.RawMessage `json:"delivery,omitempty"`
	Events                 json.RawMessage `json:"events,omitempty"`
	Cursor                 json.RawMessage `json:"cursor,omitempty"`
	Continuation           json.RawMessage `json:"continuation,omitempty"`
	ResourceAdmission      json.RawMessage `json:"resource_admission,omitempty"`
	Recheck                json.RawMessage `json:"recheck,omitempty"`
	Team                   json.RawMessage `json:"team,omitempty"`
	ParentTaskID           string          `json:"parent_task_id,omitempty"`
	Workspace              json.RawMessage `json:"workspace,omitempty"`
	Workspaces             json.RawMessage `json:"workspaces,omitempty"`
	WorkspaceCursor        string          `json:"workspace_cursor,omitempty"`
	WorkspaceSupport       json.RawMessage `json:"workspace_support,omitempty"`
	Checkpoint             json.RawMessage `json:"checkpoint,omitempty"`
	Checkpoints            json.RawMessage `json:"checkpoints,omitempty"`
	CheckpointCursor       string          `json:"checkpoint_cursor,omitempty"`
	Schedule               json.RawMessage `json:"schedule,omitempty"`
	Schedules              json.RawMessage `json:"schedules,omitempty"`
	ScheduleCursor         string          `json:"schedule_cursor,omitempty"`
	ScheduleWarnings       json.RawMessage `json:"schedule_warnings,omitempty"`
	ScheduleHistory        json.RawMessage `json:"schedule_history,omitempty"`
	ScheduleExecution      json.RawMessage `json:"schedule_execution,omitempty"`
	ScheduleQueryError     json.RawMessage `json:"schedule_query_error,omitempty"`
	ScheduleHealth         json.RawMessage `json:"schedule_health,omitempty"`
	SchedulePolicy         json.RawMessage `json:"schedule_policy,omitempty"`
	Scheduler              json.RawMessage `json:"scheduler,omitempty"`
}

type cliConnector struct {
	ContractVersion         int                        `json:"contract_version"`
	Features                []string                   `json:"features"`
	RootToken               string                     `json:"root_token"`
	ProjectToken            string                     `json:"project_token,omitempty"`
	OriginRegistered        *bool                      `json:"origin_registered,omitempty"`
	Resolution              string                     `json:"resolution,omitempty"`
	Receipt                 *cliReceipt                `json:"receipt,omitempty"`
	CreationAttempt         string                     `json:"creation_attempt,omitempty"`
	OriginBarrier           *cliOriginState            `json:"origin_barrier,omitempty"`
	Inventory               *cliInventory              `json:"inventory,omitempty"`
	ResultRange             *cliRange                  `json:"result_range,omitempty"`
	ExecutionClosure        *protocol.ExecutionClosure `json:"execution_closure,omitempty"`
	ExecutionClosurePending string                     `json:"execution_closure_pending,omitempty"`
}
type cliReceipt struct {
	ExecutionOptions executionOptions `json:"execution_options"`
	RootToken        string           `json:"root_token"`
	ProjectToken     string           `json:"project_token"`
	TaskID           string           `json:"task_id"`
	Origin           protocol.Origin  `json:"origin"`
	SpecSHA256       string           `json:"spec_sha256"`
	BriefSHA256      string           `json:"brief_sha256"`
}
type (
	executionOptions struct {
		Provider          string             `json:"provider"`
		Permission        string             `json:"permission"`
		BudgetNanoseconds int64              `json:"budget_nanoseconds"`
		Model             protocol.Selection `json:"model"`
		Effort            protocol.Selection `json:"effort"`
	}
	cliDescriptor struct {
		Basename string `json:"basename"`
		SHA256   string `json:"sha256"`
		Length   int64  `json:"length"`
	}
	cliRange struct {
		Descriptor cliDescriptor `json:"descriptor"`
		Offset     int64         `json:"offset"`
		DataBase64 string        `json:"data_base64"`
		NextOffset int64         `json:"next_offset"`
		EOF        bool          `json:"eof"`
	}
	cliOutcome struct {
		SchemaVersion  int             `json:"schema_version"`
		RootID         string          `json:"root_id"`
		TaskID         string          `json:"task_id"`
		SpecSHA256     string          `json:"spec_sha256"`
		MetaSHA256     string          `json:"meta_sha256"`
		Verdict        string          `json:"verdict"`
		EvidenceSHA256 string          `json:"evidence_sha256"`
		Predicate      json.RawMessage `json:"predicate"`
		Payload        cliDescriptor   `json:"payload"`
		Quota          json.RawMessage `json:"quota,omitempty"`
		Usage          json.RawMessage `json:"usage,omitempty"`
		Diagnostics    json.RawMessage `json:"diagnostics,omitempty"`
	}
)

type (
	cliStop struct {
		RequestID        string `json:"request_id,omitempty"`
		Cause            string `json:"cause,omitempty"`
		Requested        bool   `json:"requested"`
		Matched          bool   `json:"matched"`
		Attempted        bool   `json:"attempted"`
		Action           string `json:"action,omitempty"`
		NumericTaskID    *int64 `json:"numeric_task_id,omitempty"`
		Acknowledged     *bool  `json:"acknowledged,omitempty"`
		InFlight         bool   `json:"in_flight"`
		ObservedState    string `json:"observed_state"`
		Terminated       bool   `json:"terminated"`
		Message          string `json:"message,omitempty"`
		MessageTruncated bool   `json:"message_truncated,omitempty"`
	}
	cliFailure struct {
		Code              string          `json:"code"`
		ReasonCode        string          `json:"reason_code,omitempty"`
		Stage             string          `json:"stage"`
		NextAction        string          `json:"next_action"`
		RecoveryCommand   string          `json:"recovery_command,omitempty"`
		Inspection        json.RawMessage `json:"inspection,omitempty"`
		RetryAfterSeconds int             `json:"retry_after_seconds,omitempty"`
	}
	cliPending struct {
		Kind string `json:"kind"`
	}
	cliOriginState struct {
		GatewayID     string `json:"gateway_id"`
		RecoveryID    string `json:"recovery_id"`
		Generation    string `json:"generation"`
		AdmissionOpen bool   `json:"admission_open"`
	}
	cliInventory struct {
		Entries             []inventoryEntry `json:"entries"`
		NextCursor          string           `json:"next_cursor,omitempty"`
		Complete            bool             `json:"complete"`
		MembershipSHA256    string           `json:"membership_sha256"`
		CompletenessReceipt string           `json:"completeness_receipt,omitempty"`
	}
	inventoryEntry struct {
		Receipt     *cliReceipt      `json:"receipt,omitempty"`
		TaskID      string           `json:"task_id"`
		Resolution  string           `json:"resolution"`
		Origin      *protocol.Origin `json:"origin,omitempty"`
		SpecSHA256  string           `json:"spec_sha256,omitempty"`
		BriefSHA256 string           `json:"brief_sha256,omitempty"`
	}
)

func decodeResponse(data []byte, command string) (cliResponse, error) {
	var response cliResponse
	if err := protocol.DecodeStrict(data, &response, MaxStdoutBytes); err != nil || response.SchemaVersion != 1 || response.Command != command {
		return cliResponse{}, ErrEvidence
	}
	return response, nil
}
