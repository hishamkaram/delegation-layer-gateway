package adminapi

import (
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// Administrative pages keep their worst-case metadata within the CLI response
// bound. Registry's cursor still names the last item actually returned.
const maxAdministrativePageItems = 20

type RecoveryInput struct {
	RecoveryID string `json:"recovery_id"`
}

func (i RecoveryInput) Validate() error { return domain.RoutingToken(i.RecoveryID) }

type RecoveryRootInput struct {
	RecoveryID string `json:"recovery_id"`
	DeviceID   string `json:"device_id"`
	RootGuard  string `json:"root_guard"`
}

func (i RecoveryRootInput) Validate() error {
	if (RecoveryInput{RecoveryID: i.RecoveryID}).Validate() != nil || domain.CredentialToken(i.DeviceID) != nil || domain.ContextToken(i.RootGuard) != nil {
		return domain.ErrInvalid
	}
	return nil
}

type RecoveryRosterInput struct {
	RecoveryID string            `json:"recovery_id"`
	DeviceIDs  []domain.DeviceID `json:"device_ids"`
}

func (i RecoveryRosterInput) Validate() error {
	if (RecoveryInput{RecoveryID: i.RecoveryID}).Validate() != nil || i.DeviceIDs == nil || len(i.DeviceIDs) > routing.MaxRecoveryDevices {
		return domain.ErrInvalid
	}
	seen := make(map[domain.DeviceID]bool, len(i.DeviceIDs))
	for _, device := range i.DeviceIDs {
		if domain.CredentialToken(string(device)) != nil || seen[device] {
			return domain.ErrInvalid
		}
		seen[device] = true
	}
	return nil
}

type RecoverySealInput struct {
	RecoveryID           string `json:"recovery_id"`
	ExpectedDestinations *int   `json:"expected_destinations"`
}

func (i RecoverySealInput) Validate() error {
	if (RecoveryInput{RecoveryID: i.RecoveryID}).Validate() != nil || i.ExpectedDestinations == nil || *i.ExpectedDestinations < 0 {
		return domain.ErrInvalid
	}
	return nil
}

type RecoveryCursor struct {
	DeviceID  string `json:"device_id"`
	RootGuard string `json:"root_guard"`
}

func (i RecoveryCursor) Validate() error {
	if domain.CredentialToken(i.DeviceID) != nil || domain.ContextToken(i.RootGuard) != nil {
		return domain.ErrInvalid
	}
	return nil
}

type RecoveryProgressInput struct {
	RecoveryID string          `json:"recovery_id,omitempty"`
	After      *RecoveryCursor `json:"after,omitempty"`
	Limit      int             `json:"limit"`
}

func (i RecoveryProgressInput) Validate() error {
	if i.Limit < 1 || i.Limit > domain.MaxPageLimit {
		return domain.ErrInvalid
	}
	if i.RecoveryID != "" && domain.RoutingToken(i.RecoveryID) != nil {
		return domain.ErrInvalid
	}
	if i.After != nil {
		return i.After.Validate()
	}
	return nil
}

type RecoveryAdvanceInput struct {
	RecoveryID   string `json:"recovery_id"`
	DeviceID     string `json:"device_id"`
	RootGuard    string `json:"root_guard"`
	ProjectAlias string `json:"project_alias"`
}

func (i RecoveryAdvanceInput) Validate() error {
	if (RecoveryRootInput{RecoveryID: i.RecoveryID, DeviceID: i.DeviceID, RootGuard: i.RootGuard}).Validate() != nil {
		return domain.ErrInvalid
	}
	return (domain.Destination{Device: domain.DeviceID(i.DeviceID), Project: domain.ProjectAlias(i.ProjectAlias)}).Validate()
}

type RecoverySession struct {
	RecoveryID   string              `json:"recovery_id"`
	Kind         domain.RecoveryKind `json:"kind"`
	StartedAt    time.Time           `json:"started_at"`
	RosterSealed bool                `json:"roster_sealed"`
}

type RecoveryDestination struct {
	RecoveryID         string                         `json:"recovery_id"`
	DeviceID           string                         `json:"device_id"`
	RootGuard          string                         `json:"root_guard"`
	Stage              domain.RootInitializationStage `json:"stage"`
	ExpectedGeneration string                         `json:"expected_generation,omitempty"`
	Generation         string                         `json:"generation,omitempty"`
	Cursor             string                         `json:"cursor,omitempty"`
	MembershipSHA256   string                         `json:"membership_sha256,omitempty"`
	CompletenessSHA256 string                         `json:"completeness_sha256,omitempty"`
	MissingMappings    int                            `json:"missing_mappings"`
	ApprovalRevision   uint64                         `json:"approval_revision,omitempty"`
	ReopenRecorded     bool                           `json:"reopen_recorded"`
}

type RecoveryProgress struct {
	Session      RecoverySession       `json:"session"`
	Status       domain.RecoveryStatus `json:"status"`
	Revision     uint64                `json:"revision"`
	Destinations []RecoveryDestination `json:"destinations"`
	Next         *RecoveryCursor       `json:"next,omitempty"`
}

type TaskKey struct {
	DeviceID  string `json:"device_id"`
	RootGuard string `json:"root_guard"`
	TaskID    string `json:"task_id"`
}

func (i TaskKey) Domain() domain.NativeTaskKey {
	return domain.NativeTaskKey{Device: domain.DeviceID(i.DeviceID), Root: domain.RootGuard(i.RootGuard), Task: domain.TaskID(i.TaskID)}
}

func (i TaskKey) Validate() error { return i.Domain().Validate() }

type TaskPageInput struct {
	After *TaskKey `json:"after,omitempty"`
	Limit int      `json:"limit"`
}

func (i TaskPageInput) Validate() error {
	if i.Limit < 1 || i.Limit > domain.MaxPageLimit {
		return domain.ErrInvalid
	}
	if i.After != nil {
		return i.After.Validate()
	}
	return nil
}

type TaskDrainInput struct {
	DeviceID       string                      `json:"device_id"`
	RootGuard      string                      `json:"root_guard"`
	TaskID         string                      `json:"task_id"`
	ProjectAlias   string                      `json:"project_alias"`
	Action         domain.AdministrativeAction `json:"action"`
	CancellationID string                      `json:"cancellation_id,omitempty"`
}

func (i TaskDrainInput) Validate() error {
	if (TaskKey{DeviceID: i.DeviceID, RootGuard: i.RootGuard, TaskID: i.TaskID}).Validate() != nil || (domain.Destination{Device: domain.DeviceID(i.DeviceID), Project: domain.ProjectAlias(i.ProjectAlias)}).Validate() != nil || i.Action.Validate() != nil {
		return domain.ErrInvalid
	}
	if i.Action == domain.AdministrativeCancel {
		return domain.CancellationID(i.CancellationID).Validate()
	}
	if i.CancellationID != "" {
		return domain.ErrInvalid
	}
	return nil
}

type TaskObservation struct {
	Kind             domain.ObservationKind     `json:"kind"`
	ObservedAt       time.Time                  `json:"observed_at"`
	SpecSHA256       string                     `json:"spec_sha256,omitempty"`
	Result           *protocol.Descriptor       `json:"result,omitempty"`
	Closure          *protocol.ExecutionClosure `json:"closure,omitempty"`
	ClosurePending   domain.ClosurePending      `json:"closure_pending,omitempty"`
	StopCancellation string                     `json:"stop_cancellation,omitempty"`
}

type TaskReceipt struct {
	BriefSHA256       string             `json:"brief_sha256"`
	Provider          string             `json:"provider"`
	Permission        domain.Permission  `json:"permission"`
	BudgetNanoseconds int64              `json:"budget_nanoseconds"`
	Model             protocol.Selection `json:"model"`
	Effort            protocol.Selection `json:"effort"`
}

type AdministrativeTask struct {
	Key                  TaskKey              `json:"key"`
	Attributed           bool                 `json:"attributed"`
	OriginalProjectAlias string               `json:"original_project_alias,omitempty"`
	ProjectGuard         string               `json:"project_guard"`
	Origin               protocol.Origin      `json:"origin"`
	SpecSHA256           string               `json:"spec_sha256,omitempty"`
	Delivery             domain.DeliveryState `json:"delivery"`
	Reserved             bool                 `json:"reserved"`
	CancellationID       string               `json:"cancellation_id,omitempty"`
	Receipt              *TaskReceipt         `json:"receipt,omitempty"`
	Observation          *TaskObservation     `json:"observation,omitempty"`
}

type AdministrativeTaskPage struct {
	Items []AdministrativeTaskSummary `json:"items"`
	Next  *TaskKey                    `json:"next,omitempty"`
}

type AdministrativeTaskSummary struct {
	Key             TaskKey                `json:"key"`
	Attributed      bool                   `json:"attributed"`
	OperationID     string                 `json:"operation_id,omitempty"`
	Delivery        domain.DeliveryState   `json:"delivery"`
	Reserved        bool                   `json:"reserved"`
	CancellationID  string                 `json:"cancellation_id,omitempty"`
	SpecSHA256      string                 `json:"spec_sha256,omitempty"`
	ObservationKind domain.ObservationKind `json:"observation_kind,omitempty"`
	ObservedAt      *time.Time             `json:"observed_at,omitempty"`
}

type PermitCursor struct {
	DeviceID  string `json:"device_id"`
	BootEpoch string `json:"boot_epoch"`
	Counter   uint64 `json:"counter"`
	RequestID string `json:"request_id"`
}

func (i PermitCursor) Validate() error {
	if domain.CredentialToken(i.DeviceID) != nil || (domain.ConnectionGeneration{BootEpoch: domain.BootEpoch(i.BootEpoch), Counter: i.Counter}).Validate() != nil || domain.RoutingToken(i.RequestID) != nil {
		return domain.ErrInvalid
	}
	return nil
}

type PermitPageInput struct {
	After *PermitCursor `json:"after,omitempty"`
	Limit int           `json:"limit"`
}

func (i PermitPageInput) Validate() error {
	if i.Limit < 1 || i.Limit > domain.MaxPageLimit {
		return domain.ErrInvalid
	}
	if i.After != nil {
		return i.After.Validate()
	}
	return nil
}

type RoutingPermit struct {
	DeviceID    string               `json:"device_id"`
	ProcessBoot string               `json:"process_boot"`
	Call        protocol.ControlCall `json:"call"`
	Protected   bool                 `json:"protected"`
	Scan        bool                 `json:"scan"`
}

type RoutingPermitPage struct {
	Items []RoutingPermit `json:"items"`
	Next  *PermitCursor   `json:"next,omitempty"`
}
