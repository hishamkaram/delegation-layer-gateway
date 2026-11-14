// Package mcpadapter exposes strict public DTOs over the official MCP SDK.
// It never serializes registry records, local contexts or native CLI errors.
package mcpadapter

import (
	"context"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Recorder handles its own sink failures through protected health/counters;
// observation never changes a prepared tool response or Delegate task outcome.
type Recorder interface{ Record(observability.Event) }

type Registry interface {
	CheckProjectReadiness(context.Context, domain.ProjectReadinessRequest) (bool, error)
	Authorize(context.Context, domain.AuthorizationRequest) (domain.Authorization, error)
	AuthorizeOwnedDevice(context.Context, domain.OwnedDeviceRequest) (domain.OwnedDeviceAuthorization, error)
	ListDevices(context.Context, domain.Actor, domain.DevicePageRequest) (domain.DevicePage, error)
	ListProjects(context.Context, domain.Actor, domain.DeviceID, domain.ProjectPageRequest) (domain.ProjectPage, error)
	ListOperations(context.Context, domain.Actor, domain.OperationPageRequest) (domain.OperationPage, error)
}
type Operations interface {
	Prepare(context.Context, domain.Actor, domain.Destination, domain.FrozenRequest) (domain.PreparedOperation, error)
	Dispatch(context.Context, domain.Actor, domain.OperationID) (gateway.DispatchResult, error)
	Resolve(context.Context, domain.Actor, domain.OperationID) (domain.OperationView, error)
	Status(context.Context, domain.Actor, domain.OperationID) (domain.OperationView, error)
	Collect(context.Context, domain.Actor, domain.OperationID) (domain.OperationView, error)
	Recover(context.Context, domain.Actor, domain.OperationID) (domain.OperationView, error)
	Cancel(context.Context, domain.Actor, domain.OperationID, domain.CancellationID) (gateway.CancellationResult, error)
	ReadResult(context.Context, domain.Actor, domain.OperationID, protocol.Descriptor, int64, int) (protocol.ResultRange, error)
}

type WorkspaceTools interface {
	gateway.TargetedCapabilities
	ListWorkspaces(context.Context, domain.Actor, domain.DeviceID) (workspaces.Inventory, error)
	ResolveProject(context.Context, domain.Actor, workspaces.ResolveInput) (workspaces.Resolution, error)
}
type (
	Presence interface {
		Snapshot(domain.DeviceID) (gateway.LinkSnapshot, error)
	}
	Authenticator interface {
		AuthenticateToken(context.Context, string) (identity.VerifiedToken, error)
	}
)

type PageInput struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}
type ProjectsInput struct {
	DeviceID string `json:"device_id"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}
type CapabilitiesInput struct {
	DeviceID     string `json:"device_id"`
	ProjectAlias string `json:"project_alias"`
}
type PrepareInput struct {
	DeviceID      string  `json:"device_id"`
	ProjectAlias  string  `json:"project_alias"`
	Brief         string  `json:"brief" jsonschema:"UTF-8 brief up to 256 KiB; encoded frame must also fit 1 MiB."`
	Provider      string  `json:"provider"`
	Permission    string  `json:"permission"`
	BudgetSeconds uint32  `json:"budget_seconds"`
	Model         *string `json:"model,omitempty" jsonschema:"Omit for the provider native default; otherwise select an advertised model."`
	Effort        *string `json:"effort,omitempty" jsonschema:"Omit for the provider native default; otherwise select an advertised effort."`
}
type (
	OperationInput struct {
		OperationID string `json:"operation_id"`
	}
	CancelInput struct {
		OperationID    string `json:"operation_id"`
		CancellationID string `json:"cancellation_id" jsonschema:"Stable 32-character lowercase hex control ID; reuse it on every retry."`
	}
)

type RangeInput struct {
	OperationID string              `json:"operation_id"`
	Descriptor  protocol.Descriptor `json:"descriptor"`
	Offset      int64               `json:"offset"`
	Limit       int                 `json:"limit"`
}

type Envelope[T any] struct {
	Data  *T         `json:"data,omitempty"`
	Error *ToolError `json:"error,omitempty"`
}
type ToolError struct {
	Code         string `json:"code"`
	Retryable    bool   `json:"retryable"`
	OperationID  string `json:"operation_id,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	RetryAfterMS int    `json:"retry_after_ms,omitempty"`
}

type (
	WorkspacesInput struct {
		DeviceID string `json:"device_id"`
	}
	ResolveProjectInput struct {
		DeviceID     string `json:"device_id"`
		RequestID    string `json:"request_id" jsonschema:"Stable 32-character lowercase hex pin request ID; retain and reuse it with identical selection after retries."`
		WorkspaceID  string `json:"workspace_id"`
		RelativePath string `json:"relative_path" jsonschema:"Existing directory relative to the approved workspace; use a dot for its root. No absolute paths or traversal."`
	}
)

type WorkspaceInventory struct {
	DeviceID      string                         `json:"device_id"`
	Online        bool                           `json:"online"`
	DelegateReady bool                           `json:"delegate_ready"`
	ObservedAt    *time.Time                     `json:"observed_at,omitempty"`
	Workspaces    []protocol.WorkspaceCapability `json:"workspaces"`
	ProjectBudget *protocol.ProjectBudget        `json:"project_budget,omitempty"`
}
type ResolvedProject struct {
	DeviceID     string                    `json:"device_id"`
	RequestID    string                    `json:"request_id"`
	ProjectAlias string                    `json:"project_alias"`
	Workspace    protocol.WorkspaceBinding `json:"workspace"`
	Context      protocol.ContextBinding   `json:"context"`
}
type Device struct {
	DeviceID           string     `json:"device_id"`
	Name               string     `json:"name"`
	Online             bool       `json:"online"`
	DelegateReady      bool       `json:"delegate_ready"`
	ExecutionReadiness string     `json:"execution_readiness"`
	ObservedAt         *time.Time `json:"observed_at,omitempty"`
}
type DevicePage struct {
	Devices    []Device `json:"devices"`
	NextCursor string   `json:"next_cursor,omitempty"`
}
type Project struct {
	Alias              string     `json:"alias"`
	Online             bool       `json:"online"`
	DelegateReady      bool       `json:"delegate_ready"`
	ExecutionReadiness string     `json:"execution_readiness"`
	ObservedAt         *time.Time `json:"observed_at,omitempty"`
}
type ProjectPage struct {
	Projects   []Project `json:"projects"`
	NextCursor string    `json:"next_cursor,omitempty"`
}
type Capabilities struct {
	DeviceID              string                     `json:"device_id"`
	ProjectAlias          string                     `json:"project_alias"`
	TaskReadAllowed       bool                       `json:"task_read_allowed"`
	TaskCancelAllowed     bool                       `json:"task_cancel_allowed"`
	Online                bool                       `json:"online"`
	DelegateReady         bool                       `json:"delegate_ready"`
	ExecutionReadiness    string                     `json:"execution_readiness"`
	ObservedAt            *time.Time                 `json:"observed_at,omitempty"`
	Providers             []Provider                 `json:"providers"`
	Workspace             *protocol.WorkspaceBinding `json:"workspace,omitempty"`
	CurrentPolicyRevision *uint64                    `json:"current_policy_revision,omitempty"`
}

type Provider struct {
	Provider         string   `json:"provider"`
	Models           []string `json:"models"`
	Efforts          []string `json:"efforts"`
	Authentication   string   `json:"authentication"`
	DispatchAllowed  bool     `json:"dispatch_allowed"`
	Permissions      []string `json:"permissions"`
	MaxBudgetSeconds uint32   `json:"max_budget_seconds"`
}
type Prepared struct {
	OperationID string    `json:"operation_id"`
	TaskID      string    `json:"task_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type Observation struct {
	Kind           string                     `json:"kind"`
	ObservedAt     time.Time                  `json:"observed_at"`
	Result         *protocol.Descriptor       `json:"result,omitempty"`
	Closure        *protocol.ExecutionClosure `json:"execution_closure,omitempty"`
	ClosurePending string                     `json:"execution_closure_pending,omitempty"`
}
type Operation struct {
	OperationID    string       `json:"operation_id"`
	TaskID         string       `json:"task_id"`
	DeviceID       string       `json:"device_id"`
	ProjectAlias   string       `json:"project_alias"`
	Delivery       string       `json:"delivery"`
	CreatedAt      time.Time    `json:"created_at"`
	ExpiresAt      time.Time    `json:"expires_at"`
	Reserved       bool         `json:"reserved"`
	CancellationID string       `json:"cancellation_id,omitempty"`
	Observation    *Observation `json:"observation,omitempty"`
}
type OperationPage struct {
	Operations []Operation `json:"operations"`
	NextCursor string      `json:"next_cursor,omitempty"`
}
type Cancellation struct {
	OperationID      string `json:"operation_id"`
	CancellationID   string `json:"cancellation_id"`
	DefinitelyUnsent bool   `json:"definitely_unsent"`
	ClosureConfirmed bool   `json:"closure_confirmed"`
}
