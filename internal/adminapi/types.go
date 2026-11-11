// Package adminapi exposes fixed administrative operations exclusively through
// an owned private Unix listener. Registry remains the durable state authority.
package adminapi

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/recovery"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type Roots interface {
	Advance(context.Context, domain.RootInitializationLookup) (domain.RootInitializationProgress, error)
	Progress(context.Context, domain.RootInitializationLookup) (domain.RootInitializationProgress, error)
	Abandon(context.Context, domain.RecoveryID) error
}

type Recoveries interface {
	Begin(context.Context, domain.RecoveryID) (domain.RecoverySession, error)
	Register(context.Context, domain.RecoveryDestination) error
	RegisterRoutingRoster(context.Context, domain.RecoveryID, []domain.DeviceID) error
	Seal(context.Context, domain.RecoveryRosterSeal) error
	Progress(context.Context, domain.RecoveryProgressRequest) (domain.RecoveryProgressPage, error)
	Advance(context.Context, recovery.RestoreAdvance) (domain.RecoveryDestinationProgress, error)
	Finish(context.Context, domain.RecoveryID) error
}

type AdministrativeTasks interface {
	List(context.Context, domain.AdministrativeTaskPageRequest) (domain.AdministrativeTaskPage, error)
	Get(context.Context, domain.NativeTaskKey) (domain.AdministrativeTaskView, error)
	Control(context.Context, recovery.DrainRequest) (domain.AdministrativeTaskView, error)
}

type RoutingPermits interface {
	ListRoutingPermits(context.Context, routing.PermitPageRequest) (routing.PermitPage, error)
}

type ProjectInspector interface {
	Inspect(context.Context, domain.Destination, domain.ContextBinding) (protocol.ProjectCapability, domain.Transmission, error)
}

type Store interface {
	RegisterDevice(context.Context, domain.DeviceRegistration) (domain.Device, error)
	RegisterProject(context.Context, domain.ProjectRegistration) error
	ResolvePrincipal(context.Context, domain.ExternalSubject) (domain.Principal, error)
	PutGrant(context.Context, domain.Grant) error
	RevokeGrant(context.Context, domain.GrantKey) error
	SetPrincipalRevoked(context.Context, domain.PrincipalID, bool) error
	SetDeviceRevoked(context.Context, domain.DeviceID, bool) error
	CreateEnrollment(context.Context, domain.EnrollmentGrant) error
}

// Disconnector must honor cancellation or report unconfirmed cleanup while its
// transport owner retains that cleanup. An already-offline device is success.
type (
	Disconnector interface {
		Disconnect(context.Context, domain.DeviceID) error
	}
	Options struct {
		// Metadata hooks are optional and mounted only at fixed private admin paths.
		Roots                  Roots
		Recoveries             Recoveries
		Tasks                  AdministrativeTasks
		RoutingDrains          RoutingDrains
		GenerationDisconnector GenerationDisconnector
		Permits                RoutingPermits
		Projects               ProjectInspector
		MetadataMetrics        http.Handler
		MetadataHealth         func() observability.Health
		Store                  Store
		Authority              *Authorizer
		Disconnector           Disconnector
		Random                 io.Reader
		Now                    func() time.Time
	}
)

type (
	RegisterDeviceInput struct {
		DeviceID string `json:"device_id"`
		Name     string `json:"name"`
	}
	Device struct {
		DeviceID             string `json:"device_id"`
		Name                 string `json:"name"`
		Revoked              bool   `json:"revoked"`
		CredentialGeneration uint64 `json:"credential_generation"`
	}
	RegisterProjectInput struct {
		DeviceID     string `json:"device_id"`
		ProjectAlias string `json:"project_alias"`
		RootGuard    string `json:"root_guard"`
		ProjectGuard string `json:"project_guard"`
	}
)

type (
	ResolvePrincipalInput struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
	}
	Principal struct {
		PrincipalID string `json:"principal_id"`
		Revoked     bool   `json:"revoked"`
	}
	GrantKey struct {
		PrincipalID  string `json:"principal_id"`
		DeviceID     string `json:"device_id"`
		ProjectAlias string `json:"project_alias"`
	}
	PutGrantInput struct {
		PrincipalID      string              `json:"principal_id"`
		DeviceID         string              `json:"device_id"`
		ProjectAlias     string              `json:"project_alias"`
		Scopes           []domain.Scope      `json:"scopes"`
		Providers        []domain.ProviderID `json:"providers"`
		Permissions      []domain.Permission `json:"permissions"`
		MaxBudgetSeconds uint32              `json:"max_budget_seconds"`
	}
)

type (
	PrincipalRevocationInput struct {
		PrincipalID string `json:"principal_id"`
		Revoked     *bool  `json:"revoked"`
	}
	DeviceRevocationInput struct {
		DeviceID string `json:"device_id"`
		Revoked  *bool  `json:"revoked"`
	}
	EnrollmentInput struct {
		DeviceID   string                `json:"device_id"`
		Mode       domain.CredentialMode `json:"mode"`
		Generation uint64                `json:"generation"`
	}
	// Enrollment is delivered once. A lost response cannot recover its raw token;
	// local admin may explicitly create another grant. Creation never rotates a key.
	Enrollment struct {
		Token     string    `json:"token"`
		DeviceID  string    `json:"device_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	Mutation struct {
		Committed bool `json:"committed"`
	}
	Failure struct {
		Code      string `json:"code"`
		Committed bool   `json:"committed"`
	}
)

type Error struct {
	Code  string
	cause error
}

func (e *Error) Error() string            { return e.Code }
func (e *Error) Unwrap() error            { return e.cause }
func fail(code string, cause error) error { return &Error{Code: code, cause: cause} }

type RootInput struct {
	DeviceID     string `json:"device_id"`
	ProjectAlias string `json:"project_alias"`
	RootGuard    string `json:"root_guard"`
	ProjectGuard string `json:"project_guard"`
}
type RootProgress struct {
	GatewayID    string                         `json:"gateway_id"`
	DeviceID     string                         `json:"device_id"`
	ProjectAlias string                         `json:"project_alias"`
	RecoveryID   string                         `json:"recovery_id,omitempty"`
	Generation   string                         `json:"generation,omitempty"`
	Stage        domain.RootInitializationStage `json:"stage"`
}
type RootAbandonInput struct {
	RecoveryID string `json:"recovery_id"`
}
