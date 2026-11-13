// Package domain defines Gateway-owned values and pure policy. It never owns
// Delegate task admission, execution, or accepted outcomes.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type (
	PrincipalID         string
	DeviceID            string
	ProjectAlias        string
	OperationID         string
	TaskID              string
	RequestID           string
	GatewayID           string
	RecoveryID          string
	AdmissionGeneration string
	CredentialEpoch     string
	RootGuard           string
	ProjectGuard        string
	CancellationID      string
	IssuanceID          string
	ProviderID          string
	BootEpoch           string
	Digest              [32]byte
)

const (
	MaxBriefBytes         = 256 << 10
	MaxFrameBytes         = 1 << 20
	MaxRetainedBytes      = 64 << 20
	MaxCorrelations       = 100000
	MaxDeviceReservations = 2
	MaxGlobalReservations = 32
	DefaultPageLimit      = 50
	MaxPageLimit          = 100
	DraftTTL              = 15 * time.Minute
	EnrollmentTTL         = 10 * time.Minute
	CertificateLifetime   = 30 * 24 * time.Hour
	RenewalAfter          = 20 * 24 * time.Hour
)

var ErrInvalid = errors.New("invalid domain value")

// RoutingToken matches the bounded ASCII identifier alphabet of WSS v1.
func RoutingToken(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return ErrInvalid
	}
	for _, c := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", c) {
			return ErrInvalid
		}
	}
	return nil
}

// Token is the common routing-identifier validator.
func Token(value string) error { return RoutingToken(value) }

func optionValue(value string) error {
	if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) {
		return ErrInvalid
	}
	for _, c := range value {
		if unicode.IsControl(c) || unicode.IsSpace(c) {
			return ErrInvalid
		}
	}
	return nil
}

// ContextToken accepts the public one-way wire commitment. Local CLI context
// tokens may contain paths and must never cross the connector's wire boundary.
func ContextToken(value string) error {
	if len(value) != 69 || !strings.HasPrefix(value, "ctx1_") || strings.ToLower(value) != value {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(value[5:]); err != nil {
		return ErrInvalid
	}
	return nil
}

// CredentialToken is safe as one unescaped URI segment or URN component.
func CredentialToken(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return ErrInvalid
	}
	for _, c := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-", c) {
			return ErrInvalid
		}
	}
	return nil
}

func (id TaskID) Validate() error {
	if len(id) != 32 || strings.ToLower(string(id)) != string(id) {
		return ErrInvalid
	}
	_, err := hex.DecodeString(string(id))
	if err != nil {
		return fmt.Errorf("task identity: %w", ErrInvalid)
	}
	return nil
}

func (id CancellationID) Validate() error { return TaskID(id).Validate() }

func (d Digest) Validate() error {
	if d == (Digest{}) {
		return ErrInvalid
	}
	return nil
}

func Hash(data []byte) Digest { return sha256.Sum256(data) }

type ExternalSubject struct {
	Issuer  string
	Subject string
}

func (s ExternalSubject) Validate() error {
	u, err := url.Parse(s.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("issuer: %w", ErrInvalid)
	}
	if len(s.Issuer) > 2048 || len(s.Subject) > 256 || strings.TrimSpace(s.Subject) == "" || !utf8.ValidString(s.Subject) {
		return fmt.Errorf("subject: %w", ErrInvalid)
	}
	return nil
}

type Scope string

const (
	InventoryRead Scope = "inventory:read"
	TaskDispatch  Scope = "task:dispatch"
	TaskRead      Scope = "task:read"
	TaskCancel    Scope = "task:cancel"
	DeviceEnroll  Scope = "device:enroll"
	DeviceManage  Scope = "device:manage"
)

func (s Scope) Validate() error {
	switch s {
	case InventoryRead, TaskDispatch, TaskRead, TaskCancel, DeviceEnroll, DeviceManage:
		return nil
	default:
		return ErrInvalid
	}
}

func (s Scope) IsTask() bool {
	return s == InventoryRead || s == TaskDispatch || s == TaskRead || s == TaskCancel
}

type ScopeSet []Scope

func (s ScopeSet) Has(scope Scope) bool {
	for _, candidate := range s {
		if candidate == scope {
			return true
		}
	}
	return false
}

func (s ScopeSet) Validate() error {
	if len(s) > 6 {
		return ErrInvalid
	}
	for i, scope := range s {
		if err := scope.Validate(); err != nil {
			return err
		}
		for _, previous := range s[:i] {
			if scope == previous {
				return ErrInvalid
			}
		}
	}
	return nil
}

type Actor struct {
	Principal PrincipalID
	Scopes    ScopeSet
}

func (a Actor) Validate() error {
	if err := Token(string(a.Principal)); err != nil {
		return err
	}
	return a.Scopes.Validate()
}

type Destination struct {
	Device  DeviceID
	Project ProjectAlias
}

func (d Destination) Validate() error {
	if err := CredentialToken(string(d.Device)); err != nil {
		return err
	}
	return Token(string(d.Project))
}

type ContextBinding struct {
	Root    RootGuard
	Project ProjectGuard
}

func (c ContextBinding) Validate() error {
	if err := ContextToken(string(c.Root)); err != nil {
		return err
	}
	return ContextToken(string(c.Project))
}

type ConnectionGeneration struct {
	BootEpoch BootEpoch
	Counter   uint64
}

func (g ConnectionGeneration) Validate() error {
	if g.Counter == 0 {
		return ErrInvalid
	}
	return Token(string(g.BootEpoch))
}

type CredentialRef struct {
	Device     DeviceID
	Epoch      CredentialEpoch
	Generation uint64
}

func (c CredentialRef) Validate() error {
	if c.Generation == 0 {
		return ErrInvalid
	}
	if err := CredentialToken(string(c.Device)); err != nil {
		return err
	}
	return CredentialToken(string(c.Epoch))
}

type SelectionKind string

const (
	NativeDefault SelectionKind = "native_default"
	Explicit      SelectionKind = "explicit"
)

type Selection struct {
	Kind  SelectionKind
	Value string
}

func (s Selection) Validate() error {
	switch s.Kind {
	case NativeDefault:
		if s.Value != "" {
			return ErrInvalid
		}
		return nil
	case Explicit:
		return optionValue(s.Value)
	default:
		return ErrInvalid
	}
}

type Permission string

const (
	ReadOnly       Permission = "read-only"
	WorkspaceWrite Permission = "workspace-write"
	FullAccess     Permission = "danger-full-access"
)

func (p Permission) Validate() error {
	switch p {
	case ReadOnly, WorkspaceWrite, FullAccess:
		return nil
	default:
		return ErrInvalid
	}
}

type ExecutionOptions struct {
	Provider      ProviderID
	Model         Selection
	Effort        Selection
	Permission    Permission
	BudgetSeconds uint32
}

func (r ExecutionOptions) Validate() error {
	if err := Token(string(r.Provider)); err != nil {
		return err
	}
	if err := r.Model.Validate(); err != nil {
		return err
	}
	if err := r.Effort.Validate(); err != nil {
		return err
	}
	if err := r.Permission.Validate(); err != nil {
		return err
	}
	if r.BudgetSeconds == 0 {
		return ErrInvalid
	}
	return nil
}

type FrozenRequest struct {
	Provider      ProviderID
	Model         Selection
	Effort        Selection
	Permission    Permission
	BudgetSeconds uint32
	Brief         string
}

func (r FrozenRequest) Options() ExecutionOptions {
	return ExecutionOptions{Provider: r.Provider, Model: r.Model, Effort: r.Effort, Permission: r.Permission, BudgetSeconds: r.BudgetSeconds}
}

func (r FrozenRequest) Validate() error {
	if err := r.Options().Validate(); err != nil {
		return err
	}
	if len(r.Brief) == 0 || len(r.Brief) > MaxBriefBytes || !utf8.ValidString(r.Brief) {
		return ErrInvalid
	}
	return nil
}

type OwnerKind string

const (
	Owned     OwnerKind = "owned"
	Ownerless OwnerKind = "ownerless"
)

type OperationOwner struct {
	Kind      OwnerKind
	Principal PrincipalID
}

func (o OperationOwner) Validate() error {
	switch o.Kind {
	case Owned:
		return Token(string(o.Principal))
	case Ownerless:
		if o.Principal != "" {
			return ErrInvalid
		}
		return nil
	default:
		return ErrInvalid
	}
}

type Correlation struct {
	Operation           OperationID
	Task                TaskID
	Gateway             GatewayID
	AdmissionGeneration AdmissionGeneration
	Owner               OperationOwner
	Destination         Destination
	Context             ContextBinding
	RequestDigest       Digest
	BriefDigest         Digest
}

func (c Correlation) validateBinding() error {
	if c.Owner.Kind != Owned {
		return ErrInvalid
	}
	for _, value := range []string{string(c.Operation), string(c.Gateway), string(c.AdmissionGeneration)} {
		if err := Token(value); err != nil {
			return err
		}
	}
	for _, err := range []error{c.Task.Validate(), c.Owner.Validate(), c.Destination.Validate(), c.Context.Validate()} {
		if err != nil {
			return err
		}
	}
	return nil
}

func (c Correlation) Validate() error {
	if err := c.validateBinding(); err != nil {
		return err
	}
	if err := c.RequestDigest.Validate(); err != nil {
		return err
	}
	return c.BriefDigest.Validate()
}

// RequestDigest binds the validated brief through its digest. Plaintext is not
// needed to reconstruct the exact immutable request after a registry restore.
func RequestDigest(c Correlation, r FrozenRequest) (Digest, error) {
	if err := r.Validate(); err != nil {
		return Digest{}, err
	}
	return RequestBindingDigest(c, r.Options(), Hash([]byte(r.Brief)))
}

// RequestBindingDigest is canonical version 2. The registry's schema version
// excludes older digest formats; recovery never guesses a v1 interpretation.
func RequestBindingDigest(c Correlation, options ExecutionOptions, brief Digest) (Digest, error) {
	if err := c.validateBinding(); err != nil {
		return Digest{}, err
	}
	if err := options.Validate(); err != nil {
		return Digest{}, err
	}
	if err := brief.Validate(); err != nil {
		return Digest{}, err
	}
	if c.BriefDigest != brief {
		return Digest{}, ErrInvalid
	}
	type binding struct {
		Version     int
		Operation   OperationID
		Task        TaskID
		Gateway     GatewayID
		Generation  AdmissionGeneration
		Owner       OperationOwner
		Destination Destination
		Context     ContextBinding
		Options     ExecutionOptions
		BriefSHA256 string
	}
	encoded, err := json.Marshal(binding{2, c.Operation, c.Task, c.Gateway, c.AdmissionGeneration, c.Owner, c.Destination, c.Context, options, hex.EncodeToString(brief[:])})
	if err != nil {
		return Digest{}, fmt.Errorf("encode request: %w", err)
	}
	return Hash(encoded), nil
}

type ErrorCode string

const (
	Invalid         ErrorCode = "invalid_request"
	Forbidden       ErrorCode = "forbidden"
	NotFound        ErrorCode = "not_found"
	Conflict        ErrorCode = "conflict"
	Expired         ErrorCode = "expired"
	Pending         ErrorCode = "pending"
	ResourceLimit   ErrorCode = "resource_limit"
	EvidenceInvalid ErrorCode = "evidence_invalid"
)

// Error has only public, bounded classification fields. Storage errors stay wrapped
// separately at the I/O boundary and must never be serialized as public messages.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string    { return string(e.Code) }
func Reject(code ErrorCode) error { return &Error{Code: code} }
