package domain

import "time"

type Principal struct {
	ID      PrincipalID
	Subject ExternalSubject
	Revoked bool
}
type CredentialMode string

const (
	Regular      CredentialMode = "regular"
	RecoveryOnly CredentialMode = "recovery_only"
)

func (m CredentialMode) Validate() error {
	switch m {
	case Regular, RecoveryOnly:
		return nil
	default:
		return ErrInvalid
	}
}

type Device struct {
	ID                   DeviceID
	Name                 string
	Revoked              bool
	CredentialGeneration uint64
	ConnectionCounter    uint64
}
type (
	DeviceRegistration struct {
		ID   DeviceID
		Name string
	}
	ProjectRegistration struct {
		Destination Destination
		Context     ContextBinding
	}
	GrantKey struct {
		Principal   PrincipalID
		Destination Destination
	}
	DispatchCeiling struct {
		Providers        []ProviderID
		Permissions      []Permission
		MaxBudgetSeconds uint32
	}
)

func (c DispatchCeiling) Validate() error {
	if len(c.Providers) == 0 || len(c.Providers) > 100 || len(c.Permissions) == 0 || len(c.Permissions) > 3 || c.MaxBudgetSeconds == 0 {
		return ErrInvalid
	}
	for _, provider := range c.Providers {
		if err := Token(string(provider)); err != nil {
			return err
		}
	}
	for _, permission := range c.Permissions {
		if err := permission.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (p ProjectRegistration) Validate() error {
	if err := p.Destination.Validate(); err != nil {
		return err
	}
	if err := p.Context.Validate(); err != nil {
		return err
	}
	return nil
}

func (c DispatchCeiling) Allows(r FrozenRequest) bool {
	return c.AllowsOptions(r.Options())
}

// AllowsOptions is the sole grant-ceiling decision for both admission and resume.
func (c DispatchCeiling) AllowsOptions(r ExecutionOptions) bool {
	if c.Validate() != nil || r.Validate() != nil {
		return false
	}
	if r.BudgetSeconds > c.MaxBudgetSeconds {
		return false
	}
	providerOK, permissionOK := false, false
	for _, provider := range c.Providers {
		if provider == r.Provider {
			providerOK = true
		}
	}
	for _, permission := range c.Permissions {
		if permission == r.Permission {
			permissionOK = true
		}
	}
	return providerOK && permissionOK
}

type (
	Grant struct {
		Key     GrantKey
		Scopes  ScopeSet
		Ceiling DispatchCeiling
	}
	AuthorizationRequest struct {
		Actor       Actor
		Destination Destination
		Scope       Scope
	}
	Authorization struct {
		Principal   PrincipalID
		Destination Destination
		Grant       Grant
	}
)

func (r AuthorizationRequest) Validate() error {
	if err := r.Actor.Validate(); err != nil {
		return err
	}
	if err := r.Destination.Validate(); err != nil {
		return err
	}
	if !r.Scope.IsTask() {
		return ErrInvalid
	}
	if !r.Actor.Scopes.Has(r.Scope) {
		return Reject(Forbidden)
	}
	return nil
}

func (g Grant) Validate() error {
	if err := Token(string(g.Key.Principal)); err != nil {
		return err
	}
	if err := g.Key.Destination.Validate(); err != nil {
		return err
	}
	if err := g.Scopes.Validate(); err != nil {
		return err
	}
	if len(g.Scopes) == 0 {
		return ErrInvalid
	}
	for _, scope := range g.Scopes {
		if !scope.IsTask() {
			return ErrInvalid
		}
	}
	if g.Scopes.Has(TaskDispatch) {
		return g.Ceiling.Validate()
	}
	return nil
}

type DeliveryState string

const (
	Prepared      DeliveryState = "prepared"
	PossibleSend  DeliveryState = "possible_send"
	Resolved      DeliveryState = "resolved"
	ExpiredUnsent DeliveryState = "expired_unsent"
)

func (s DeliveryState) Validate() error {
	switch s {
	case Prepared, PossibleSend, Resolved, ExpiredUnsent:
		return nil
	default:
		return ErrInvalid
	}
}

type (
	Preparation struct {
		Correlation Correlation
		Request     FrozenRequest
		Now         time.Time
	}
	PreparedOperation struct {
		Correlation Correlation
		ExpiresAt   time.Time
	}
	Transmission struct {
		Operation         OperationID
		Credential        CredentialRef
		Connection        ConnectionGeneration
		EncodedFrameBytes int
		Now               time.Time
	}
)
type SendKind string

const (
	SendOnce        SendKind = "send_once"
	ObserveExisting SendKind = "observe_existing"
)

type (
	SendDecision struct {
		Kind      SendKind
		Operation OperationView
		Request   FrozenRequest
	}
	DispatchView struct {
		Operation OperationView
		Request   FrozenRequest
	}
	RecoveryView struct {
		Correlation Correlation
		SpecDigest  Digest
	}
	OperationView struct {
		Correlation    Correlation
		EffectiveOwner OperationOwner
		Delivery       DeliveryState
		CreatedAt      time.Time
		ExpiresAt      time.Time
		Reserved       bool
		Cancellation   CancellationID
		Observation    *DelegateObservation
	}
)

type (
	ExpirySummary struct {
		Count        int
		RemovedBytes int64
	}
	CancellationBinding struct {
		Operation        OperationID
		Cancellation     CancellationID
		Correlation      Correlation
		SpecDigest       Digest
		DefinitelyUnsent bool
	}
	ObservationKind string
)

const (
	Existing ObservationKind = "existing"
	Terminal ObservationKind = "terminal"
	Refused  ObservationKind = "refused"
	Unknown  ObservationKind = "unknown"
)

func (k ObservationKind) Validate() error {
	switch k {
	case Existing, Terminal, Refused, Unknown:
		return nil
	default:
		return ErrInvalid
	}
}

type (
	ResultDescriptor struct {
		Digest Digest
		Bytes  int64
	}
	// DelegateObservation is a dated cache. No provider output or result bytes belong here.
	DelegateObservation struct {
		Kind           ObservationKind
		ObservedAt     time.Time
		SpecDigest     Digest
		Result         *ResultDescriptor
		Closure        *ClosureEvidence
		ConfirmedStop  *StopConfirmation
		ClosurePending ClosurePending
	}
)

type ClosureKind string

const (
	ClosureRegisteredNative      ClosureKind = "registered-native"
	ClosureRegisteredRecovered   ClosureKind = "registered-recovered"
	ClosureLegacyPreviousBoot    ClosureKind = "legacy-previous-boot"
	ClosureUnregisteredRecovered ClosureKind = "unregistered-recovered"
	ClosureNeverStarted          ClosureKind = "never-started"
)

func (k ClosureKind) Validate() error {
	switch k {
	case ClosureRegisteredNative, ClosureRegisteredRecovered, ClosureLegacyPreviousBoot, ClosureUnregisteredRecovered, ClosureNeverStarted:
		return nil
	default:
		return ErrInvalid
	}
}

type ClosurePending string

const (
	NoClosurePending       ClosurePending = ""
	ClosureOwnerBusy       ClosurePending = "owner_busy"
	ClosureMissingOwner    ClosurePending = "missing_owner"
	ClosurePartialEvidence ClosurePending = "partial_evidence"
	ClosureUnproven        ClosurePending = "closure_unproven"
)

func (p ClosurePending) Validate() error {
	switch p {
	case NoClosurePending, ClosureOwnerBusy, ClosureMissingOwner, ClosurePartialEvidence, ClosureUnproven:
		return nil
	default:
		return ErrInvalid
	}
}

type ClosureEvidence struct {
	Kind      ClosureKind
	Reference Digest
}

func (c ClosureEvidence) Validate() error {
	if err := c.Kind.Validate(); err != nil {
		return err
	}
	return c.Reference.Validate()
}

// StopConfirmation is dated evidence from one matching cancellation response,
// never task ownership or permission to infer closure from a timeout.
type StopConfirmation struct {
	Cancellation CancellationID
}

func (s StopConfirmation) Validate() error { return s.Cancellation.Validate() }

func (o DelegateObservation) validateClosure() error {
	if err := o.ClosurePending.Validate(); err != nil {
		return err
	}
	if o.Kind != Terminal {
		if o.Closure != nil || o.ConfirmedStop != nil || (o.Kind == Refused && o.ClosurePending != NoClosurePending) {
			return ErrInvalid
		}
		return nil
	}
	if o.ClosurePending != NoClosurePending || (o.Closure == nil && o.ConfirmedStop == nil) {
		return ErrInvalid
	}
	if o.Closure != nil {
		if err := o.Closure.Validate(); err != nil {
			return err
		}
	}
	if o.ConfirmedStop != nil {
		return o.ConfirmedStop.Validate()
	}
	return nil
}

func (o DelegateObservation) Validate(now time.Time) error {
	if err := o.Kind.Validate(); err != nil {
		return err
	}
	if now.IsZero() || o.ObservedAt.IsZero() || o.ObservedAt.After(now) {
		return ErrInvalid
	}
	if err := o.validateClosure(); err != nil {
		return err
	}
	if o.Kind == Existing || o.Kind == Terminal {
		if err := o.SpecDigest.Validate(); err != nil {
			return err
		}
	}
	if o.Result != nil {
		if o.Result.Bytes < 0 || o.Kind == Refused {
			return ErrInvalid
		}
		return o.Result.Digest.Validate()
	}
	return nil
}

type ValidatedObservation struct {
	Correlation Correlation
	Connection  ConnectionGeneration
	Credential  CredentialRef
	Observation DelegateObservation
	Now         time.Time
}
type ValidatedResolution struct {
	ValidatedObservation
	DurableRequest bool
}

type (
	DevicePageRequest struct {
		After DeviceID
		Limit int
	}
	DevicePage struct {
		Items []Device
		Next  DeviceID
	}
	ProjectPageRequest struct {
		After ProjectAlias
		Limit int
	}
	ProjectPage struct {
		Items []ProjectRegistration
		Next  ProjectAlias
	}
	OperationPageRequest struct {
		After OperationID
		Limit int
	}
	OperationPage struct {
		Items []OperationView
		Next  OperationID
	}
)

func PageLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultPageLimit, nil
	}
	if limit < 1 || limit > MaxPageLimit {
		return 0, ErrInvalid
	}
	return limit, nil
}

type EnrollmentGrant struct {
	TokenHash  Digest
	Device     DeviceID
	Mode       CredentialMode
	Generation uint64
	CreatedAt  time.Time
	ExpiresAt  time.Time
}
type EnrollmentAttempt struct {
	TokenHash     Digest
	CSRHash       Digest
	PublicKeyHash Digest
	Issuance      IssuanceID
	Serial        []byte
	Now           time.Time
}
type RenewalAttempt struct {
	Credential    CredentialRef
	Request       RequestID
	CSRHash       Digest
	PublicKeyHash Digest
	Issuance      IssuanceID
	Serial        []byte
	Now           time.Time
}
type IssuanceIntent struct {
	ID            IssuanceID
	Serial        []byte
	Credential    CredentialRef
	Mode          CredentialMode
	CSRHash       Digest
	PublicKeyHash Digest
	NotBefore     time.Time
	NotAfter      time.Time
}
type (
	IssuanceCompletion struct {
		Intent         IssuanceID
		CertificateDER []byte
		Now            time.Time
	}
	CertificateReceipt struct {
		Intent         IssuanceIntent
		CertificateDER []byte
	}
	Credential struct {
		Ref           CredentialRef
		Mode          CredentialMode
		PublicKeyHash Digest
		NotBefore     time.Time
		NotAfter      time.Time
	}
)

type (
	RecoverySession struct {
		Kind         RecoveryKind
		ID           RecoveryID
		Epoch        CredentialEpoch
		StartedAt    time.Time
		RosterSealed bool
	}
	RecoveryStart struct {
		ID    RecoveryID
		Epoch CredentialEpoch
		Now   time.Time
	}
	RecoveryDestination struct {
		Recovery RecoveryID
		Device   DeviceID
		Root     RootGuard
	}
	RecoveryRosterSeal struct {
		Recovery             RecoveryID
		ExpectedDestinations int
	}
	ValidatedBarrierReceipt struct {
		Destination RecoveryDestination
		Generation  AdmissionGeneration
		Receipt     Digest
	}
)

type InventoryEntry struct {
	Correlation Correlation
	Observation DelegateObservation
}
type ValidatedInventoryPage struct {
	Destination         RecoveryDestination
	Generation          AdmissionGeneration
	Cursor              string
	NextCursor          string
	Entries             []InventoryEntry
	Membership          Digest
	Now                 time.Time
	CompletenessReceipt *Digest
}
type ValidatedCompletenessReceipt struct {
	Destination RecoveryDestination
	Generation  AdmissionGeneration
	Membership  Digest
	Receipt     Digest
}
type (
	RecoveryApproval struct {
		Recovery RecoveryID
		Now      time.Time
	}
	ReopenTarget struct {
		Destination  RecoveryDestination
		Generation   AdmissionGeneration
		Completeness Digest
		Revision     uint64
	}
	ReopenPlan struct {
		Recovery RecoveryID
		Targets  []ReopenTarget
	}
	ValidatedReopenReceipt struct {
		Target  ReopenTarget
		Receipt Digest
		Now     time.Time
	}
)

// Root eligibility is Registry authority. Aliases select a route; they cannot
// choose or establish an admission generation.
type RootState string

const (
	RootPending RootState = "pending"
	RootOpen    RootState = "open"
)

type RecoveryKind string

const (
	RestoreRecovery RecoveryKind = "restore"
	RootRecovery    RecoveryKind = "root"
)

type RootInitializationStage string

const (
	RootNeedsBarrier    RootInitializationStage = "needs_barrier"
	RootNeedsInventory  RootInitializationStage = "needs_inventory"
	RootNeedsApproval   RootInitializationStage = "needs_approval"
	RootNeedsReopen     RootInitializationStage = "needs_reopen"
	RootReady           RootInitializationStage = "ready"
	RootRestoreRequired RootInitializationStage = "restore_required"
)

type RootInitializationStart struct {
	Route           Destination
	ExpectedContext ContextBinding
	RootRoute       *RootRoute
	Credential      CredentialRef
	Connection      ConnectionGeneration
	Now             time.Time
}
type (
	RootInitializationLookup struct {
		Route           Destination
		ExpectedContext ContextBinding
		RootRoute       *RootRoute
	}
	RootInitializationProgress struct {
		GatewayID    GatewayID
		Route        Destination
		Context      ContextBinding
		RootRoute    *RootRoute
		RecoveryID   RecoveryID
		Generation   AdmissionGeneration
		Stage        RootInitializationStage
		Cursor       string
		Membership   Digest
		Completeness Digest
		Reopen       *ReopenTarget
	}
)

type BarrierPreparation struct {
	Destination        RecoveryDestination
	Credential         CredentialRef
	Connection         ConnectionGeneration
	ExpectedGeneration AdmissionGeneration
	Now                time.Time
}
type BarrierPlan struct {
	Destination        RecoveryDestination
	ExpectedGeneration AdmissionGeneration
	Generation         AdmissionGeneration
}
type ReopenCheck struct {
	Target     ReopenTarget
	Credential CredentialRef
	Connection ConnectionGeneration
	Now        time.Time
}

// ProjectReadinessRequest compares a dated peer advertisement with current
// Registry eligibility. Authorization errors remain distinct from not-ready.
type ProjectReadinessRequest struct {
	Actor       Actor
	Destination Destination
	Context     ContextBinding
	Generation  AdmissionGeneration
	Credential  CredentialRef
	Connection  ConnectionGeneration
	Now         time.Time
}
