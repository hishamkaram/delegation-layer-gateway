package domain

import "time"

// NativeTaskKey identifies Delegate authority without inventing a Gateway owner.
type NativeTaskKey struct {
	Device DeviceID
	Root   RootGuard
	Task   TaskID
}

func (k NativeTaskKey) Validate() error {
	if CredentialToken(string(k.Device)) != nil || ContextToken(string(k.Root)) != nil || k.Task.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type TaskOrigin struct {
	Gateway             GatewayID
	AdmissionGeneration AdmissionGeneration
	Operation           OperationID
	Principal           PrincipalID
	RequestDigest       Digest
}

func (o TaskOrigin) Validate() error {
	for _, value := range []string{string(o.Gateway), string(o.AdmissionGeneration), string(o.Operation), string(o.Principal)} {
		if RoutingToken(value) != nil {
			return ErrInvalid
		}
	}
	return o.RequestDigest.Validate()
}

type NativeTaskBinding struct {
	Task       TaskID
	Context    ContextBinding
	Origin     TaskOrigin
	SpecDigest Digest
}

func (b NativeTaskBinding) Validate() error {
	if b.Task.Validate() != nil || b.Context.Validate() != nil || b.Origin.Validate() != nil || b.SpecDigest.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

// HistoricalExecutionOptions preserves native precision without rounding into a
// different immutable Gateway request.
type HistoricalExecutionOptions struct {
	Provider          ProviderID
	Permission        Permission
	BudgetNanoseconds int64
	Model             Selection
	Effort            Selection
}

func (o HistoricalExecutionOptions) Validate() error {
	if RoutingToken(string(o.Provider)) != nil || o.Permission.Validate() != nil || o.BudgetNanoseconds <= 0 || o.Model.Validate() != nil || o.Effort.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type NativeTaskReceipt struct {
	Binding     NativeTaskBinding
	Options     HistoricalExecutionOptions
	BriefDigest Digest
}

func (r NativeTaskReceipt) Validate() error {
	if r.Binding.Validate() != nil || r.Options.Validate() != nil || r.BriefDigest.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type CanonicalInventoryExisting struct {
	Receipt     NativeTaskReceipt
	Observation DelegateObservation
}

type (
	NamespaceRefusal struct {
		Task   TaskID
		Origin *TaskOrigin
	}
	ImportedInventoryEntry struct {
		Existing *CanonicalInventoryExisting
		Refusal  *NamespaceRefusal
	}
)

type ImportedInventoryPage struct {
	Destination         RecoveryDestination
	Generation          AdmissionGeneration
	Cursor              string
	NextCursor          string
	Entries             []ImportedInventoryEntry
	Membership          Digest
	Now                 time.Time
	CompletenessReceipt *Digest
	Credential          CredentialRef
	Connection          ConnectionGeneration
}

type InventoryApplyResult struct {
	CanonicalComplete bool
	MissingMappings   int
}

type AdministrativeRouteBinding struct {
	Destination Destination
	Context     ContextBinding
	Credential  CredentialRef
	Connection  ConnectionGeneration
	Now         time.Time
}

// AdministrativeTaskBinding may have unknown SpecDigest for resolve/fence;
// unlike a native receipt, it does not claim canonical options were recovered.
type AdministrativeTaskBinding struct {
	Task       TaskID
	Context    ContextBinding
	Origin     TaskOrigin
	SpecDigest Digest
}

func (b AdministrativeTaskBinding) Validate() error {
	if b.Task.Validate() != nil || b.Context.Validate() != nil || b.Origin.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type AdministrativeTaskView struct {
	Key          NativeTaskKey
	Correlation  *Correlation
	Receipt      *NativeTaskReceipt
	Binding      AdministrativeTaskBinding
	Delivery     DeliveryState
	Reserved     bool
	Cancellation CancellationID
	Observation  *DelegateObservation
}

type (
	AdministrativeTaskPageRequest struct {
		After *NativeTaskKey
		Limit int
	}
	AdministrativeTaskPage struct {
		Items []AdministrativeTaskView
		Next  *NativeTaskKey
	}
)

type AdministrativeAction string

const (
	AdministrativeResolve AdministrativeAction = "resolve"
	AdministrativeStatus  AdministrativeAction = "status"
	AdministrativeCollect AdministrativeAction = "collect"
	AdministrativeFence   AdministrativeAction = "fence"
	AdministrativeCancel  AdministrativeAction = "cancel"
)

func (a AdministrativeAction) Validate() error {
	switch a {
	case AdministrativeResolve, AdministrativeStatus, AdministrativeCollect, AdministrativeFence, AdministrativeCancel:
		return nil
	default:
		return ErrInvalid
	}
}

type AdministrativeDrainCheck struct {
	Key         NativeTaskKey
	Action      AdministrativeAction
	Destination Destination
	Credential  CredentialRef
	Connection  ConnectionGeneration
	Now         time.Time
}

type AdministrativeObservation struct {
	Check       AdministrativeDrainCheck
	Binding     AdministrativeTaskBinding
	Observation DelegateObservation
}

type RecoveryStatus string

type RecoveryFinish struct {
	Recovery RecoveryID
	Now      time.Time
}

const (
	RecoveryActive   RecoveryStatus = "active"
	RecoveryFinished RecoveryStatus = "finished"
	RecoveryAborted  RecoveryStatus = "aborted"
)

type (
	RecoveryDestinationCursor struct {
		Device DeviceID
		Root   RootGuard
	}
	RecoveryProgressRequest struct {
		Recovery RecoveryID
		After    *RecoveryDestinationCursor
		Limit    int
		Now      time.Time
	}
	RecoveryProgressPage struct {
		Session      RecoverySession
		Status       RecoveryStatus
		Revision     uint64
		Destinations []RecoveryDestinationProgress
		Next         *RecoveryDestinationCursor
	}
)

type RecoveryDestinationProgress struct {
	Destination     RecoveryDestination
	Barrier         *BarrierPlan
	BarrierReceipt  *Digest
	Stage           RootInitializationStage
	Cursor          string
	Membership      *Digest
	Completeness    *Digest
	MissingMappings int
	Reopen          *ReopenTarget
	RecordedReopen  *Digest
}

const (
	RootNeedsMapping           RootInitializationStage = "needs_mapping"
	RootNeedsRegularCredential RootInitializationStage = "needs_regular_credential"
)
