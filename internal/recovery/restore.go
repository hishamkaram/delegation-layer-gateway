package recovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// RestoreBeginStore owns the durable identity and epoch of a recovery intent.
type RestoreBeginStore interface {
	BeginRecovery(context.Context, domain.RecoveryStart) (domain.RecoverySession, error)
	ReadRecoveryProgress(context.Context, domain.RecoveryProgressRequest) (domain.RecoveryProgressPage, error)
}

// RestoreStore is the sole authority for durable recovery phases and holds.
// Restorer performs explicit bounded calls using evidence from the live device.
type RestoreStore interface {
	RestoreBeginStore
	RegisterRecoveryDestination(context.Context, domain.RecoveryDestination) error
	RegisterRoutingRecoveryRoster(context.Context, domain.RecoveryID, []domain.DeviceID) error
	SealRecoveryRoster(context.Context, domain.RecoveryRosterSeal) error
	RecordBarrier(context.Context, domain.ValidatedBarrierReceipt) error
	ApplyImportedInventoryPage(context.Context, domain.ImportedInventoryPage) (domain.InventoryApplyResult, error)
	ApproveRecoveryReopen(context.Context, domain.RecoveryApproval) (domain.ReopenPlan, error)
	RecordReopen(context.Context, domain.ValidatedReopenReceipt) error
	FinishRecovery(context.Context, domain.RecoveryFinish) error
}

type Restorer struct {
	store     RestoreStore
	namespace *Service
	now       func() time.Time
}

type RestoreAdvance struct {
	Recovery domain.RecoveryID
	Route    domain.Destination
	Root     domain.RootGuard
}

func NewRestorer(store RestoreStore, namespace *Service, now func() time.Time) (*Restorer, error) {
	if store == nil || namespace == nil || now == nil {
		return nil, domain.ErrInvalid
	}
	return &Restorer{store: store, namespace: namespace, now: now}, nil
}

// Begin reuses the epoch already stored for this explicit recovery identity.
// A lost reply is recovered by reading that identity before another mutation.
func (r *Restorer) Begin(ctx context.Context, id domain.RecoveryID) (domain.RecoverySession, error) {
	return BeginRestore(ctx, r.store, id, r.now())
}

// BeginRestore shares the explicit recovery identity and epoch handling between
// the live private administrator and the offline caller holding the instance lease.
func BeginRestore(ctx context.Context, store RestoreBeginStore, id domain.RecoveryID, now time.Time) (domain.RecoverySession, error) {
	if store == nil || now.IsZero() || domain.RoutingToken(string(id)) != nil {
		return domain.RecoverySession{}, domain.ErrInvalid
	}
	page, err := store.ReadRecoveryProgress(ctx, domain.RecoveryProgressRequest{Recovery: id, Limit: 1, Now: now})
	if err == nil {
		if page.Session.Kind != domain.RestoreRecovery || page.Status != domain.RecoveryActive {
			return domain.RecoverySession{}, domain.Reject(domain.Conflict)
		}
		return page.Session, nil
	}
	var classified *domain.Error
	if !errors.As(err, &classified) || classified.Code != domain.NotFound {
		return domain.RecoverySession{}, err
	}
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return domain.RecoverySession{}, errors.New("recovery epoch entropy unavailable")
	}
	return store.BeginRecovery(ctx, domain.RecoveryStart{ID: id, Epoch: domain.CredentialEpoch(hex.EncodeToString(entropy[:])), Now: now})
}

func (r *Restorer) Register(ctx context.Context, destination domain.RecoveryDestination) error {
	return r.store.RegisterRecoveryDestination(ctx, destination)
}

func (r *Restorer) RegisterRoutingRoster(ctx context.Context, id domain.RecoveryID, devices []domain.DeviceID) error {
	if devices == nil {
		return domain.ErrInvalid
	}
	return r.store.RegisterRoutingRecoveryRoster(ctx, id, devices)
}

func (r *Restorer) Seal(ctx context.Context, input domain.RecoveryRosterSeal) error {
	return r.store.SealRecoveryRoster(ctx, input)
}

func (r *Restorer) Progress(ctx context.Context, input domain.RecoveryProgressRequest) (domain.RecoveryProgressPage, error) {
	input.Now = r.now()
	return r.store.ReadRecoveryProgress(ctx, input)
}

func (r *Restorer) Finish(ctx context.Context, id domain.RecoveryID) error {
	return r.store.FinishRecovery(ctx, domain.RecoveryFinish{Recovery: id, Now: r.now()})
}

// Advance performs one durable phase for the explicitly selected root. It never
// chooses another device or submits a task while reconciling recovery evidence.
func (r *Restorer) Advance(ctx context.Context, input RestoreAdvance) (domain.RecoveryDestinationProgress, error) {
	progress, err := r.destination(ctx, input)
	if err != nil {
		return progress, err
	}
	if err = r.advance(ctx, input, progress); err != nil {
		return progress, err
	}
	return r.destination(ctx, input)
}

func (r *Restorer) destination(ctx context.Context, input RestoreAdvance) (domain.RecoveryDestinationProgress, error) {
	if domain.RoutingToken(string(input.Recovery)) != nil || input.Route.Validate() != nil || domain.ContextToken(string(input.Root)) != nil {
		return domain.RecoveryDestinationProgress{}, domain.ErrInvalid
	}
	request := domain.RecoveryProgressRequest{Recovery: input.Recovery, Limit: domain.MaxPageLimit}
	for {
		page, err := r.Progress(ctx, request)
		if err != nil {
			return domain.RecoveryDestinationProgress{}, err
		}
		if page.Session.Kind != domain.RestoreRecovery || page.Status != domain.RecoveryActive {
			return domain.RecoveryDestinationProgress{}, domain.Reject(domain.Conflict)
		}
		if destination, found := selectedRecoveryDestination(page.Destinations, input); found {
			return destination, nil
		}
		if page.Next == nil {
			return domain.RecoveryDestinationProgress{}, domain.Reject(domain.NotFound)
		}
		if request.After != nil && (page.Next.Device < request.After.Device || (page.Next.Device == request.After.Device && page.Next.Root <= request.After.Root)) {
			return domain.RecoveryDestinationProgress{}, domain.Reject(domain.EvidenceInvalid)
		}
		request.After = page.Next
	}
}

func selectedRecoveryDestination(destinations []domain.RecoveryDestinationProgress, input RestoreAdvance) (domain.RecoveryDestinationProgress, bool) {
	for _, destination := range destinations {
		if destination.Destination.Device == input.Route.Device && destination.Destination.Root == input.Root {
			return destination, true
		}
	}
	return domain.RecoveryDestinationProgress{}, false
}

func (r *Restorer) advance(ctx context.Context, input RestoreAdvance, progress domain.RecoveryDestinationProgress) error {
	switch progress.Stage {
	case domain.RootNeedsBarrier:
		return r.barrier(ctx, input, progress)
	case domain.RootNeedsInventory:
		if progress.Barrier == nil {
			return domain.Reject(domain.EvidenceInvalid)
		}
		report, transmission, err := r.namespace.inventory(ctx, input.Route, *progress.Barrier, progress.Cursor)
		if err != nil {
			return err
		}
		page, err := inventoryPage(report, *progress.Barrier, progress.Cursor, r.namespace.gateway, transmission, r.now())
		if err != nil {
			return err
		}
		_, err = r.store.ApplyImportedInventoryPage(ctx, page)
		return err
	case domain.RootNeedsApproval:
		_, err := r.store.ApproveRecoveryReopen(ctx, domain.RecoveryApproval{Recovery: input.Recovery, Now: r.now()})
		return err
	case domain.RootNeedsReopen:
		return r.reopen(ctx, input, progress)
	case domain.RootNeedsMapping, domain.RootNeedsRegularCredential:
		return domain.Reject(domain.Pending)
	case domain.RootReady:
		return nil
	case domain.RootRestoreRequired:
		return domain.Reject(domain.Conflict)
	default:
		return domain.Reject(domain.EvidenceInvalid)
	}
}

func (r *Restorer) barrier(ctx context.Context, input RestoreAdvance, progress domain.RecoveryDestinationProgress) error {
	root, transmission, err := r.namespace.InspectRoot(ctx, input.Route, input.Root)
	if err != nil {
		return err
	}
	expected := domain.AdmissionGeneration("")
	if root.Origin != nil {
		expected = domain.AdmissionGeneration(root.Origin.Generation)
	}
	if progress.Barrier != nil {
		expected = progress.Barrier.ExpectedGeneration
	}
	report, err := r.namespace.Barrier(ctx, input.Route, domain.BarrierPreparation{Destination: progress.Destination, Credential: transmission.Credential, Connection: transmission.Connection, ExpectedGeneration: expected, Now: r.now()})
	if err != nil {
		return err
	}
	receipt, err := stateReceipt(report)
	if err != nil {
		return err
	}
	return r.store.RecordBarrier(ctx, domain.ValidatedBarrierReceipt{Destination: progress.Destination, Generation: domain.AdmissionGeneration(report.Generation), Receipt: receipt})
}

func (r *Restorer) reopen(ctx context.Context, input RestoreAdvance, progress domain.RecoveryDestinationProgress) error {
	if progress.Reopen == nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	report, err := r.namespace.Reopen(ctx, input.Route, input.Root, *progress.Reopen)
	if err != nil {
		return err
	}
	receipt, err := stateReceipt(report)
	if err != nil {
		return err
	}
	return r.store.RecordReopen(ctx, domain.ValidatedReopenReceipt{Target: *progress.Reopen, Receipt: receipt, Now: r.now()})
}
