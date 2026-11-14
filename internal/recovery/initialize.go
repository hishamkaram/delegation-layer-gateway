package recovery

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// RootStore owns root eligibility and every durable initialization phase.
// The initializer owns no queue, background goroutine or task lifecycle.
type RootStore interface {
	initializationStore
	AbandonRootInitialization(context.Context, domain.RecoveryID) error
}

type initializationStore interface {
	ReadRootInitializationProgress(context.Context, domain.RootInitializationLookup) (domain.RootInitializationProgress, error)
	BeginRootInitialization(context.Context, domain.RootInitializationStart) (domain.RootInitializationProgress, error)
	RecordBarrier(context.Context, domain.ValidatedBarrierReceipt) error
	ApplyInventoryPage(context.Context, domain.ValidatedInventoryPage) error
	ApproveRecoveryReopen(context.Context, domain.RecoveryApproval) (domain.ReopenPlan, error)
	RecordReopen(context.Context, domain.ValidatedReopenReceipt) error
	FinishRecovery(context.Context, domain.RecoveryFinish) error
}

type Initializer struct {
	store     initializationStore
	namespace initializationNamespace
	now       func() time.Time
	abandon   func(context.Context, domain.RecoveryID) error
}

func NewInitializer(store RootStore, namespace *Service, now func() time.Time) (*Initializer, error) {
	if store == nil || namespace == nil || now == nil {
		return nil, domain.ErrInvalid
	}
	return &Initializer{store: store, namespace: projectInitialization{namespace}, now: now, abandon: store.AbandonRootInitialization}, nil
}

// Advance performs at most one durable initialization phase. A caller retries
// the same route/context; Registry supplies the original attempt and generation.
// A lost reply never creates a new namespace or task identity.
func (i *Initializer) Advance(ctx context.Context, lookup domain.RootInitializationLookup) (domain.RootInitializationProgress, error) {
	progress, err := i.store.ReadRootInitializationProgress(ctx, lookup)
	if err != nil {
		return progress, err
	}
	if progress.Stage == domain.RootReady {
		return progress, nil
	}
	if progress.Stage == domain.RootRestoreRequired {
		return progress, domain.Reject(domain.Conflict)
	}
	inspection, tx, err := i.namespace.inspect(ctx, lookup)
	if err != nil {
		return progress, err
	}
	progress, err = i.store.BeginRootInitialization(ctx, domain.RootInitializationStart{Route: lookup.Route, ExpectedContext: lookup.ExpectedContext, RootRoute: lookup.RootRoute, Credential: tx.Credential, Connection: tx.Connection, Now: i.now()})
	if err != nil {
		return progress, err
	}
	if progress.Stage == domain.RootReady {
		return progress, nil
	}
	// A fresh namespace is expected absent. A retry may see only its own target;
	// Delegate additionally verifies the original recovery ID on barrier replay.
	if inspection.Generation != "" && inspection.Generation != string(progress.Generation) || inspection.Recovery != "" && inspection.Recovery != progress.RecoveryID {
		return progress, domain.Reject(domain.Conflict)
	}
	if err = i.advance(ctx, progress, tx); err != nil {
		return progress, err
	}
	return i.store.ReadRootInitializationProgress(ctx, lookup)
}

func (i *Initializer) advance(ctx context.Context, p domain.RootInitializationProgress, tx domain.Transmission) error {
	root, err := p.Lookup().Namespace()
	if err != nil {
		return err
	}
	destination := domain.RecoveryDestination{Recovery: p.RecoveryID, Device: root.Device, Root: root.Root}
	plan := domain.BarrierPlan{Destination: destination, Generation: p.Generation}
	switch p.Stage {
	case domain.RootNeedsBarrier:
		report, err := i.namespace.barrier(ctx, p.Lookup(), domain.BarrierPreparation{Destination: destination, Credential: tx.Credential, Connection: tx.Connection, Now: i.now()})
		if err != nil {
			return err
		}
		receipt, err := stateReceipt(report)
		if err != nil {
			return err
		}
		return i.store.RecordBarrier(ctx, domain.ValidatedBarrierReceipt{Destination: destination, Generation: p.Generation, Receipt: receipt})
	case domain.RootNeedsInventory:
		return i.inventory(ctx, p, plan)
	case domain.RootNeedsApproval:
		_, err := i.store.ApproveRecoveryReopen(ctx, domain.RecoveryApproval{Recovery: p.RecoveryID, Now: i.now()})
		return err
	case domain.RootNeedsReopen:
		return i.finishInitialization(ctx, p)
	case domain.RootReady:
		return nil
	case domain.RootRestoreRequired, domain.RootNeedsMapping, domain.RootNeedsRegularCredential:
		return domain.Reject(domain.Conflict)
	default:
		return domain.Reject(domain.EvidenceInvalid)
	}
}

func (i *Initializer) finishInitialization(ctx context.Context, p domain.RootInitializationProgress) error {
	if p.Reopen == nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	report, err := i.namespace.reopen(ctx, p.Lookup(), *p.Reopen)
	if err != nil {
		return err
	}
	if err = i.namespace.ready(ctx, p); err != nil {
		return err
	}
	receipt, err := stateReceipt(report)
	if err != nil {
		return err
	}
	if err = i.store.RecordReopen(ctx, domain.ValidatedReopenReceipt{Target: *p.Reopen, Receipt: receipt, Now: i.now()}); err != nil {
		return err
	}
	return i.store.FinishRecovery(ctx, domain.RecoveryFinish{Recovery: p.RecoveryID, Now: i.now()})
}

func (i *Initializer) inventory(ctx context.Context, p domain.RootInitializationProgress, plan domain.BarrierPlan) error {
	report, err := i.namespace.inventory(ctx, p.Lookup(), plan, p.Cursor)
	if err != nil {
		return err
	}
	// Fresh Gateway identity plus expected-absent namespace cannot legitimately
	// own historical tasks. Existing evidence requires the explicit restore path.
	if len(report.Entries) != 0 || !report.Complete {
		return domain.Reject(domain.Conflict)
	}
	membership, err := parseDigest(report.MembershipSHA256)
	if err != nil {
		return err
	}
	complete, err := parseDigest(report.CompletenessReceipt)
	if err != nil {
		return err
	}
	return i.store.ApplyInventoryPage(ctx, domain.ValidatedInventoryPage{Destination: plan.Destination, Generation: plan.Generation, Cursor: p.Cursor, NextCursor: report.NextCursor, Membership: membership, CompletenessReceipt: &complete, Now: i.now()})
}

func stateReceipt(report protocol.OriginStateReport) (domain.Digest, error) {
	if report.Validate() != nil {
		return domain.Digest{}, domain.Reject(domain.EvidenceInvalid)
	}
	body, err := protocol.Encode(report, protocol.MaxFrameBytes)
	if err != nil {
		return domain.Digest{}, err
	}
	return domain.Hash(body), nil
}

func parseDigest(encoded string) (domain.Digest, error) {
	var digest domain.Digest
	bytes, err := hex.DecodeString(encoded)
	if err != nil || len(bytes) != len(digest) {
		return digest, domain.Reject(domain.EvidenceInvalid)
	}
	copy(digest[:], bytes)
	if digest.Validate() != nil {
		return domain.Digest{}, domain.Reject(domain.EvidenceInvalid)
	}
	return digest, nil
}

func (i *Initializer) Progress(ctx context.Context, lookup domain.RootInitializationLookup) (domain.RootInitializationProgress, error) {
	return i.store.ReadRootInitializationProgress(ctx, lookup)
}

func (i *Initializer) Abandon(ctx context.Context, id domain.RecoveryID) error {
	return i.abandon(ctx, id)
}
