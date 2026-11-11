package adminapi

import (
	"encoding/hex"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (s RecoverySession) Validate() error {
	if domain.RoutingToken(s.RecoveryID) != nil || s.StartedAt.IsZero() || (s.Kind != domain.RestoreRecovery && s.Kind != domain.RootRecovery) {
		return domain.ErrInvalid
	}
	return nil
}

func (p RecoveryDestination) Validate() error {
	if (RecoveryRootInput{RecoveryID: p.RecoveryID, DeviceID: p.DeviceID, RootGuard: p.RootGuard}).Validate() != nil || p.MissingMappings < 0 {
		return domain.ErrInvalid
	}
	for _, generation := range []string{p.ExpectedGeneration, p.Generation} {
		if generation != "" && domain.RoutingToken(generation) != nil {
			return domain.ErrInvalid
		}
	}
	if p.Cursor != "" && domain.TaskID(p.Cursor).Validate() != nil {
		return domain.ErrInvalid
	}
	for _, digest := range []string{p.MembershipSHA256, p.CompletenessSHA256} {
		if digest != "" && !validDigest(digest) {
			return domain.ErrInvalid
		}
	}
	switch p.Stage {
	case domain.RootNeedsBarrier, domain.RootNeedsInventory, domain.RootNeedsApproval, domain.RootNeedsReopen, domain.RootReady, domain.RootRestoreRequired, domain.RootNeedsMapping, domain.RootNeedsRegularCredential:
		return nil
	default:
		return domain.ErrInvalid
	}
}

func (p RecoveryProgress) Validate() error {
	if p.Session.Validate() != nil || len(p.Destinations) > maxAdministrativePageItems || (p.Status != domain.RecoveryActive && p.Status != domain.RecoveryFinished && p.Status != domain.RecoveryAborted) {
		return domain.ErrInvalid
	}
	for _, destination := range p.Destinations {
		if destination.Validate() != nil || destination.RecoveryID != p.Session.RecoveryID {
			return domain.ErrInvalid
		}
	}
	if p.Next != nil {
		return p.Next.Validate()
	}
	return nil
}

func validDigest(value string) bool {
	return (protocol.Descriptor{SHA256: value}).Validate() == nil
}

func (s AdministrativeTaskSummary) Validate() error {
	if s.Key.Validate() != nil || s.Delivery.Validate() != nil || (s.Attributed != (s.OperationID != "")) {
		return domain.ErrInvalid
	}
	if s.OperationID != "" && domain.RoutingToken(s.OperationID) != nil {
		return domain.ErrInvalid
	}
	if s.CancellationID != "" && domain.CancellationID(s.CancellationID).Validate() != nil {
		return domain.ErrInvalid
	}
	if s.SpecSHA256 != "" && !validDigest(s.SpecSHA256) {
		return domain.ErrInvalid
	}
	if s.ObservedAt == nil {
		if s.ObservationKind != "" {
			return domain.ErrInvalid
		}
	} else if s.ObservedAt.IsZero() || s.ObservationKind.Validate() != nil {
		return domain.ErrInvalid
	}
	return nil
}

func (t AdministrativeTask) Validate() error {
	if err := t.validateIdentity(); err != nil {
		return err
	}
	if t.CancellationID != "" && domain.CancellationID(t.CancellationID).Validate() != nil {
		return domain.ErrInvalid
	}
	if !t.Attributed && t.Receipt == nil {
		return domain.ErrInvalid
	}
	if t.Receipt != nil && t.Receipt.Validate() != nil {
		return domain.ErrInvalid
	}
	if t.Observation != nil {
		if t.Observation.Validate() != nil || (t.Observation.StopCancellation != "" && t.Observation.StopCancellation != t.CancellationID) {
			return domain.ErrInvalid
		}
	}
	return nil
}

func (t AdministrativeTask) validateIdentity() error {
	if t.Key.Validate() != nil || t.Delivery.Validate() != nil || t.Attributed != (t.OriginalProjectAlias != "") {
		return domain.ErrInvalid
	}
	if t.OriginalProjectAlias != "" && (domain.Destination{Device: domain.DeviceID(t.Key.DeviceID), Project: domain.ProjectAlias(t.OriginalProjectAlias)}).Validate() != nil {
		return domain.ErrInvalid
	}
	binding := protocol.TaskBinding{TaskID: t.Key.TaskID, Context: protocol.ContextBinding{Root: t.Key.RootGuard, Project: t.ProjectGuard}, Origin: t.Origin, SpecSHA256: t.SpecSHA256}
	if binding.Validate(t.Receipt != nil) != nil {
		return domain.ErrInvalid
	}
	return nil
}

func (r TaskReceipt) Validate() error {
	options := domain.HistoricalExecutionOptions{Provider: domain.ProviderID(r.Provider), Permission: r.Permission, BudgetNanoseconds: r.BudgetNanoseconds, Model: domain.Selection{Kind: domain.SelectionKind(r.Model.Kind), Value: r.Model.Value}, Effort: domain.Selection{Kind: domain.SelectionKind(r.Effort.Kind), Value: r.Effort.Value}}
	if !validDigest(r.BriefSHA256) || options.Validate() != nil {
		return domain.ErrInvalid
	}
	return nil
}

func (o TaskObservation) Validate() error {
	observation := domain.DelegateObservation{Kind: o.Kind, ObservedAt: o.ObservedAt, ClosurePending: o.ClosurePending}
	var err error
	if o.SpecSHA256 != "" {
		observation.SpecDigest, err = metadataDigest(o.SpecSHA256)
		if err != nil {
			return err
		}
	}
	if o.Result != nil {
		digest, digestErr := metadataDigest(o.Result.SHA256)
		if digestErr != nil {
			return digestErr
		}
		observation.Result = &domain.ResultDescriptor{Digest: digest, Bytes: o.Result.Length}
	}
	if o.Closure != nil {
		digest, digestErr := metadataDigest(o.Closure.ReferenceSHA256)
		if digestErr != nil {
			return digestErr
		}
		observation.Closure = &domain.ClosureEvidence{Kind: domain.ClosureKind(o.Closure.Kind), Reference: digest}
	}
	if o.StopCancellation != "" {
		observation.ConfirmedStop = &domain.StopConfirmation{Cancellation: domain.CancellationID(o.StopCancellation)}
	}
	return observation.Validate(o.ObservedAt)
}

func metadataDigest(value string) (domain.Digest, error) {
	var digest domain.Digest
	if !validDigest(value) {
		return digest, domain.ErrInvalid
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return digest, err
	}
	copy(digest[:], decoded)
	return digest, digest.Validate()
}
