package recovery

import (
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// inventoryPage translates authenticated native facts, never attribution or
// lifecycle outcomes. Registry classifies receipts inside its import transaction.
func inventoryPage(report protocol.OriginInventoryReport, plan domain.BarrierPlan, cursor string, gateway domain.GatewayID, transmission domain.Transmission, now time.Time) (domain.ImportedInventoryPage, error) {
	request := protocol.OriginInventoryRequest{GatewayID: string(gateway), Generation: string(plan.Generation), Cursor: cursor, Limit: domain.MaxPageLimit, ExpectedRoot: string(plan.Destination.Root)}
	if report.ValidateFor(request) != nil || transmission.Credential.Validate() != nil || transmission.Connection.Validate() != nil || transmission.Credential.Device != plan.Destination.Device || domain.Token(string(plan.Destination.Recovery)) != nil || now.IsZero() {
		return domain.ImportedInventoryPage{}, domain.Reject(domain.EvidenceInvalid)
	}
	page := domain.ImportedInventoryPage{Destination: plan.Destination, Generation: plan.Generation, Cursor: cursor, NextCursor: report.NextCursor, Credential: transmission.Credential, Connection: transmission.Connection, Now: now}
	var err error
	page.Membership, err = parseDigest(report.MembershipSHA256)
	if err != nil {
		return domain.ImportedInventoryPage{}, err
	}
	if report.Complete {
		receipt, parseErr := parseDigest(report.CompletenessReceipt)
		if parseErr != nil {
			return domain.ImportedInventoryPage{}, parseErr
		}
		page.CompletenessReceipt = &receipt
	}
	page.Entries = make([]domain.ImportedInventoryEntry, 0, len(report.Entries))
	for _, entry := range report.Entries {
		mapped, mapErr := inventoryEntry(entry, now)
		if mapErr != nil {
			return domain.ImportedInventoryPage{}, mapErr
		}
		page.Entries = append(page.Entries, mapped)
	}
	return page, nil
}

func inventoryEntry(entry protocol.OriginInventoryEntry, now time.Time) (domain.ImportedInventoryEntry, error) {
	if entry.Validate() != nil {
		return domain.ImportedInventoryEntry{}, domain.Reject(domain.EvidenceInvalid)
	}
	if entry.Resolution == "permanently_refused" {
		refusal := &domain.NamespaceRefusal{Task: domain.TaskID(entry.TaskID)}
		if entry.Origin != nil {
			origin, err := inventoryOrigin(*entry.Origin)
			if err != nil {
				return domain.ImportedInventoryEntry{}, err
			}
			refusal.Origin = &origin
		}
		return domain.ImportedInventoryEntry{Refusal: refusal}, nil
	}
	if entry.Receipt == nil {
		return domain.ImportedInventoryEntry{}, domain.Reject(domain.EvidenceInvalid)
	}
	receipt, err := inventoryReceipt(*entry.Receipt)
	if err != nil {
		return domain.ImportedInventoryEntry{}, err
	}
	return domain.ImportedInventoryEntry{Existing: &domain.CanonicalInventoryExisting{Receipt: receipt, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: now, SpecDigest: receipt.Binding.SpecDigest}}}, nil
}

func inventoryOrigin(origin protocol.Origin) (domain.TaskOrigin, error) {
	digest, err := parseDigest(origin.RequestSHA256)
	if err != nil {
		return domain.TaskOrigin{}, err
	}
	result := domain.TaskOrigin{Gateway: domain.GatewayID(origin.GatewayID), AdmissionGeneration: domain.AdmissionGeneration(origin.AdmissionGeneration), Operation: domain.OperationID(origin.OperationID), Principal: domain.PrincipalID(origin.PrincipalRef), RequestDigest: digest}
	if result.Validate() != nil {
		return domain.TaskOrigin{}, domain.Reject(domain.EvidenceInvalid)
	}
	return result, nil
}

func inventoryReceipt(receipt protocol.InventoryReceipt) (domain.NativeTaskReceipt, error) {
	if receipt.Validate() != nil {
		return domain.NativeTaskReceipt{}, domain.Reject(domain.EvidenceInvalid)
	}
	origin, err := inventoryOrigin(receipt.Task.Origin)
	if err != nil {
		return domain.NativeTaskReceipt{}, err
	}
	spec, err := parseDigest(receipt.Task.SpecSHA256)
	if err != nil {
		return domain.NativeTaskReceipt{}, err
	}
	brief, err := parseDigest(receipt.BriefSHA256)
	if err != nil {
		return domain.NativeTaskReceipt{}, err
	}
	options := receipt.ExecutionOptions
	result := domain.NativeTaskReceipt{
		Binding:     domain.NativeTaskBinding{Task: domain.TaskID(receipt.Task.TaskID), Context: domain.ContextBinding{Root: domain.RootGuard(receipt.Task.Context.Root), Project: domain.ProjectGuard(receipt.Task.Context.Project)}, Origin: origin, SpecDigest: spec},
		Options:     domain.HistoricalExecutionOptions{Provider: domain.ProviderID(options.Provider), Permission: domain.Permission(options.Permission), BudgetNanoseconds: options.BudgetNanoseconds, Model: domain.Selection{Kind: domain.SelectionKind(options.Model.Kind), Value: options.Model.Value}, Effort: domain.Selection{Kind: domain.SelectionKind(options.Effort.Kind), Value: options.Effort.Value}},
		BriefDigest: brief,
	}
	if result.Validate() != nil {
		return domain.NativeTaskReceipt{}, domain.Reject(domain.EvidenceInvalid)
	}
	return result, nil
}
