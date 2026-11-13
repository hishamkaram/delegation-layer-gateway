package connector

import (
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (r request) normalizeInventory(local *cliInventory) (protocol.OriginInventoryReport, error) {
	if local == nil || r.inventory == nil || len(local.Entries) > r.inventory.Limit {
		return protocol.OriginInventoryReport{}, ErrEvidence
	}
	wire := protocol.OriginInventoryReport{Entries: make([]protocol.OriginInventoryEntry, 0, len(local.Entries)), NextCursor: local.NextCursor, Complete: local.Complete, MembershipSHA256: local.MembershipSHA256, CompletenessReceipt: local.CompletenessReceipt}
	for _, entry := range local.Entries {
		normalized, entryErr := r.normalizeInventoryEntry(entry)
		if entryErr != nil {
			return protocol.OriginInventoryReport{}, entryErr
		}
		wire.Entries = append(wire.Entries, normalized)
	}
	if wire.ValidateFor(*r.inventory) != nil {
		return protocol.OriginInventoryReport{}, ErrEvidence
	}
	return wire, nil
}

func (r request) normalizeInventoryEntry(local inventoryEntry) (protocol.OriginInventoryEntry, error) {
	wire := protocol.OriginInventoryEntry{TaskID: local.TaskID, Resolution: local.Resolution, SpecSHA256: local.SpecSHA256, BriefSHA256: local.BriefSHA256}
	if local.Origin != nil {
		origin := *local.Origin
		wire.Origin = &origin
	}
	if local.Receipt != nil {
		receipt := local.Receipt
		if receipt.RootToken != r.project.RootToken || !r.validInventoryProject(receipt) {
			return protocol.OriginInventoryEntry{}, ErrEvidence
		}
		wire.Receipt = &protocol.InventoryReceipt{
			Task:             protocol.TaskBinding{TaskID: receipt.TaskID, Context: protocol.ContextBinding{Root: protocol.WireContextGuard(receipt.RootToken), Project: protocol.WireContextGuard(receipt.ProjectToken)}, Origin: receipt.Origin, SpecSHA256: receipt.SpecSHA256},
			ExecutionOptions: protocol.InventoryExecutionOptions(receipt.ExecutionOptions), BriefSHA256: receipt.BriefSHA256,
		}
	}
	if wire.Validate() != nil {
		return protocol.OriginInventoryEntry{}, ErrEvidence
	}
	return wire, nil
}

func (r request) validInventoryProject(receipt *cliReceipt) bool {
	if r.config.ProjectStore == nil {
		return len(receipt.ProjectToken) > 0 && len(receipt.ProjectToken) <= 4096 && !strings.ContainsAny(receipt.ProjectToken, "\x00\r\n") && receipt.WorkspaceConstraint == nil
	}
	if !validNativeProjectToken(receipt.ProjectToken) {
		return false
	}
	constraint := receipt.WorkspaceConstraint
	return constraint == nil || (validNativeProjectToken(constraint.Token) && protocol.ValidRelativeProject(constraint.RelativeProject))
}
