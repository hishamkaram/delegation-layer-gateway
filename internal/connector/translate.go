package connector

import (
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// A taskless absent/refusal response proves only the guarded root/task scope.
// Project attestation requires the matching frozen receipt below.
func (r request) rootTaskProof(response cliResponse) bool {
	c := response.Connector
	return c != nil && c.ContractVersion == 1 && protocol.NativeFeaturesCompatible(c.Features) && c.RootToken == r.project.RootToken && response.TaskID == r.task.TaskID
}

func (r request) receipt(response cliResponse) error {
	if !r.rootTaskProof(response) || response.Connector.ProjectToken != r.project.ProjectToken {
		return ErrEvidence
	}
	c := response.Connector
	if c.Receipt == nil {
		if c.Resolution == "existing" {
			return ErrEvidence
		}
		return nil
	}
	if !r.receiptBinding(c.Receipt) || !validReceiptOptions(c.Receipt) {
		return ErrEvidence
	}
	if r.admission != nil && (c.Receipt.ExecutionOptions != admissionOptions(*r.admission) || c.Receipt.BriefSHA256 != briefHash(r.admission.Brief)) {
		return ErrEvidence
	}
	return nil
}

func (r request) receiptBinding(receipt *cliReceipt) bool {
	if receipt.RootToken != r.project.RootToken || receipt.ProjectToken != r.project.ProjectToken || receipt.TaskID != r.task.TaskID || receipt.Origin != r.task.Origin {
		return false
	}
	if r.task.SpecSHA256 != "" && receipt.SpecSHA256 != r.task.SpecSHA256 {
		return false
	}
	bound := r.task
	bound.SpecSHA256 = receipt.SpecSHA256
	return bound.Validate(true) == nil
}

func validReceiptOptions(receipt *cliReceipt) bool {
	options := receipt.ExecutionOptions
	return digest(receipt.BriefSHA256) && options.Provider != "" && options.BudgetNanoseconds > 0 && options.Model.Validate() == nil && options.Effort.Validate() == nil && domain.Permission(options.Permission).Validate() == nil
}

func (r request) translate(response cliResponse) protocol.Reply {
	if r.command.Operation.Administrative() {
		return r.translateOrigin(response)
	}
	if err := r.receipt(response); err != nil {
		return failed(r.command.Operation, err)
	}
	if r.rangeRequest != nil {
		return r.translateRange(response)
	}
	c := response.Connector
	observation := protocol.TaskObservation{Task: r.task, Resolution: c.Resolution, Admission: response.Admission, Liveness: response.Liveness, Publication: response.Publication, ExecutionClosure: c.ExecutionClosure, ExecutionClosurePending: c.ExecutionClosurePending}
	if c.Receipt != nil {
		observation.Task.SpecSHA256 = c.Receipt.SpecSHA256
		observation.BriefSHA256 = c.Receipt.BriefSHA256
	}
	if err := r.outcome(response, &observation); err != nil {
		return failed(r.command.Operation, err)
	}
	if response.Stop != nil && response.Stop.Matched {
		stop := response.Stop
		if r.cancellation != nil && stop.RequestID != r.cancellation.CancellationID {
			return failed(r.command.Operation, ErrEvidence)
		}
		observation.Stop = &protocol.StopObservation{RequestID: stop.RequestID, Requested: stop.Requested, Terminated: stop.Terminated}
	}
	if observation.Validate() != nil {
		return failed(r.command.Operation, ErrEvidence)
	}
	return bodyReply(r.command.Operation, observation)
}

func (r request) outcome(response cliResponse, observation *protocol.TaskObservation) error {
	if response.Outcome == nil {
		return nil
	}
	outcome := response.Outcome
	if outcome.SchemaVersion != 1 || outcome.TaskID != r.task.TaskID || outcome.SpecSHA256 != observation.Task.SpecSHA256 || outcome.Verdict != response.Publication {
		return ErrEvidence
	}
	observation.Verdict = outcome.Verdict
	if outcome.Verdict == "committed" {
		if outcome.Payload.Basename != "result.txt" {
			return ErrEvidence
		}
		descriptor := protocol.Descriptor{SHA256: outcome.Payload.SHA256, Length: outcome.Payload.Length}
		if descriptor.Validate() != nil {
			return ErrEvidence
		}
		if response.Payload != nil && *response.Payload != outcome.Payload {
			return ErrEvidence
		}
		observation.Result = &descriptor
	}
	return nil
}

func (r request) translateRange(response cliResponse) protocol.Reply {
	value := response.Connector.ResultRange
	if value == nil || value.Descriptor.Basename != "result.txt" || response.Publication != "committed" {
		return failed(r.command.Operation, ErrEvidence)
	}
	result := protocol.ResultRange{Descriptor: protocol.Descriptor{SHA256: value.Descriptor.SHA256, Length: value.Descriptor.Length}, Offset: value.Offset, DataBase64: value.DataBase64, NextOffset: value.NextOffset, EOF: value.EOF}
	if result.ValidateFor(*r.rangeRequest) != nil {
		return failed(r.command.Operation, ErrEvidence)
	}
	return bodyReply(r.command.Operation, result)
}

func (r request) translateOrigin(response cliResponse) protocol.Reply {
	c := response.Connector
	if c == nil || c.ContractVersion != 1 || c.RootToken != r.project.RootToken || !protocol.NativeFeaturesCompatible(c.Features) {
		return failed(r.command.Operation, ErrEvidence)
	}
	if r.inventory != nil {
		inventory, inventoryErr := r.normalizeInventory(c.Inventory)
		if inventoryErr != nil {
			return failed(r.command.Operation, inventoryErr)
		}
		return bodyReply(r.command.Operation, inventory)
	}
	state := c.OriginBarrier
	if !r.originStateValid(state) {
		return failed(r.command.Operation, ErrEvidence)
	}
	return bodyReply(r.command.Operation, protocol.OriginStateReport{GatewayID: state.GatewayID, RecoveryID: state.RecoveryID, Generation: state.Generation, AdmissionOpen: state.AdmissionOpen})
}

func (r request) originStateValid(state *cliOriginState) bool {
	if state == nil || state.GatewayID != string(r.config.GatewayID) || !wireIdentifier(state.RecoveryID) || !wireIdentifier(state.Generation) {
		return false
	}
	if r.barrier != nil && (state.Generation != r.barrier.Generation || state.RecoveryID != r.barrier.RecoveryID || state.AdmissionOpen) {
		return false
	}
	if r.reopen != nil && (state.Generation != r.reopen.Generation || state.RecoveryID != r.reopen.RecoveryID || !state.AdmissionOpen) {
		return false
	}
	return true
}

func digest(value string) bool {
	return (protocol.Descriptor{SHA256: value, Length: 0}).Validate() == nil
}

func (r request) rootReport(response cliResponse) (protocol.RootCapability, error) {
	c := response.Connector
	if c == nil || c.RootToken != r.project.RootToken || c.ProjectToken != "" || c.OriginRegistered == nil {
		return protocol.RootCapability{}, ErrEvidence
	}
	result := protocol.RootCapability{Root: protocol.WireContextGuard(c.RootToken), ContractVersion: c.ContractVersion, Features: protocol.RecognizedNativeFeatures(c.Features), OriginRegistered: *c.OriginRegistered}
	if state := c.OriginBarrier; state != nil {
		if state.GatewayID != string(r.config.GatewayID) {
			return protocol.RootCapability{}, ErrEvidence
		}
		result.Origin = &protocol.OriginStateReport{GatewayID: state.GatewayID, RecoveryID: state.RecoveryID, Generation: state.Generation, AdmissionOpen: state.AdmissionOpen}
	}
	if result.Validate() != nil {
		return protocol.RootCapability{}, ErrEvidence
	}
	return result, nil
}
