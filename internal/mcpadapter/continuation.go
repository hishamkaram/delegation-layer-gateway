package mcpadapter

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// ContinuationOverridesInput contains only literal Native continuation choices.
// Empty values inherit; Native owns validation of supported option semantics.
type ContinuationOverridesInput struct {
	Budget               string `json:"budget,omitempty"`
	Model                string `json:"model,omitempty"`
	Effort               string `json:"effort,omitempty"`
	OutputSilenceTimeout string `json:"output_silence_timeout,omitempty" jsonschema:"Omit to inherit; use 0 to explicitly disable the output silence timeout."`
}

func (i ContinuationOverridesInput) options() domain.ContinuationOverrides {
	return domain.ContinuationOverrides{Version: 1, Budget: i.Budget, Model: i.Model, Effort: i.Effort, OutputSilenceTimeout: i.OutputSilenceTimeout}
}

type PrepareContinuationInput struct {
	DeviceID               string                     `json:"device_id"`
	PredecessorOperationID string                     `json:"predecessor_operation_id" jsonschema:"Saved operation handle to continue on the explicit device. Does not grant task or result read access."`
	RequestID              string                     `json:"request_id" jsonschema:"Stable 32-character lowercase hex preparation ID. Reuse it with the identical input after uncertainty."`
	Selection              *protocol.FileSelection    `json:"selection,omitempty" jsonschema:"Omit to reuse the predecessor's captured selection. An explicit selection must still identify the same saved project."`
	Brief                  *string                    `json:"brief,omitempty" jsonschema:"Omit to inherit Native's saved brief bytes; otherwise supply a UTF-8 brief up to 256 KiB."`
	Overrides              ContinuationOverridesInput `json:"overrides,omitempty" jsonschema:"Omitted values inherit the predecessor's Native execution options."`
}

type continuationOperations interface {
	PrepareContinuation(context.Context, domain.Actor, gateway.ContinuationPreparation) (domain.PreparedOperation, error)
}

func (a *Adapter) prepareContinuation(ctx context.Context, actor domain.Actor, input PrepareContinuationInput) (Prepared, error) {
	if !input.valid() {
		return Prepared{}, domain.ErrInvalid
	}
	operations, ok := a.options.Operations.(continuationOperations)
	if !ok {
		return Prepared{}, &gateway.RemoteError{Failure: protocol.Failure{Code: "unsupported_feature"}}
	}
	prepared, err := operations.PrepareContinuation(ctx, actor, gateway.ContinuationPreparation{RequestID: domain.RequestID(input.RequestID), Device: domain.DeviceID(input.DeviceID), Predecessor: domain.OperationID(input.PredecessorOperationID), Selection: input.Selection, Overrides: input.Overrides.options(), Brief: input.Brief})
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{OperationID: string(prepared.Correlation.Operation), TaskID: string(prepared.Correlation.Task), ExpiresAt: prepared.ExpiresAt}, nil
}

func (i PrepareContinuationInput) valid() bool {
	if domain.TaskID(i.RequestID).Validate() != nil || domain.CredentialToken(i.DeviceID) != nil || domain.Token(i.PredecessorOperationID) != nil {
		return false
	}
	request := domain.FrozenRequest{Continuation: i.Overrides.options(), BriefPresent: i.Brief != nil, SelectionExplicit: i.Selection != nil}
	if i.Brief != nil {
		request.Brief = *i.Brief
	}
	return request.Validate() == nil && (i.Selection == nil || (protocol.SelectionRequest{Selection: *i.Selection}).Validate() == nil)
}

func (i PrepareContinuationInput) retainedRequestID() string {
	if !i.valid() {
		return ""
	}
	return i.RequestID
}
