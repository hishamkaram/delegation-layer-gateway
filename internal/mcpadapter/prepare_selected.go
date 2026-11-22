package mcpadapter

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// NativeOptionsInput preserves omission. Supported combinations and defaults
// come from Delegate, never an independent Gateway policy or cached catalog.
type NativeOptionsInput struct {
	Provider             string  `json:"provider"`
	Model                *string `json:"model,omitempty"`
	Effort               *string `json:"effort,omitempty"`
	Permission           string  `json:"permission,omitempty"`
	Budget               string  `json:"budget,omitempty"`
	ReviewTarget         string  `json:"review_target,omitempty"`
	NativeTimeout        string  `json:"native_timeout,omitempty"`
	OutputSilenceTimeout string  `json:"output_silence_timeout,omitempty"`
}

func (i NativeOptionsInput) options() domain.NativeOptions {
	return domain.NativeOptions{Version: 1, Provider: domain.ProviderID(i.Provider), Model: selection(i.Model), Effort: selection(i.Effort), Permission: i.Permission, Budget: i.Budget, ReviewTarget: i.ReviewTarget, NativeTimeout: i.NativeTimeout, OutputSilenceTimeout: i.OutputSilenceTimeout}
}

type selectedOperations interface {
	PrepareSelected(context.Context, domain.Actor, gateway.SelectedPreparation) (domain.PreparedOperation, error)
}

func (a *Adapter) prepareSelected(ctx context.Context, actor domain.Actor, input PrepareInput) (Prepared, error) {
	if !input.validSelectedPreparation() {
		return Prepared{}, domain.ErrInvalid
	}
	operations, ok := a.options.Operations.(selectedOperations)
	if !ok {
		return Prepared{}, &gateway.RemoteError{Failure: protocol.Failure{Code: "unsupported_feature"}}
	}
	prepared, err := operations.PrepareSelected(ctx, actor, gateway.SelectedPreparation{RequestID: domain.RequestID(input.RequestID), Device: domain.DeviceID(input.DeviceID), Selection: *input.Selection, Request: domain.FrozenRequest{Brief: input.Brief, Native: input.NativeOptions.options()}})
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{OperationID: string(prepared.Correlation.Operation), TaskID: string(prepared.Correlation.Task), ExpiresAt: prepared.ExpiresAt}, nil
}

func (i PrepareInput) validSelectedPreparation() bool {
	if i.Selection == nil || i.NativeOptions == nil || domain.TaskID(i.RequestID).Validate() != nil || domain.CredentialToken(i.DeviceID) != nil || i.ProjectAlias != "" || i.Provider != "" || i.Permission != "" || i.BudgetSeconds != 0 || i.Model != nil || i.Effort != nil {
		return false
	}
	request := protocol.SelectionRequest{Selection: *i.Selection}
	return request.Validate() == nil
}

func (i PrepareInput) retainedRequestID() string {
	if !i.validSelectedPreparation() {
		return ""
	}
	return i.RequestID
}
