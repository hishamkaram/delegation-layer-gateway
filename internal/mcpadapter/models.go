package mcpadapter

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type ModelsInput struct {
	DeviceID  string                 `json:"device_id"`
	Selection protocol.FileSelection `json:"selection"`
	Provider  string                 `json:"provider"`
	Cursor    string                 `json:"cursor,omitempty"`
	Limit     int                    `json:"limit,omitempty"`
}

type modelTools interface {
	ObserveModels(context.Context, domain.Actor, domain.DeviceID, protocol.ModelQuery) (gateway.MetadataObservation[protocol.ModelPage], error)
	metadataChecker
}

type modelsOutput struct {
	protocol.ModelPage
	source gateway.MetadataSource
}

func (o modelsOutput) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	tools, ok := a.options.Workspaces.(modelTools)
	if !ok {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return tools.CheckMetadataObservation(ctx, actor, o.source, nil)
}

func (a *Adapter) registerModelTools() error {
	if _, ok := a.options.Workspaces.(modelTools); !ok {
		return nil
	}
	return register(a, "list_models", "Explicitly discover one page of dated Native model and effort advice for an explicit device, selection and provider. Native discovery may probe and record an inspection, but creates no task. Follow next_cursor; a partial/blocked catalog is not an execution restriction. Explicit models absent from discovery may still be requested from Native.", []domain.Scope{domain.TaskDispatch}, toolHints{Idempotent: true}, a.models)
}

func (i ModelsInput) query() protocol.ModelQuery {
	return protocol.ModelQuery{Selection: i.Selection, Provider: i.Provider, Cursor: i.Cursor, Limit: i.Limit}
}

func (a *Adapter) models(ctx context.Context, actor domain.Actor, input ModelsInput) (modelsOutput, error) {
	query := input.query()
	if domain.CredentialToken(input.DeviceID) != nil || query.Validate() != nil {
		return modelsOutput{}, domain.ErrInvalid
	}
	if err := input.responseAuthority(ctx, a, actor); err != nil {
		return modelsOutput{}, err
	}
	tools, ok := a.options.Workspaces.(modelTools)
	if !ok {
		return modelsOutput{}, domain.ErrInvalid
	}
	observed, err := tools.ObserveModels(ctx, actor, domain.DeviceID(input.DeviceID), query)
	if err != nil {
		return modelsOutput{}, err
	}
	if observed.Value.ValidateFor(query) != nil || !metadataSourceMatches(observed.Source, domain.DeviceID(input.DeviceID), protocol.ProviderModels) {
		return modelsOutput{}, domain.Reject(domain.EvidenceInvalid)
	}
	return modelsOutput{ModelPage: observed.Value, source: observed.Source}, nil
}

func (i ModelsInput) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	_, err := a.options.Registry.AuthorizeOwnedDevice(ctx, domain.OwnedDeviceRequest{Actor: actor, Device: domain.DeviceID(i.DeviceID), Scope: domain.TaskDispatch})
	return err
}
