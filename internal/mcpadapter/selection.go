package mcpadapter

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type selectionTools interface {
	ObserveSelection(context.Context, domain.Actor, domain.DeviceID, protocol.SelectionRequest) (gateway.MetadataObservation[protocol.SelectionObservation], error)
	metadataChecker
}

func (a *Adapter) selectedCapabilities(ctx context.Context, actor domain.Actor, input CapabilitiesInput) (Capabilities, error) {
	if input.ProjectAlias != "" || input.Selection == nil {
		return Capabilities{}, domain.ErrInvalid
	}
	request := protocol.SelectionRequest{Selection: *input.Selection}
	if request.Validate() != nil {
		return Capabilities{}, domain.ErrInvalid
	}
	device := domain.DeviceID(input.DeviceID)
	authority, err := a.options.Registry.AuthorizeOwnedDevice(ctx, domain.OwnedDeviceRequest{Actor: actor, Device: device, Scope: domain.InventoryRead})
	if err != nil {
		return Capabilities{}, err
	}
	tools, ok := a.options.Workspaces.(selectionTools)
	if !ok {
		return Capabilities{}, domain.Reject(domain.Invalid)
	}
	observation, err := tools.ObserveSelection(ctx, actor, device, request)
	if err != nil {
		return Capabilities{}, err
	}
	observed := observation.Value
	if observed.ValidateFor(request) != nil || !metadataSourceMatches(observation.Source, device, protocol.SelectProject) || observed.Context.Root != string(observation.Source.Binding.Route.Root) {
		return Capabilities{}, domain.Reject(domain.EvidenceInvalid)
	}
	// Recheck current authority after the Native read, before returning names.
	authority, err = a.options.Registry.AuthorizeOwnedDevice(ctx, domain.OwnedDeviceRequest{Actor: actor, Device: device, Scope: domain.InventoryRead})
	if err != nil {
		return Capabilities{}, err
	}
	result := Capabilities{DeviceID: input.DeviceID, Selection: input.Selection, TaskReadAllowed: actor.Scopes.Has(domain.TaskRead) && authority.Policy.Scopes.Has(domain.TaskRead), TaskCancelAllowed: actor.Scopes.Has(domain.TaskCancel) && authority.Policy.Scopes.Has(domain.TaskCancel), Online: true, DelegateReady: true, ExecutionReadiness: "unknown", ObservedAt: &observed.ObservedAt, AdmissionOpen: observed.AdmissionOpen, Providers: []Provider{}}
	result.metadataSource = &observation.Source
	for _, provider := range observed.Providers {
		result.Providers = append(result.Providers, Provider{Provider: provider.Provider, Models: []string{}, Efforts: []string{}, Authentication: provider.Authentication, Permissions: []string{}, SupportedModes: append([]string{}, provider.SupportedModes...), SupportedOptions: append([]string{}, provider.SupportedOptions...), RequiredOptions: append([]string{}, provider.RequiredOptions...), Continuation: provider.Continuation, DispatchAllowed: actor.Scopes.Has(domain.TaskDispatch) && authority.Policy.Scopes.Has(domain.TaskDispatch)})
	}
	return result, nil
}

func (o Capabilities) responseAuthority(ctx context.Context, a *Adapter, actor domain.Actor) error {
	if o.Selection == nil {
		return nil // Legacy capability reports remain dated observations.
	}
	if o.metadataSource == nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	tools, ok := a.options.Workspaces.(selectionTools)
	if !ok {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return tools.CheckMetadataObservation(ctx, actor, *o.metadataSource, domain.ScopeSet{domain.InventoryRead})
}
