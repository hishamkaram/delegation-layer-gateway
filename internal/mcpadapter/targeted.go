package mcpadapter

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
)

func (a *Adapter) targetedCapabilities(ctx context.Context, actor domain.Actor, destination domain.Destination) (Capabilities, error) {
	observation, err := a.options.Workspaces.InspectProject(ctx, actor, destination, domain.InventoryRead)
	if err != nil {
		return Capabilities{}, err
	}
	if observation.Capability.Validate() != nil || observation.Capability.Project.Handle != string(destination.Project) || observation.Credential.Device != destination.Device || observation.Credential.Validate() != nil || observation.Connection.Validate() != nil || observation.ObservedAt.IsZero() {
		return Capabilities{}, domain.Reject(domain.EvidenceInvalid)
	}
	// The live query can outlast a policy change. Project the current grant only
	// after the reply; the backend separately rechecks before every send/response.
	authorization, err := a.options.Registry.Authorize(ctx, domain.AuthorizationRequest{Actor: actor, Destination: destination, Scope: domain.InventoryRead})
	if err != nil {
		return Capabilities{}, err
	}
	capability := observation.Capability.Capability
	result := Capabilities{DeviceID: string(destination.Device), ProjectAlias: string(destination.Project), Online: true, DelegateReady: capability.Ready, ExecutionReadiness: "not_ready", ObservedAt: &observation.ObservedAt, Providers: []Provider{}}
	result.TaskReadAllowed = actor.Scopes.Has(domain.TaskRead) && authorization.Grant.Scopes.Has(domain.TaskRead)
	result.TaskCancelAllowed = actor.Scopes.Has(domain.TaskCancel) && authorization.Grant.Scopes.Has(domain.TaskCancel)
	result.Workspace = &observation.Capability.Project.Workspace
	result.CurrentPolicyRevision = &observation.Capability.CurrentPolicyRevision
	snapshot := gateway.LinkSnapshot{Credential: observation.Credential, Connection: observation.Connection, ObservedAt: observation.ObservedAt}
	result.ExecutionReadiness, err = a.projectExecutionReadiness(ctx, actor, destination, snapshot, capability)
	if err != nil {
		return Capabilities{}, err
	}
	for _, provider := range capability.Providers {
		result.Providers = append(result.Providers, publicProvider(provider, actor, authorization.Grant))
	}
	return result, nil
}
