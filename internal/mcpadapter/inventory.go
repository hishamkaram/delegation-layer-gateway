package mcpadapter

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (a *Adapter) devices(ctx context.Context, actor domain.Actor, input PageInput) (DevicePage, error) {
	page, err := a.options.Registry.ListDevices(ctx, actor, domain.DevicePageRequest{After: domain.DeviceID(input.Cursor), Limit: input.Limit})
	if err != nil {
		return DevicePage{}, err
	}
	result := DevicePage{Devices: make([]Device, 0, len(page.Items)), NextCursor: string(page.Next)}
	for _, device := range page.Items {
		entry, entryErr := a.device(ctx, actor, device)
		if entryErr != nil {
			return DevicePage{}, entryErr
		}
		result.Devices = append(result.Devices, entry)
	}
	return result, nil
}

func (a *Adapter) device(ctx context.Context, actor domain.Actor, device domain.Device) (Device, error) {
	result := Device{DeviceID: string(device.ID), Name: device.Name, ExecutionReadiness: "not_ready"}
	snapshot, online, err := a.snapshot(device.ID)
	if err != nil || !online {
		return result, err
	}
	result.Online = true
	if !snapshot.ObservedAt.IsZero() {
		result.ObservedAt = &snapshot.ObservedAt
	}
	// Device-level readiness must not reveal a hidden project's capabilities.
	// Authorize the bounded advertised set, rather than assuming the first
	// registry page contains every advertised alias.
	for _, capability := range snapshot.Capabilities.Projects {
		delegateReady, readiness, readinessErr := a.deviceCapability(ctx, actor, device.ID, snapshot, capability)
		if readinessErr != nil {
			return result, readinessErr
		}
		result.DelegateReady = result.DelegateReady || delegateReady
		if readiness == "ready" {
			result.ExecutionReadiness = readiness
			break
		}
		if readiness == "unknown" {
			result.ExecutionReadiness = readiness
		}
	}

	return result, nil
}

func (a *Adapter) projects(ctx context.Context, actor domain.Actor, input ProjectsInput) (ProjectPage, error) {
	page, err := a.options.Registry.ListProjects(ctx, actor, domain.DeviceID(input.DeviceID), domain.ProjectPageRequest{After: domain.ProjectAlias(input.Cursor), Limit: input.Limit})
	if err != nil {
		return ProjectPage{}, err
	}
	snapshot, online, err := a.snapshot(domain.DeviceID(input.DeviceID))
	if err != nil {
		return ProjectPage{}, err
	}
	result := ProjectPage{Projects: make([]Project, 0, len(page.Items)), NextCursor: string(page.Next)}
	for _, project := range page.Items {
		entry, entryErr := a.projectSummary(ctx, actor, project, snapshot, online)
		if entryErr != nil {
			return ProjectPage{}, entryErr
		}
		result.Projects = append(result.Projects, entry)
	}

	return result, nil
}

func (a *Adapter) capabilities(ctx context.Context, actor domain.Actor, input CapabilitiesInput) (Capabilities, error) {
	destination := domain.Destination{Device: domain.DeviceID(input.DeviceID), Project: domain.ProjectAlias(input.ProjectAlias)}
	authorization, err := a.options.Registry.Authorize(ctx, domain.AuthorizationRequest{Actor: actor, Destination: destination, Scope: domain.InventoryRead})
	if err != nil {
		return Capabilities{}, err
	}
	result := Capabilities{DeviceID: input.DeviceID, ProjectAlias: input.ProjectAlias, ExecutionReadiness: "not_ready", Providers: []Provider{}}
	snapshot, online, err := a.snapshot(destination.Device)
	if err != nil || !online {
		return result, err
	}
	result.Online = true
	if !snapshot.ObservedAt.IsZero() {
		result.ObservedAt = &snapshot.ObservedAt
	}
	capability, found := findProject(snapshot, destination.Project)
	if !found {
		return result, nil
	}
	result.DelegateReady = capability.Ready
	result.ExecutionReadiness, err = a.projectExecutionReadiness(ctx, actor, destination, snapshot, capability)
	if err != nil {
		return Capabilities{}, err
	}
	for _, provider := range capability.Providers {
		result.Providers = append(result.Providers, publicProvider(provider, actor, authorization.Grant))
	}
	return result, nil
}

func (a *Adapter) snapshot(device domain.DeviceID) (gateway.LinkSnapshot, bool, error) {
	snapshot, err := a.options.Presence.Snapshot(device)
	if err != nil {
		var failure *gateway.RemoteError
		if errors.As(err, &failure) && failure.Failure.Code == "device_offline" {
			return gateway.LinkSnapshot{}, false, nil
		}
		return snapshot, false, err
	}
	if snapshot.Credential.Device != device || snapshot.Credential.Validate() != nil || snapshot.Connection.Validate() != nil {
		return snapshot, false, domain.Reject(domain.EvidenceInvalid)
	}
	if snapshot.Capabilities.ObservedAt.IsZero() && len(snapshot.Capabilities.Projects) == 0 {
		return snapshot, true, nil
	}
	if snapshot.ObservedAt.IsZero() || snapshot.Capabilities.Validate() != nil {
		return snapshot, false, domain.Reject(domain.EvidenceInvalid)
	}
	return snapshot, true, nil
}

func visibilityDenied(err error) bool {
	var failure *domain.Error
	return errors.As(err, &failure) && (failure.Code == domain.Forbidden || failure.Code == domain.NotFound)
}

func findProject(snapshot gateway.LinkSnapshot, alias domain.ProjectAlias) (protocol.ProjectCapability, bool) {
	for _, project := range snapshot.Capabilities.Projects {
		if project.Alias == string(alias) {
			return project, true
		}
	}
	return protocol.ProjectCapability{}, false
}

func executionReadiness(project protocol.ProjectCapability) string {
	if !project.Ready {
		return "not_ready"
	}
	unknown := false
	for _, provider := range project.Providers {
		if provider.Authentication == "verified" {
			return "ready"
		}
		if provider.Authentication == "unknown" {
			unknown = true
		}
	}
	if unknown {
		return "unknown"
	}
	return "not_ready"
}

// Delegate readiness is a dated capability. Registry independently decides
// whether this exact authenticated route and generation may execute now.
func (a *Adapter) projectExecutionReadiness(ctx context.Context, actor domain.Actor, destination domain.Destination, snapshot gateway.LinkSnapshot, capability protocol.ProjectCapability) (string, error) {
	if !capability.Ready {
		return "not_ready", nil
	}
	ready, err := a.options.Registry.CheckProjectReadiness(ctx, domain.ProjectReadinessRequest{Actor: actor, Destination: destination, Context: domain.ContextBinding{Root: domain.RootGuard(capability.Context.Root), Project: domain.ProjectGuard(capability.Context.Project)}, Generation: domain.AdmissionGeneration(capability.AdmissionGeneration), Credential: snapshot.Credential, Connection: snapshot.Connection, Now: a.options.Now()})
	if err != nil || !ready {
		return "not_ready", err
	}
	return executionReadiness(capability), nil
}

func publicProvider(provider protocol.ProviderCapability, actor domain.Actor, grant domain.Grant) Provider {
	result := Provider{Provider: provider.Provider, Models: append([]string{}, provider.Models...), Efforts: append([]string{}, provider.Efforts...), Authentication: provider.Authentication, Permissions: []string{}}
	if !actor.Scopes.Has(domain.TaskDispatch) || !grant.Scopes.Has(domain.TaskDispatch) {
		return result
	}
	allowed := false
	for _, id := range grant.Ceiling.Providers {
		if string(id) == provider.Provider {
			allowed = true
			break
		}
	}
	if !allowed {
		return result
	}
	for _, permission := range provider.Permissions {
		for _, allowedPermission := range grant.Ceiling.Permissions {
			if permission == string(allowedPermission) {
				result.Permissions = append(result.Permissions, permission)
				break
			}
		}
	}
	if len(result.Permissions) == 0 {
		return result
	}
	result.MaxBudgetSeconds = min(provider.MaxBudgetSeconds, grant.Ceiling.MaxBudgetSeconds)
	result.DispatchAllowed = result.MaxBudgetSeconds > 0
	return result
}

func (a *Adapter) deviceCapability(ctx context.Context, actor domain.Actor, device domain.DeviceID, snapshot gateway.LinkSnapshot, capability protocol.ProjectCapability) (bool, string, error) {
	destination := domain.Destination{Device: device, Project: domain.ProjectAlias(capability.Alias)}
	if _, err := a.options.Registry.Authorize(ctx, domain.AuthorizationRequest{Actor: actor, Destination: destination, Scope: domain.InventoryRead}); err != nil {
		if visibilityDenied(err) {
			return false, "not_ready", nil
		}
		return false, "not_ready", err
	}
	readiness, err := a.projectExecutionReadiness(ctx, actor, destination, snapshot, capability)
	return capability.Ready, readiness, err
}

func (a *Adapter) projectSummary(ctx context.Context, actor domain.Actor, project domain.ProjectRegistration, snapshot gateway.LinkSnapshot, online bool) (Project, error) {
	entry := Project{Alias: string(project.Destination.Project), Online: online, ExecutionReadiness: "not_ready"}
	if !online {
		return entry, nil
	}
	if !snapshot.ObservedAt.IsZero() {
		entry.ObservedAt = &snapshot.ObservedAt
	}
	capability, found := findProject(snapshot, project.Destination.Project)
	if !found {
		return entry, nil
	}
	entry.DelegateReady = capability.Ready
	readiness, err := a.projectExecutionReadiness(ctx, actor, project.Destination, snapshot, capability)
	entry.ExecutionReadiness = readiness
	return entry, err
}
