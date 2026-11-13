package connector

import (
	"context"
	"slices"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (a *Adapter) WorkspaceMode() bool { return a.snapshot().ProjectStore != nil }

func (a *Adapter) observeRoot(generation uint64, report protocol.RootCapability) {
	if report.Validate() != nil || !slices.Contains(report.Features, protocol.WorkspaceFeature) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.generation != generation || a.config.ProjectStore == nil {
		return
	}
	copy := report
	copy.Features = append([]string(nil), report.Features...)
	if report.Origin != nil {
		origin := *report.Origin
		copy.Origin = &origin
	}
	a.root, a.rootObserved, a.probed = &copy, a.now(), true
}

// ProbeWorkspaces inspects the selected Native root once. Periodic metadata
// reports below never launch Native, inspect directories or query providers.
func (a *Adapter) ProbeWorkspaces(ctx context.Context) error {
	cfg := a.snapshot()
	if cfg.ProjectStore == nil {
		return ErrConfiguration
	}
	state, err := cfg.ProjectStore.Snapshot(ctx)
	if err != nil {
		return err
	}
	body, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(cfg.GatewayID), RootOnly: true}, protocol.MaxFrameBytes)
	if err != nil {
		return ErrEvidence
	}
	reply := a.execute(ctx, protocol.Command{Operation: protocol.ContextInspect, Root: protocol.WireContextGuard(state.RootContext), Body: body}, acceptance{generation: cfg.generation})
	if reply.Error != nil {
		return ErrConfiguration
	}
	a.mu.RLock()
	valid := a.root != nil
	a.mu.RUnlock()
	if !valid {
		return ErrConfiguration
	}
	return nil
}

func (a *Adapter) CapabilitiesV2(ctx context.Context) (protocol.CapabilityReportV2, error) {
	cfg := a.snapshot()
	if cfg.ProjectStore == nil {
		return protocol.CapabilityReportV2{}, ErrConfiguration
	}
	state, err := cfg.ProjectStore.Snapshot(ctx)
	if err != nil {
		return protocol.CapabilityReportV2{}, err
	}
	a.mu.RLock()
	report := protocol.CapabilityReportV2{ObservedAt: a.rootObserved, Root: a.root, ProjectBudget: &state.ProjectBudget}
	a.mu.RUnlock()
	if report.ObservedAt.IsZero() {
		report.ObservedAt = a.now()
	}
	if report.Root != nil {
		copy := *report.Root
		copy.Features = append([]string(nil), copy.Features...)
		if copy.Origin != nil {
			origin := *copy.Origin
			copy.Origin = &origin
		}
		report.Root = &copy
		if copy.Root != protocol.WireContextGuard(state.RootContext) {
			return protocol.CapabilityReportV2{}, ErrConflict
		}
		for _, workspace := range state.Workspaces {
			if workspace.Enabled {
				report.Workspaces = append(report.Workspaces, protocol.WorkspaceCapability{WorkspaceBinding: protocol.WorkspaceBinding{ID: workspace.ID, Guard: protocol.WireContextGuard(workspace.NativeContext)}, Name: workspace.Alias, PolicyRevision: workspace.Revision})
			}
		}
	}
	if report.Validate() != nil {
		return protocol.CapabilityReportV2{}, ErrEvidence
	}
	return report, nil
}
