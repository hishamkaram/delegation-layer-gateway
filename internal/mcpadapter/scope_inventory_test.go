package mcpadapter

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type scopeInventoryBackend struct {
	workspaceBackend
	scopes         []protocol.FilesystemScope
	discoveryError string
}

func (b *scopeInventoryBackend) ObserveWorkspaces(ctx context.Context, actor domain.Actor, device domain.DeviceID) (workspaces.InventoryObservation, error) {
	value, err := b.ListWorkspaces(ctx, actor, device)
	result := workspaces.InventoryObservation{Value: value}
	if b.discoveryError == "" {
		source := testMetadataSource(device, protocol.FilesystemScopes)
		result.Source = &source
	}
	return result, err
}

func (b *scopeInventoryBackend) ListWorkspaces(_ context.Context, _ domain.Actor, device domain.DeviceID) (workspaces.Inventory, error) {
	return workspaces.Inventory{Device: device, Online: true, DelegateReady: true, Scopes: b.scopes, ScopeDiscoveryError: b.discoveryError, Workspaces: []protocol.WorkspaceCapability{}, ObservedAt: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}, nil
}

func TestWorkspaceInventoryPreservesAutomaticScopesAndExplicitTempFailure(t *testing.T) {
	for _, discoveryError := range []string{"", "temp_unavailable", "resource_limit", "scope_discovery_failed"} {
		backend := &scopeInventoryBackend{scopes: []protocol.FilesystemScope{{ID: "code", Kind: "workspace", Name: "Approved code"}}}
		if discoveryError != "" {
			backend.discoveryError = discoveryError
		} else {
			backend.scopes = append(backend.scopes, protocol.FilesystemScope{ID: protocol.SharedTempScope, Kind: "shared_temp", Name: "Shared temporary directory"}, protocol.FilesystemScope{ID: protocol.UserTempScope, Kind: "user_temp", Name: "User temporary directory"})
		}
		f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Workspaces = backend })
		backend.metadataRegistry = f.store
		device := ownedFilesystemDevice(t, f)
		result := decodeResult[WorkspaceInventory](t, f.call(t, f.session(t, "inventory"), "list_workspaces", args(t, WorkspacesInput{DeviceID: string(device)})))
		if result.Error != nil || result.Data == nil || !reflect.DeepEqual(result.Data.Scopes, backend.scopes) || result.Data.ScopeDiscoveryError != backend.discoveryError || result.Data.ObservedAt == nil {
			t.Fatalf("scope discovery result was hidden or substituted: %+v", result)
		}
	}
}
