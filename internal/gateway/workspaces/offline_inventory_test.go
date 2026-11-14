package workspaces_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const inventoryFailureMarker = "private-workspace-inventory-failure"

type workspaceInventoryFailure struct {
	name    string
	err     error
	offline bool
}

func workspaceInventoryFailures() []workspaceInventoryFailure {
	offline := &gateway.RemoteError{Failure: protocol.Failure{Code: "device_offline", Retryable: true}}
	var nilRemote *gateway.RemoteError
	return []workspaceInventoryFailure{
		{name: "sole-offline", err: offline, offline: true},
		{name: "single-join-offline", err: errors.Join(offline, nil), offline: true},
		{name: "mixed-storage", err: errors.Join(offline, errors.New(inventoryFailureMarker))},
		{name: "ordinary-wrapper", err: fmt.Errorf("%s: %w", inventoryFailureMarker, offline)},
		{name: "typed-nil", err: nilRemote},
	}
}

type workspaceFailedPresence struct{ err error }

func (p workspaceFailedPresence) Snapshot(domain.DeviceID) (gateway.LinkSnapshot, error) {
	return gateway.LinkSnapshot{}, p.err
}

func workspaceInventoryService(t *testing.T, f *fixture, presence workspaces.Presence) *workspaces.Service {
	t.Helper()
	service, err := workspaces.New(workspaces.Options{
		Store: f.store, Presence: presence, Controls: f.controls,
		GatewayID: f.gateway, Now: time.Now,
		Roots: func(context.Context, domain.OwnedRootBinding) (workspaces.Initializer, error) {
			return nil, errors.New("inventory unexpectedly requested namespace initialization")
		},
	})
	require(t, err)
	return service
}

func TestWorkspaceInventoryOfflineProjectionRequiresSoleCause(t *testing.T) {
	f := newFixture(t)
	for _, test := range workspaceInventoryFailures() {
		t.Run(test.name, func(t *testing.T) {
			service := workspaceInventoryService(t, f, workspaceFailedPresence{err: test.err})
			inventory, err := service.ListWorkspaces(t.Context(), f.actor, f.device)
			if test.offline {
				require(t, err)
				assertOfflineWorkspaceInventory(t, inventory, f.device)
			} else {
				if !errors.Is(err, test.err) {
					t.Fatal("workspace inventory discarded its original Presence cause")
				}
				assertOfflineWorkspaceInventory(t, inventory, "")
			}
		})
	}
	assertInventoryStartedNoControls(t, f)
}

func assertOfflineWorkspaceInventory(t *testing.T, inventory workspaces.Inventory, device domain.DeviceID) {
	t.Helper()
	if inventory.Device != device || inventory.Online || inventory.DelegateReady || !inventory.ObservedAt.IsZero() || len(inventory.Workspaces) != 0 || inventory.ProjectBudget != nil {
		t.Fatal("failed Presence projection disclosed live workspace metadata")
	}
}

func assertInventoryStartedNoControls(t *testing.T, f *fixture) {
	t.Helper()
	if f.resolveCalls.Load() != 0 || f.inspectCalls.Load() != 0 || f.barrierCalls.Load() != 0 {
		t.Fatal("workspace inventory requested a project or namespace control")
	}
}
