package workspaces_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type unavailableAuthorization struct{ *registry.Store }

func (s unavailableAuthorization) AuthorizeOwnedDevice(context.Context, domain.OwnedDeviceRequest) (domain.OwnedDeviceAuthorization, error) {
	return domain.OwnedDeviceAuthorization{}, errors.Join(domain.Reject(domain.NotFound), errors.New("private-storage-canary"))
}

func TestInitialResolutionDenialRecordsOneBoundedObservationAndNoDestination(t *testing.T) {
	f := newFixture(t)
	ctx := bounded(t)
	policy := ownerPolicy()
	policy.Enabled = false
	require(t, f.store.PutOwnerPolicy(ctx, f.actor.Principal, policy))
	_, err := f.backend.ResolveProject(ctx, f.actor, f.input())
	requireCode(t, err, domain.Forbidden)
	values := f.observations.snapshot()
	if len(values) != 1 {
		t.Fatalf("initial denial recorded %d observations, want1", len(values))
	}
	value := values[0]
	if value.Principal != f.actor.Principal || value.Destination != (domain.Destination{}) || value.Operation != "" || value.RootOnly || value.Control.Class != routing.ControlClass(protocol.ResolveProject) || value.Control.Authorization != routing.DeniedOrMissing || value.Control.Transport != routing.NotAttempted || value.Control.WriteState != routing.WriteNotStarted {
		t.Fatalf("initial denial did not conceal requested route: %+v", value)
	}
	if f.resolveCalls.Load() != 0 {
		t.Fatal("denied request reached Native")
	}
}

func TestInitialResolutionMixedFailurePreservesUncertaintyWithoutDenialObservation(t *testing.T) {
	f := newFixture(t)
	backend := f.service(t, unavailableAuthorization{Store: f.store})
	_, err := backend.ResolveProject(bounded(t), f.actor, f.input())
	if err == nil {
		t.Fatal("mixed authorization/storage failure disappeared")
	}
	if len(f.observations.snapshot()) != 0 || f.resolveCalls.Load() != 0 {
		t.Fatal("mixed operational failure was reported as a policy denial or routed")
	}
}
