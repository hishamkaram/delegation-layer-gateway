package registry

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func ownedRootFixture(t *testing.T) (*fixture, *OwnedRootPort) {
	t.Helper()
	f := newFixture(t)
	actor, input := selfEnrollmentFixture(t, f)
	requireOK(t, f.store.PutOwnerPolicy(t.Context(), actor.Principal, testOwnerPolicy()))
	reserved, err := f.store.BeginSelfEnrollment(t.Context(), actor, input)
	intent := must(t, reserved, err)
	_, err = f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: intent.ID, CertificateDER: signFixture(t, intent, f.key), Now: f.now})
	requireOK(t, err)
	connection, err := f.store.NextConnectionGeneration(t.Context(), intent.Credential, "owned-boot", f.now)
	requireOK(t, err)
	binding := domain.OwnedRootBinding{Route: domain.RootRoute{Device: intent.Credential.Device, Root: domain.RootGuard(fixtureGuard("owned-root"))}, Credential: intent.Credential, Connection: connection}
	p, err := NewOwnedRootPort(t.Context(), f.store, binding, func() time.Time { return f.now })
	return f, must(t, p, err)
}

func beginOwnedRoot(t *testing.T, p *OwnedRootPort) domain.RootInitializationProgress {
	t.Helper()
	progress, err := p.BeginRootInitialization(t.Context(), domain.RootInitializationStart{RootRoute: &p.binding.Route, Credential: p.binding.Credential, Connection: p.binding.Connection, Now: p.now()})
	return must(t, progress, err)
}

func TestOwnedRootZeroProjectsUsesExistingDurablePhasesAndRestart(t *testing.T) {
	f, p := ownedRootFixture(t)
	var count int
	requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM projects WHERE device=?", p.binding.Route.Device).Scan(&count))
	if count != 0 {
		t.Fatal("fixture invented a project")
	}
	progress, err := p.ReadRootInitializationProgress(t.Context(), p.lookup())
	if got := must(t, progress, err); got.Stage != domain.RootNeedsBarrier || got.RootRoute == nil || got.Route != (domain.Destination{}) {
		t.Fatal("root report did not register zero-project pending state")
	}
	progress = beginOwnedRoot(t, p)
	destination := domain.RecoveryDestination{Recovery: progress.RecoveryID, Device: p.binding.Route.Device, Root: p.binding.Route.Root}
	plan, err := p.PrepareRecoveryBarrier(t.Context(), domain.BarrierPreparation{Destination: destination, Credential: p.binding.Credential, Connection: p.binding.Connection, Now: f.now})
	requireOK(t, err)
	if plan.Generation != progress.Generation || plan.ExpectedGeneration != "" {
		t.Fatal("fresh root did not reserve an expected-absent generation")
	}
	requireOK(t, p.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: destination, Generation: plan.Generation, Receipt: domain.Hash([]byte("canonical native barrier"))}))
	complete := domain.Hash([]byte("canonical native completeness"))
	requireOK(t, p.ApplyInventoryPage(t.Context(), domain.ValidatedInventoryPage{Destination: destination, Generation: plan.Generation, Membership: domain.Hash([]byte("empty gateway membership")), CompletenessReceipt: &complete, Now: f.now}))
	approved, err := p.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: progress.RecoveryID, Now: f.now})
	approval := must(t, approved, err)
	if len(approval.Targets) != 1 || approval.Targets[0].Destination != destination {
		t.Fatal("owned recovery approved outside the exact root")
	}
	target := approval.Targets[0]
	requireOK(t, p.CheckReopen(t.Context(), domain.ReopenCheck{Target: target, Credential: p.binding.Credential, Connection: p.binding.Connection, Now: f.now}))
	requireOK(t, p.RecordReopen(t.Context(), domain.ValidatedReopenReceipt{Target: target, Receipt: domain.Hash([]byte("canonical native reopened")), Now: f.now}))
	requireOK(t, p.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: progress.RecoveryID, Now: f.now}))
	binding := p.Binding()
	f.restart(t)
	p, err = NewOwnedRootPort(t.Context(), f.store, binding, func() time.Time { return f.now })
	requireOK(t, err)
	ready, err := p.ReadRootInitializationProgress(t.Context(), p.lookup())
	if got := must(t, ready, err); got.Stage != domain.RootReady || got.Generation != plan.Generation || got.RecoveryID != progress.RecoveryID {
		t.Fatal("restart lost the authoritative ready generation")
	}
}

func TestOwnedRootPortRechecksPolicyConnectionAndExactRoot(t *testing.T) {
	for _, kind := range []string{"disabled-policy", "revoked-owner", "revoked-device", "new-connection"} {
		t.Run(kind, func(t *testing.T) {
			f, p := ownedRootFixture(t)
			progress := beginOwnedRoot(t, p)
			switch kind {
			case "disabled-policy":
				policy := testOwnerPolicy()
				policy.Enabled = false
				requireOK(t, f.store.PutOwnerPolicy(t.Context(), p.owner, policy))
			case "revoked-owner":
				requireOK(t, f.store.SetPrincipalRevoked(t.Context(), p.owner, true))
			case "revoked-device":
				requireOK(t, f.store.SetDeviceRevoked(t.Context(), p.binding.Route.Device, true))
			case "new-connection":
				_, err := f.store.NextConnectionGeneration(t.Context(), p.binding.Credential, "new-owned-boot", f.now)
				requireOK(t, err)
			}
			if err := p.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: domain.RecoveryDestination{Recovery: progress.RecoveryID, Device: p.binding.Route.Device, Root: p.binding.Route.Root}, Generation: progress.Generation, Receipt: domain.Hash([]byte("barrier"))}); err == nil {
				t.Fatal("stale owner authority mutated a durable phase")
			}
			var barrier []byte
			requireOK(t, f.store.db.QueryRowContext(t.Context(), "SELECT barrier FROM recovery_destinations WHERE recovery=?", progress.RecoveryID).Scan(&barrier))
			if len(barrier) != 0 {
				t.Fatal("denied receipt committed")
			}
		})
	}
	f, p := ownedRootFixture(t)
	legacy := domain.OwnedRootBinding{Route: domain.RootRoute{Device: f.credential.Device, Root: binding().Root}, Credential: f.credential, Connection: f.connection}
	_, err := NewOwnedRootPort(t.Context(), f.store, legacy, func() time.Time { return f.now })
	requireCode(t, err, domain.Forbidden)
	wrong := p.binding
	wrong.Route.Root = domain.RootGuard(fixtureGuard("different-root"))
	_, err = NewOwnedRootPort(t.Context(), f.store, wrong, func() time.Time { return f.now })
	requireCode(t, err, domain.Conflict)
	_, err = p.ReadRootInitializationProgress(t.Context(), domain.RootInitializationLookup{Route: destination(), ExpectedContext: binding()})
	requireCode(t, err, domain.Forbidden)
	_, err = p.BeginRootInitialization(t.Context(), domain.RootInitializationStart{RootRoute: &p.binding.Route, Credential: f.credential, Connection: f.connection, Now: f.now})
	requireCode(t, err, domain.Forbidden)
}

func TestOwnedRootPortCannotMutateForeignRecoveryOrImportTasks(t *testing.T) {
	_, p := ownedRootFixture(t)
	progress := beginOwnedRoot(t, p)
	destination := domain.RecoveryDestination{Recovery: progress.RecoveryID, Device: p.binding.Route.Device, Root: p.binding.Route.Root}
	foreign := destination
	foreign.Recovery = "other-recovery"
	requireCode(t, p.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: foreign, Generation: progress.Generation, Receipt: domain.Hash([]byte("barrier"))}), domain.Forbidden)
	foreign = destination
	foreign.Root = domain.RootGuard(fixtureGuard("another-root"))
	requireCode(t, p.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: foreign, Generation: progress.Generation, Receipt: domain.Hash([]byte("barrier"))}), domain.Forbidden)
	complete := domain.Hash([]byte("complete"))
	requireCode(t, p.ApplyInventoryPage(t.Context(), domain.ValidatedInventoryPage{Destination: destination, Generation: progress.Generation, Entries: []domain.InventoryEntry{{}}, CompletenessReceipt: &complete}), domain.Conflict)
	_, err := p.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: "other-recovery"})
	requireCode(t, err, domain.Forbidden)
	requireCode(t, p.FinishRecovery(t.Context(), domain.RecoveryFinish{Recovery: "other-recovery"}), domain.Forbidden)
}

func rootRoutingRequest(t *testing.T, p *OwnedRootPort, request string, operation protocol.Operation, body any) routing.Request {
	t.Helper()
	encoded, err := protocol.Encode(body, protocol.MaxFrameBytes)
	requireOK(t, err)
	payload, err := protocol.Encode(protocol.Command{Operation: operation, Root: string(p.binding.Route.Root), Body: encoded}, protocol.MaxFrameBytes)
	requireOK(t, err)
	digest := domain.Hash(payload)
	return routing.Request{WireVersion: protocol.WireVersion2, Credential: p.binding.Credential, ProcessBoot: strings.Repeat("a", 32), Call: protocol.ControlCall{Generation: protocol.Generation{BootEpoch: string(p.binding.Connection.BootEpoch), Counter: p.binding.Connection.Counter}, RequestID: request, Operation: operation, RequestSHA256: hex.EncodeToString(digest[:])}, Payload: payload, Now: p.now()}
}

func TestOwnedRootRoutingRetainsCensusQuotaAndRejectsNonRootControls(t *testing.T) {
	f, p := ownedRootFixture(t)
	report := protocol.ControlInventory{PolicyVersion: protocol.RoutingPolicyVersion, ProcessBoot: strings.Repeat("a", 32), BarrierID: strings.Repeat("b", 32), Generation: protocol.Generation{BootEpoch: string(p.binding.Connection.BootEpoch), Counter: p.binding.Connection.Counter}, Complete: true}
	_, err := f.store.ReconcileRouting(t.Context(), p.binding.Credential, report, f.now)
	requireOK(t, err)
	request := rootRoutingRequest(t, p, "g:1", protocol.ContextInspect, protocol.InspectRequest{GatewayID: string(p.gateway), RootOnly: true})
	requireOK(t, p.AcquireRouting(t.Context(), request))
	requireCode(t, p.AcquireRouting(t.Context(), request), domain.Conflict)
	wrong := request
	wrong.WireVersion = protocol.Version
	if err = p.AcquireRouting(t.Context(), wrong); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("wire1 root control passed acquisition", err)
	}
	wrong = rootRoutingRequest(t, p, "g:2", protocol.ContextInspect, protocol.InspectRequest{GatewayID: "other-gateway", RootOnly: true})
	if err = p.AcquireRouting(t.Context(), wrong); err == nil {
		t.Fatal("owned root routed another Gateway namespace")
	}
	wrong = rootRoutingRequest(t, p, "g:3", protocol.ResolveProject, struct{}{})
	if err = p.AcquireRouting(t.Context(), wrong); err == nil {
		t.Fatal("initializer authority became project resolution authority")
	}
	active := []routing.Request{request}
	for i := 2; i <= 32; i++ {
		next := rootRoutingRequest(t, p, "g:"+strconv.Itoa(i+10), protocol.ContextInspect, protocol.InspectRequest{GatewayID: string(p.gateway), RootOnly: true})
		requireOK(t, p.AcquireRouting(t.Context(), next))
		active = append(active, next)
	}
	overflow := rootRoutingRequest(t, p, "g:999", protocol.ContextInspect, protocol.InspectRequest{GatewayID: string(p.gateway), RootOnly: true})
	requireCode(t, p.AcquireRouting(t.Context(), overflow), domain.ResourceLimit)
	for _, input := range active {
		requireOK(t, f.store.ReleaseUnpublishedRouting(t.Context(), input))
	}
}
