package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func nextInventory(t *testing.T, service *Service, counter uint64) protocol.ControlInventory {
	t.Helper()
	report, inventoryErr := service.Inventory(t.Context(), domain.ConnectionGeneration{BootEpoch: "boot", Counter: counter})
	if inventoryErr != nil {
		t.Fatal(inventoryErr)
	}
	return report
}

func ackInventory(t *testing.T, service *Service, report protocol.ControlInventory) {
	t.Helper()
	ack := protocol.ControlInventoryAck{PolicyVersion: protocol.RoutingPolicyVersion, CredentialMode: string(domain.Regular), ProcessBoot: report.ProcessBoot, BarrierID: report.BarrierID, Generation: report.Generation, Ready: true}
	if ackErr := service.Acknowledge(t.Context(), ack); ackErr != nil {
		t.Fatal(ackErr)
	}
}

func expectNudge(t *testing.T, service *Service) {
	t.Helper()
	select {
	case <-service.NeedsReconcile():
	case <-time.After(10 * time.Second):
		t.Fatal("settled owner did not request fenced reconciliation")
	}
}

func blockedStatus(t *testing.T, f *fixture, p *fakePeer) *fakeControl {
	t.Helper()
	control := p.control(t, f.command(protocol.Status), 1)
	p.incoming <- control
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+f.task().TaskID))
	return control
}

func primeLongStatus(t *testing.T, f *fixture) {
	t.Helper()
	f.config.ControlTimeout = 30 * time.Second
	if reloadErr := f.adapter.Reload(t.Context(), f.config); reloadErr != nil {
		t.Fatal(reloadErr)
	}
	f.adapter.Probe(t.Context())
	f.state.Block = "status"
	f.writeState()
}

func TestCensusFencesOldIntakeAndLateOldGenerationCompletionNudges(t *testing.T) {
	f := newFixture(t)
	primeLongStatus(t, f)
	p := &fakePeer{incoming: make(chan control, 1)}
	service, _, oldDone := attachedService(t, f, p)
	accepted := blockedStatus(t, f, p)
	if _, inventoryErr := service.Inventory(t.Context(), p.generation()); !errors.Is(inventoryErr, ErrConflict) {
		t.Fatal("same-generation census allowed after normal claims began")
	}
	report := nextInventory(t, service, 2)
	select {
	case <-oldDone:
	default:
		t.Fatal("census preceded old intake join")
	}
	if !p.closed.Load() || len(report.Active) != 1 || report.Active[0] != accepted.call {
		t.Fatal("census omitted accepted old-generation owner")
	}
	copy := report
	copy.Active = append([]protocol.ControlCall(nil), report.Active...)
	report.Active[0].RequestID = "g:999"
	replay := nextInventory(t, service, 2)
	if !reflect.DeepEqual(replay, copy) {
		t.Fatal("lost ACK replay changed stable census contents")
	}
	beforeACK := &fakePeer{gen: domain.ConnectionGeneration{BootEpoch: "boot", Counter: 2}, incoming: make(chan control)}
	if attachErr := service.attach(t.Context(), beforeACK); !errors.Is(attachErr, ErrConflict) {
		t.Fatal("new intake began before exact census ACK")
	}
	ackInventory(t, service, replay)
	f.release()
	expectNudge(t, service)
	if f.adapter.Status().Active != 0 || service.Status().Ready {
		t.Fatal("old-generation completion lost cleanup ownership or skipped reconciliation")
	}
	final := nextInventory(t, service, 3)
	if len(final.Active) != 0 {
		t.Fatal("joined old-generation control stayed active in next census")
	}
	ackInventory(t, service, final)
	if !service.Status().Ready {
		t.Fatal("fresh acknowledged census did not restore local readiness")
	}
}

func TestPendingCleanupKeepsKeyAfterReplyUntilActualCleanup(t *testing.T) {
	f := newFixture(t)
	primeLongStatus(t, f)
	p := &fakePeer{incoming: make(chan control, 1)}
	service, _, _ := attachedService(t, f, p)
	accepted := blockedStatus(t, f, p)
	dirs, readErr := os.ReadDir(f.config.TemporaryDirectory)
	if readErr != nil || len(dirs) != 1 {
		t.Fatal("missing owned control temp directory")
	}
	foreign := filepath.Join(f.config.TemporaryDirectory, dirs[0].Name(), "test-owned-foreign")
	if writeErr := os.WriteFile(foreign, []byte("not adapter-owned"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	t.Cleanup(func() {
		f.release()
		if removeErr := os.Remove(foreign); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			t.Error(removeErr)
		}
		settleTestCleanup(t, f)
	})
	f.release()
	select {
	case completion := <-accepted.completions:
		if completion.Disposition != protocol.ControlPending {
			t.Fatal("unsettled cleanup was reported settled")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("missing pending cleanup receipt")
	}
	report := nextInventory(t, service, 2)
	if len(report.Active) != 1 || report.Active[0] != accepted.call {
		t.Fatal("pending key disappeared after reply")
	}
	ackInventory(t, service, report)
	if removeErr := os.Remove(foreign); removeErr != nil {
		t.Fatal(removeErr)
	}
	expectNudge(t, service)
	final := nextInventory(t, service, 3)
	if len(final.Active) != 0 || f.adapter.Status().Active != 0 {
		t.Fatal("actual joined cleanup did not clear retained census key")
	}
	ackInventory(t, service, final)
}

func settleTestCleanup(t *testing.T, f *fixture) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		cleanupErr := f.adapter.RetryCleanup()
		if cleanupErr == nil && f.adapter.Status().Active == 0 {
			return
		}
		select {
		case <-timer.C:
			t.Error("owned cleanup did not settle")
			return
		case <-ticker.C:
		}
	}
}

func TestLocalBusyScanDeclinesNetworkControlWithoutLaterCLI(t *testing.T) {
	f := newFixture(t)
	primeLongStatus(t, f)
	local := make(chan protocol.Reply, 1)
	go func() { local <- f.adapter.Execute(t.Context(), f.command(protocol.Status)) }()
	t.Cleanup(func() {
		f.release()
		select {
		case <-local:
		case <-time.After(10 * time.Second):
			t.Error("local owner did not join")
		}
	})
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+f.task().TaskID))
	p := &fakePeer{incoming: make(chan control, 1)}
	_, _, _ = attachedService(t, f, p)
	refused := p.control(t, f.command(protocol.Status), 1)
	p.incoming <- refused
	assertResourceRefusal(t, refused)
	if refused.claimed.Load() {
		t.Fatal("busy scan accepted network ownership")
	}
	f.release()
	// Joining via the creator's result channel is repeated safely for cleanup.
	reply := <-local
	local <- reply
	count := 0
	for _, call := range f.calls() {
		if call.Command == "status" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("declined control ran after scan capacity became free")
	}
}

func TestCensusClosesRetainedSocketAfterIntakeAlreadyExited(t *testing.T) {
	f := newFixture(t)
	p := &fakePeer{incoming: make(chan control, 1)}
	service, cancel, done := attachedService(t, f, p)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("old intake did not exit")
	}
	if p.closeCalls.Load() != 0 {
		t.Fatal("fixture cannot distinguish intake from socket close")
	}
	ctx, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer stop()
	if attachErr := service.attach(ctx, p); !errors.Is(attachErr, ErrConflict) {
		t.Fatal("same acknowledged generation accepted another intake")
	}
	_ = nextInventory(t, service, 2)
	if p.closeCalls.Load() != 1 {
		t.Fatal("census lost concrete socket reader owner when intake exited")
	}
}

func TestDirtyCensusRejectsReadyACKUntilFreshGeneration(t *testing.T) {
	f := newFixture(t)
	primeLongStatus(t, f)
	p := &fakePeer{incoming: make(chan control, 1)}
	service, _, _ := attachedService(t, f, p)
	blockedStatus(t, f, p)
	report := nextInventory(t, service, 2)
	f.release()
	expectNudge(t, service)
	ack := protocol.ControlInventoryAck{PolicyVersion: protocol.RoutingPolicyVersion, CredentialMode: string(domain.Regular), ProcessBoot: report.ProcessBoot, BarrierID: report.BarrierID, Generation: report.Generation, Ready: true}
	if ackErr := service.Acknowledge(t.Context(), ack); !errors.Is(ackErr, ErrPending) {
		t.Fatal("ready ACK hid a local completion after its census")
	}
	if service.Status().Ready {
		t.Fatal("dirty census advertised execution readiness")
	}
	final := nextInventory(t, service, 3)
	ackInventory(t, service, final)
	if !service.Status().Ready {
		t.Fatal("fresh complete census did not restore readiness")
	}
}
