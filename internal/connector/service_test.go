package connector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type fakeControl struct {
	call        protocol.ControlCall
	frame       protocol.Frame
	deadline    time.Time
	claimed     atomic.Bool
	discarded   atomic.Bool
	reply       chan protocol.Reply
	completions chan protocol.ControlCompletion
	rejected    chan protocol.Failure
	peer        *fakePeer
}

func (c *fakeControl) Frame() protocol.Frame { return c.frame }
func (c *fakeControl) Claim(ctx context.Context) (protocol.Frame, error) {
	if ctx.Err() != nil || c.peer.closed.Load() || !time.Now().Before(c.deadline) {
		return protocol.Frame{}, ErrConflict
	}
	if !c.claimed.CompareAndSwap(false, true) {
		return protocol.Frame{}, ErrConflict
	}
	return c.frame, nil
}

func (c *fakeControl) ControlCall() protocol.ControlCall { return c.call }
func (c *fakeControl) ReplyControl(_ context.Context, reply protocol.Reply, completion protocol.ControlCompletion) error {
	if completion.Validate() != nil || completion.Call != c.call || completion.ProcessBoot != c.peer.boot() {
		return ErrEvidence
	}
	if c.peer.closed.Load() {
		return ErrPending
	}
	if c.completions != nil {
		c.completions <- completion
	}
	c.reply <- reply
	return nil
}

func (c *fakeControl) Reject(_ context.Context, failure protocol.Failure) error {
	if c.claimed.Load() {
		return ErrConflict
	}
	c.rejected <- failure
	return nil
}
func (c *fakeControl) Discard() error { c.discarded.Store(true); return nil }

type fakePeer struct {
	closeCalls atomic.Int32
	gen        domain.ConnectionGeneration
	incoming   chan control
	closed     atomic.Bool
	mu         sync.Mutex
	reports    []protocol.CapabilityReport
	reported   chan struct{}
}

func (p *fakePeer) generation() domain.ConnectionGeneration {
	if p.gen.Counter == 0 {
		return domain.ConnectionGeneration{BootEpoch: "boot", Counter: 1}
	}
	return p.gen
}
func (p *fakePeer) boot() string { return strings.Repeat("a", 32) }
func (p *fakePeer) close() error { p.closeCalls.Add(1); p.closed.Store(true); return nil }

func (p *fakePeer) next(ctx context.Context) (control, error) {
	select {
	case <-ctx.Done():
		p.closed.Store(true)
		return nil, ErrPending
	case c := <-p.incoming:
		return c, nil
	}
}

func (p *fakePeer) report(_ context.Context, r protocol.CapabilityReport) error {
	p.mu.Lock()
	p.reports = append(p.reports, r)
	p.mu.Unlock()
	if p.reported != nil {
		select {
		case p.reported <- struct{}{}:
		default:
		}
	}
	return nil
}

func (p *fakePeer) control(t *testing.T, command protocol.Command, id int) *fakeControl {
	t.Helper()
	frame := protocol.Frame{Version: protocol.Version, Type: protocol.Request, RequestID: fmt.Sprintf("g:%d", id), Generation: protocol.Generation{BootEpoch: string(p.generation().BootEpoch), Counter: p.generation().Counter}, OperationID: "operation-one", TTLMillis: 30000, Payload: encoded(t, command)}
	hash := domain.Hash(frame.Payload)
	call := protocol.ControlCall{Generation: frame.Generation, RequestID: frame.RequestID, OperationID: frame.OperationID, Operation: command.Operation, RequestSHA256: hex.EncodeToString(hash[:])}
	return &fakeControl{call: call, frame: frame, deadline: time.Now().Add(30 * time.Second), reply: make(chan protocol.Reply, 1), completions: make(chan protocol.ControlCompletion, 1), rejected: make(chan protocol.Failure, 1), peer: p}
}

func TestServiceKeepsFourOwnersAndReservedCancellationAfterDisconnect(t *testing.T) {
	f := newFixture(t)
	f.config.ControlTimeout = 30 * time.Second
	if reloadErr := f.adapter.Reload(t.Context(), f.config); reloadErr != nil {
		t.Fatal(reloadErr)
	}
	f.adapter.Probe(t.Context())
	f.state.Block = "context"
	f.writeState()
	p := &fakePeer{incoming: make(chan control, 8)}
	service, cancelAttach, attached := attachedService(t, f, p)

	for index := 1; index <= 4; index++ {
		command := protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: encoded(t, protocol.InspectRequest{GatewayID: "gateway-one"})}
		p.incoming <- p.control(t, command, index)
		waitStarted(t, f.config.Projects[0].Root, index)
	}
	f.state.Block = "status"
	f.writeState()

	overflow := p.control(t, protocol.Command{Operation: protocol.ContextInspect, Project: "project-one", Body: encoded(t, protocol.InspectRequest{GatewayID: "gateway-one"})}, 5)
	p.incoming <- overflow
	assertResourceRefusal(t, overflow)
	cancellation := protocol.Command{Operation: protocol.Cancel, Project: "project-one", Body: encoded(t, protocol.Cancellation{Task: f.task(), CancellationID: strings.Repeat("e", 32)})}
	urgent := p.control(t, cancellation, 6)
	p.incoming <- urgent
	assertStoppedReply(t, urgent)
	cancelAttach()
	select {
	case <-attached:
	case <-time.After(10 * time.Second):
		t.Fatal("detached intake did not stop")
	}
	f.clock.advance(2 * time.Second)
	status := service.Status()
	if status.Adapter.Active != 4 || status.UnobservedControls != 4 || status.Ready {
		t.Fatal("disconnect discarded unsettled process ownership")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if closeErr := service.Close(ctx); !errors.Is(closeErr, ErrPending) {
		t.Fatal("Close claimed unjoined controls settled")
	}
	f.release()
}

func TestCancelledOwnerCannotAttachNewControlIntake(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	service, err := NewService(ctx, f.adapter, testServiceConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer stop()
		if closeErr := service.Close(owner); closeErr != nil {
			t.Error(closeErr)
		}
	})
	acknowledgeFake(t, service, &fakePeer{})
	cancel()
	if attachErr := service.attach(t.Context(), &fakePeer{incoming: make(chan control)}); !errors.Is(attachErr, ErrConflict) {
		t.Fatal("cancelled service owner accepted new intake")
	}
}

func TestAcceptedControlUsesFiniteLocalDeadlineBeyondReceiptTTL(t *testing.T) {
	f := newFixture(t)
	f.config.ControlTimeout = 45 * time.Second
	if reloadErr := f.adapter.Reload(t.Context(), f.config); reloadErr != nil {
		t.Fatal(reloadErr)
	}
	f.state.Block = "status"
	f.writeState()
	p := &fakePeer{incoming: make(chan control, 1)}
	service, cancelAttach, _ := attachedService(t, f, p)

	c := p.control(t, f.command(protocol.Status), 1)
	c.deadline = time.Now().Add(10 * time.Second)
	c.frame.TTLMillis = 10000
	p.incoming <- c
	waitPath(t, filepath.Join(f.config.Projects[0].Root, "started-"+f.task().TaskID))
	f.clock.advance(31 * time.Second)
	status := f.adapter.Status()
	if status.Active != 1 || status.CleanupPending != 0 {
		t.Fatal("receipt TTL truncated accepted45s native ownership")
	}
	assertStatusTimeout(t, f.calls())
	cancelAttach()
	if f.adapter.Status().Active != 1 {
		t.Fatal("disconnect released accepted native owner")
	}
	f.release()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if closeErr := service.Close(ctx); closeErr != nil {
		t.Fatal(closeErr)
	}
	if f.adapter.Status().Active != 0 {
		t.Fatal("joined CLI retained execution ownership")
	}
}

func assertNativeTimeout(t *testing.T, args []string) {
	t.Helper()
	for i, arg := range args {
		if arg == "--control-timeout" && i+1 < len(args) {
			value, parseErr := time.ParseDuration(args[i+1])
			if parseErr != nil || value <= 30*time.Second || value > 45*time.Second {
				t.Fatal("public CLI did not receive configured finite execution deadline")
			}
			return
		}
	}
	t.Fatal("public CLI missing finite control deadline")
}

func attachedService(t *testing.T, f *fixture, p *fakePeer) (*Service, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	service, serviceErr := NewService(t.Context(), f.adapter, testServiceConfig())
	if serviceErr != nil {
		t.Fatal(serviceErr)
	}
	t.Cleanup(func() {
		f.release()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()
		if closeErr := service.Close(ctx); closeErr != nil {
			t.Error(closeErr)
		}
	})
	acknowledgeFake(t, service, p)
	cancel, done := startFakeAttachment(t, f, service, p)
	return service, cancel, done
}

func startFakeAttachment(t *testing.T, f *fixture, service *Service, p *fakePeer) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		attachErr := service.attach(ctx, p)
		if attachErr != nil && !errors.Is(attachErr, ErrPending) {
			t.Error(attachErr)
		}
	}()
	t.Cleanup(func() {
		cancel()
		f.release()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("intake did not join")
		}
	})
	return cancel, done
}

func assertResourceRefusal(t *testing.T, control *fakeControl) {
	t.Helper()
	select {
	case rejected := <-control.rejected:
		if rejected.Code != "resource_limit" || control.claimed.Load() {
			t.Fatal("saturated control acquired execution ownership")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("missing bounded saturation refusal")
	}
}

func assertStoppedReply(t *testing.T, control *fakeControl) {
	t.Helper()
	select {
	case reply := <-control.reply:
		result := observation(t, reply)
		if result.Stop == nil || !result.Stop.Terminated {
			t.Fatal("reserved cancellation did not finish")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ordinary calls consumed reserved cancellation capacity")
	}
}

func assertStatusTimeout(t *testing.T, calls []helperCall) {
	t.Helper()
	for _, call := range calls {
		if call.Command == "status" {
			assertNativeTimeout(t, call.Args)
			return
		}
	}
	t.Fatal("missing started status control")
}

func testServiceConfig() ServiceConfig {
	return ServiceConfig{ProcessBoot: strings.Repeat("a", 32), Random: rand.Reader}
}

func acknowledgeFake(t *testing.T, service *Service, p *fakePeer) {
	t.Helper()
	inventory, inventoryErr := service.Inventory(t.Context(), p.generation())
	if inventoryErr != nil {
		t.Fatal(inventoryErr)
	}
	ack := protocol.ControlInventoryAck{PolicyVersion: protocol.RoutingPolicyVersion, CredentialMode: string(domain.Regular), ProcessBoot: inventory.ProcessBoot, BarrierID: inventory.BarrierID, Generation: inventory.Generation, Ready: true}
	if ackErr := service.Acknowledge(t.Context(), ack); ackErr != nil {
		t.Fatal(ackErr)
	}
}

func waitStarted(t *testing.T, root string, count int) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		entries, readErr := os.ReadDir(root)
		if readErr != nil {
			t.Fatal(readErr)
		}
		started := 0
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "started-") {
				started++
			}
		}
		if started == count {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("owned metadata processes did not reach their start gates")
		case <-ticker.C:
		}
	}
}
