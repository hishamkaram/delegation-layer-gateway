package connector

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type boundedOutput struct {
	data     []byte
	limit    int
	overflow bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	n := len(data)
	remaining := b.limit - len(b.data)
	if n > remaining {
		b.overflow = true
		data = data[:remaining]
	}
	b.data = append(b.data, data...)
	return n, nil
}

type permit struct{ channels []chan struct{} }

func (p permit) release() {
	for _, ch := range p.channels {
		<-ch
	}
}

type limits struct {
	ordinary   chan struct{}
	urgent     chan struct{}
	admission  chan struct{}
	scan       chan struct{}
	resolution chan struct{}
}

func newLimits() limits {
	return limits{ordinary: make(chan struct{}, 4), urgent: make(chan struct{}, 2), admission: make(chan struct{}, 2), scan: make(chan struct{}, 1), resolution: make(chan struct{}, 2)}
}

func (l limits) acquire(op protocol.Operation) (permit, error) {
	lane := l.ordinary
	if op == protocol.Cancel || op == protocol.FenceAbsent {
		lane = l.urgent
	}
	channels := []chan struct{}{lane}
	if op == protocol.Admit || op == protocol.ResumeExisting {
		channels = append(channels, l.admission)
	}
	if op.ScanConsumer() {
		channels = append(channels, l.scan)
	}
	if op == protocol.ResolveProject {
		channels = append(channels, l.resolution)
	}
	p := permit{}
	for _, ch := range channels {
		select {
		case ch <- struct{}{}:
			p.channels = append(p.channels, ch)
		default:
			p.release()
			return permit{}, ErrCapacity
		}
	}
	return p, nil
}

type controlOwner struct {
	deadline      time.Time
	waited        bool
	temporary     string
	files         []string
	cleanupFailed bool
	cleanupBusy   bool
	held          permit
}

// Adapter owns config generations, CLI permits and unsettled controls. It has
// no task ledger: every task fact comes from a validated public CLI response.
type Adapter struct {
	mu           sync.RWMutex
	config       *configuration
	now          func() time.Time
	limits       limits
	owners       map[*controlOwner]struct{}
	probed       bool
	report       protocol.CapabilityReport
	observed     map[string]time.Time
	root         *protocol.RootCapability
	rootObserved time.Time
}

type Status struct {
	Active           int
	CleanupPending   int
	Ready            bool
	ConfigGeneration uint64
}

func NewAdapter(config Config, now func() time.Time) (*Adapter, error) {
	if now == nil {
		return nil, ErrConfiguration
	}
	checked, err := checkedConfig(config)
	if err != nil {
		return nil, err
	}
	checked.generation = 1
	return &Adapter{config: checked, now: now, limits: newLimits(), owners: make(map[*controlOwner]struct{})}, nil
}
func (a *Adapter) snapshot() *configuration { a.mu.RLock(); defer a.mu.RUnlock(); return a.config }
func (a *Adapter) Generation() uint64       { return a.snapshot().generation }
func (a *Adapter) Reload(ctx context.Context, config Config) error {
	if ctx.Err() != nil {
		return ErrPending
	}
	checked, err := checkedConfig(config)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.generation == ^uint64(0) {
		return ErrCapacity
	}
	checked.generation = a.config.generation + 1
	a.config = checked
	a.probed = false
	a.report = protocol.CapabilityReport{}
	a.observed = nil
	return nil
}

func (a *Adapter) Status() Status {
	a.mu.RLock()
	defer a.mu.RUnlock()
	status := Status{Active: len(a.owners), Ready: a.probed, ConfigGeneration: a.config.generation}
	now := a.now()
	for owner := range a.owners {
		if owner.cleanupFailed || (!owner.waited && !now.Before(owner.deadline)) {
			status.CleanupPending++
			status.Ready = false
		}
	}
	return status
}

type invocation struct {
	directory  string
	command    string
	args       []string
	config     *configuration
	startGuard func(context.Context) (func() error, error)
}

func (a *Adapter) run(ctx context.Context, call invocation) (cliResponse, error) {
	if ctx.Err() != nil {
		return cliResponse{}, ErrPending
	}
	limit := MaxStdoutBytes
	if call.config.ProjectStore != nil {
		limit = MaxWorkspaceStdoutBytes
	}
	stdout := &boundedOutput{limit: limit}
	stderr := &boundedOutput{limit: MaxStderrBytes}
	command := exec.Command(call.config.Executable, call.args...)
	command.Dir = call.directory
	command.Env = cliEnvironment(os.Environ(), call.directory)
	command.Stdout = stdout
	command.Stderr = stderr
	release, guardErr := acquireStartGuard(ctx, call)
	if guardErr != nil {
		return cliResponse{}, guardErr
	}
	// Start is the generation linearization point. Reload cannot change pins or
	// ceilings between this check and starting the locally owned CLI process.
	a.mu.RLock()
	if a.config.generation != call.config.generation {
		a.mu.RUnlock()
		return cliResponse{}, errors.Join(ErrConflict, release())
	}
	if ctx.Err() != nil {
		a.mu.RUnlock()
		return cliResponse{}, errors.Join(ErrPending, release())
	}
	startErr := command.Start()
	a.mu.RUnlock()
	unlockErr := release()
	if startErr != nil {
		return cliResponse{}, errors.Join(ErrEvidence, unlockErr)
	}
	// No CommandContext/WaitDelay: observation expiry cannot kill this accepted
	// control or release its permit while process/output copier ownership remains.
	waitErr := command.Wait()
	if unlockErr != nil {
		// The accepted command has still been joined exactly once. Reporting
		// uncertainty must never cause another Start with this invocation.
		return cliResponse{}, errors.Join(ErrPending, unlockErr)
	}
	if stdout.overflow || stderr.overflow {
		return cliResponse{}, ErrCapacity
	}
	response, err := decodeResponse(stdout.data, call.command, limit)
	if err != nil {
		return cliResponse{}, err
	}
	if waitErr != nil {
		var exit *exec.ExitError
		if !errors.As(waitErr, &exit) {
			return cliResponse{}, ErrPending
		}
		response.exitCode = exit.ExitCode()
	}
	return response, nil
}

func acquireStartGuard(ctx context.Context, call invocation) (func() error, error) {
	if call.startGuard == nil {
		return func() error { return nil }, nil
	}
	return call.startGuard(ctx)
}

func (a *Adapter) begin(ctx context.Context, cfg *configuration) (*controlOwner, error) {
	if ctx.Err() != nil {
		return nil, ErrPending
	}
	dir, err := os.MkdirTemp(cfg.TemporaryDirectory, "gateway-control-")
	if err != nil {
		return nil, ErrCapacity
	}
	deadline := a.now().Add(cfg.ControlTimeout)
	if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
		deadline = caller
	}
	owner := &controlOwner{deadline: deadline, temporary: dir}
	a.mu.Lock()
	a.owners[owner] = struct{}{}
	a.mu.Unlock()
	return owner, nil
}

func (o *controlOwner) file(name string, data []byte) (string, error) {
	path := filepath.Join(o.temporary, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", ErrCapacity
	}
	o.files = append(o.files, path)
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if errors.Join(writeErr, closeErr) != nil {
		return "", ErrCapacity
	}
	return path, nil
}

func (a *Adapter) settle(owner *controlOwner, held permit) error {
	// Reaching settle means every exec Start has returned from Wait, including
	// os/exec-owned stdout/stderr copy goroutines. Only known owned paths go away.
	a.mu.Lock()
	owner.waited = true
	a.mu.Unlock()
	if err := cleanup(owner); err != nil {
		a.mu.Lock()
		owner.cleanupFailed = true
		owner.held = held
		a.mu.Unlock()
		return ErrPending
	}
	a.mu.Lock()
	delete(a.owners, owner)
	a.mu.Unlock()
	held.release()
	return nil
}

// RetryCleanup only retries known temporary-file cleanup after Wait completed.
// It never frees a running process, guesses helper closure or deletes strangers.
func (a *Adapter) RetryCleanup() error {
	a.mu.Lock()
	var selected []*controlOwner
	for owner := range a.owners {
		if owner.waited && owner.cleanupFailed && !owner.cleanupBusy {
			owner.cleanupBusy = true
			selected = append(selected, owner)
		}
	}
	a.mu.Unlock()
	for _, owner := range selected {
		err := cleanup(owner)
		a.mu.Lock()
		owner.cleanupBusy = false
		if err == nil {
			delete(a.owners, owner)
			owner.held.release()
		}
		a.mu.Unlock()
	}
	if a.Status().CleanupPending != 0 {
		return ErrPending
	}
	return nil
}

func cleanup(owner *controlOwner) error {
	var failures []error
	for _, path := range owner.files {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		return ErrPending
	}
	if err := os.Remove(owner.temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrPending
	}
	return nil
}

// Ensure the bounded sink's contract remains compatible with exec's joining I/O.
var _ io.Writer = (*boundedOutput)(nil)

// Explicit argv is the sole Delegate-root selector. Keep the account/provider
// environment, but prevent inherited root/PWD from changing local resolution.
func cliEnvironment(inherited []string, directory string) []string {
	result := make([]string, 0, len(inherited)+1)
	for _, entry := range inherited {
		if strings.HasPrefix(entry, "DELEGATE_ROOT=") || strings.HasPrefix(entry, "PWD=") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "PWD="+directory)
}
