package deviceclient

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceruntime"
)

var (
	ErrRuntimeStarted = errors.New("gateway_runtime_already_started")
	ErrRuntimeClosed  = errors.New("gateway_runtime_closed")
)

// Runtime owns one identity lease and one invocation of the existing device
// runtime. Delegate remains the execution/closure authority. Close joins Serve
// before releasing identity; it does not cancel accepted Delegate tasks.
type Runtime struct {
	mu            sync.Mutex
	identity      *deviceidentity.Store
	configuration runtimeConfiguration
	started       bool
	closing       bool
	serveDone     chan struct{}
	closeDone     chan struct{}
	cancel        context.CancelFunc
	serveErr      error
	closeErr      error
}

func (*Runtime) String() string     { return "gateway_runtime" }
func (r *Runtime) GoString() string { return r.String() }

// OpenRuntime validates only saved local source/trust/credential data and owns
// the identity lease. It performs no network request, OAuth or Native CLI call.
func OpenRuntime(ctx context.Context, directory string) (runtime *Runtime, result error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, failed(ErrTransport, err)
	}
	selected, err := readRuntimeProfile(directory)
	if err != nil {
		return nil, err
	}
	cfg, err := newRuntimeConfiguration(directory, selected)
	if err != nil {
		return nil, err
	}
	identity, err := openExistingIdentity(directory)
	if err != nil {
		return nil, err
	}

	defer func() {
		if runtime == nil {
			result = errors.Join(result, failedClose(identity.Close()))
		}
	}()
	if err = enrolledLocalIdentity(identity); err != nil {
		return nil, err
	}
	intent, err := identity.EnrollmentIntent()
	if err != nil {
		return nil, failed(ErrProfile, err)
	}
	if intent.Plan.GatewayID != selected.Descriptor.GatewayID || intent.Plan.Name != selected.DeviceName {
		return nil, ErrConflict
	}
	roots, err := cfg.DeviceRoots()
	if err != nil {
		return nil, err
	}
	_, ref, err := identity.Certificate(roots, time.Now())
	if err != nil {
		return nil, failed(ErrEnrollment, err)
	}
	cfg.deviceID = ref.Device
	if err = ctx.Err(); err != nil {
		return nil, failed(ErrTransport, err)
	}
	return &Runtime{identity: identity, configuration: cfg, serveDone: make(chan struct{}), closeDone: make(chan struct{})}, nil
}

func failedClose(err error) error {
	if err == nil {
		return nil
	}
	return failed(ErrPersistence, err)
}

func readRuntimeProfile(directory string) (selected profile, result error) {
	store, err := openProfile(directory, false, false)
	if err != nil {
		return selected, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrProfile, closeErr))
		}
	}()
	if store.value == nil {
		return selected, ErrProfile
	}
	return *store.value, nil
}

// Serve runs once. Connection/startup failures are returned to this caller;
// reconnect, renewal and CLI cleanup remain owned by deviceruntime.RunConfigured.
func (r *Runtime) Serve(ctx context.Context) (result error) {
	if r == nil || ctx == nil {
		return ErrConfiguration
	}
	r.mu.Lock()
	if r.identity == nil || r.serveDone == nil || r.closeDone == nil {
		r.mu.Unlock()
		return ErrConfiguration
	}
	if r.closing {
		r.mu.Unlock()
		return ErrRuntimeClosed
	}
	if r.started {
		r.mu.Unlock()
		return ErrRuntimeStarted
	}
	r.started = true
	runContext, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.mu.Unlock()
	defer func() { cancel(); r.mu.Lock(); r.serveErr = result; close(r.serveDone); r.mu.Unlock() }()
	if err := deviceruntime.RunConfigured(runContext, &r.configuration, r.identity); err != nil {
		if runContext.Err() != nil && deviceruntime.IsExpectedCancellation(err) {
			return expectedRuntimeStop{cause: runContext.Err()}
		}
		kind := ErrTransport
		if errors.Is(err, deviceruntime.ErrConfiguration) {
			kind = ErrConfiguration
		}
		return failed(kind, err)
	}
	return nil
}

type expectedRuntimeStop struct{ cause error }

func (expectedRuntimeStop) Error() string         { return "gateway_runtime_stopped" }
func (e expectedRuntimeStop) Unwrap() error       { return e.cause }
func (expectedRuntimeStop) qualifiedRuntimeStop() {}

// IsExpectedShutdown is for a caller that has invoked Serve then Close. True
// requires the SDK's direct qualified cancellation result and a clean Close:
// SDK/CLI control owners joined and identity close succeeded. It proves neither
// Delegate provider-task closure nor a successful Gateway connection. Wrapping
// or joining another failure to the qualified result cannot establish success.
func IsExpectedShutdown(serveErr, closeErr error) bool {
	if closeErr != nil {
		return false
	}
	_, qualified := serveErr.(interface{ qualifiedRuntimeStop() })
	return qualified
}

// Close stops observation and joins Serve/its CLI owners before identity close.
// It reports cleanup evidence and preserves close errors across repeated calls.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.identity == nil || r.serveDone == nil || r.closeDone == nil {
		r.mu.Unlock()
		return ErrConfiguration
	}
	if r.closing {
		done := r.closeDone
		r.mu.Unlock()
		<-done
		r.mu.Lock()
		err := r.closeErr
		r.mu.Unlock()
		return err
	}
	r.closing = true
	started, cancel := r.started, r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if started {
		<-r.serveDone
	}
	result := failedClose(r.identity.Close())
	r.mu.Lock()
	if errors.Is(r.serveErr, deviceruntime.ErrCleanup) {
		result = errors.Join(result, failed(ErrPersistence, r.serveErr))
	}
	r.closeErr = result
	close(r.closeDone)
	r.mu.Unlock()
	return result
}
