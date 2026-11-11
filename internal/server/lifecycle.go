package server

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
)

// Serve coordinates owned child servers without adding itself to their join
// group. Child results are buffered before Done, so Close cannot wait on itself.
func (r *Runtime) Serve(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	r.mu.Lock()
	if r.started || r.closed {
		r.mu.Unlock()
		return ErrUnavailable
	}
	r.started = true
	workers := []func(context.Context) error{r.public.Serve, r.device.Serve, r.admin.Serve}
	for range 4 {
		workers = append(workers, r.renewals)
	}
	for _, serve := range workers {
		r.workers.Add(1)
		go func() {
			defer r.workers.Done()
			serveErr := serve(r.lifetime)
			// Each concrete Close reports its cleanup errors independently. A child
			// losing startup to intentional lifetime cancellation is expected.
			if r.lifetime.Err() != nil {
				serveErr = nil
			}
			r.serveErrors <- serveErr
		}()
	}
	r.mu.Unlock()
	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case <-r.lifetime.Done():
		result = r.lifetime.Err()
	case result = <-r.serveErrors:
		if result == nil {
			result = ErrUnavailable
		}
	}
	return failed(errors.Join(result, r.Close()))
}

// Close stops hijacked WSS owners before HTTP closure, joins all handlers and
// renewal workers, closes persistence, then releases instance leases last.
func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		started := r.started
		r.mu.Unlock()
		if r.recorder != nil {
			r.recorder.Record(observability.Event{Code: observability.ShutdownStarted})
		}
		r.cancel()
		failures := r.closeNetwork(started)
		failures = append(failures, r.joinWorkers()...)
		if r.store != nil {
			failures = append(failures, r.store.Close())
		}
		if r.audit != nil {
			failures = append(failures, r.audit.Close())
		}
		if r.ownJWKS != nil {
			r.ownJWKS.CloseIdleConnections()
		}
		if r.lease != nil {
			failures = append(failures, r.lease.Close())
		}
		if err := errors.Join(failures...); err != nil {
			r.closeError = failed(err)
		}
	})
	return r.closeError
}

func (r *Runtime) joinWorkers() []error {
	r.workers.Wait()
	var failures []error
	for {
		select {
		case err := <-r.serveErrors:
			failures = append(failures, err)
		default:
			return failures
		}
	}
}

func (r *Runtime) closeNetwork(started bool) []error {
	var failures []error
	// Running WSS owners must join before their HTTP handlers. During partial
	// construction no reader exists, so unwind listener dependencies in reverse.
	if started && r.hub != nil {
		failures = append(failures, r.hub.Close())
	}
	if r.admin != nil {
		failures = append(failures, r.admin.Close())
	}
	if r.device != nil {
		failures = append(failures, r.device.Close())
	}
	if r.public != nil {
		failures = append(failures, r.public.Close())
	}
	if !started && r.hub != nil {
		failures = append(failures, r.hub.Close())
	}
	return failures
}
