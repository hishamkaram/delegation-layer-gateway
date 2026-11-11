// Package server owns Gateway network composition and resource lifetimes.
// Registry remains the durable authority; Delegate owns execution and outcomes.
package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/httpsserver"
	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

var ErrUnavailable = errors.New("gateway_server_unavailable")

type failure struct{ cause error }

func (f failure) Error() string   { return ErrUnavailable.Error() }
func (f failure) Unwrap() []error { return []error{ErrUnavailable, f.cause} }
func failed(cause error) error    { return failure{cause: cause} }

type (
	// Options retains no ownership of JWKSClient. Injected clock and transport
	// must support concurrent requests. A nil clock/client selects owned defaults.
	Options struct {
		Now        func() time.Time
		JWKSClient *http.Client
	}
	Addresses struct {
		Public string
		Device string
		Admin  string
	}
	Runtime struct {
		gatewayID       domain.GatewayID
		controlTimeout  time.Duration
		now             func() time.Time
		lifetime        context.Context
		cancel          context.CancelFunc
		addresses       Addresses
		lease           *instance.Lease
		audit           *observability.Audit
		metrics         observability.Metrics
		recorder        *observability.Recorder
		store           *registry.Store
		hub             *transport.Hub
		enrollment      *enrollment.Service
		public, device  *httpsserver.Server
		admin           *adminapi.Server
		ownJWKS         *http.Transport
		mu              sync.Mutex
		started, closed bool
		workers         sync.WaitGroup
		serveErrors     chan error
		closeOnce       sync.Once
		closeError      error
	}
)

func (r *Runtime) Addresses() Addresses          { return r.addresses }
func (r *Runtime) MetadataMetrics() http.Handler { return &r.metrics }
func (r *Runtime) Health() observability.Health  { return r.recorder.Health() }
