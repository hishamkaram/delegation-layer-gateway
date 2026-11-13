package adminapi

import (
	"context"
	"sync"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type (
	authorityMarker struct{ valid bool }
	privateKey      struct{}
	privateProof    struct {
		marker *authorityMarker
		gate   *requestGate
	}
)

// Authorizer checks an instance-bound marker that only this package's Unix
// server can create. Its zero value, task scopes and public contexts deny access.
type Authorizer struct{ marker *authorityMarker }

func NewAuthorizer() *Authorizer { return &Authorizer{marker: &authorityMarker{valid: true}} }
func (a *Authorizer) AuthorizeAdmin(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	proof, ok := ctx.Value(privateKey{}).(privateProof)
	if a == nil || a.marker == nil || !a.marker.valid || !ok || proof.marker != a.marker || proof.gate == nil {
		return domain.Reject(domain.Forbidden)
	}
	return nil
}

type requestGate struct {
	mu      sync.Mutex
	closed  bool
	active  int
	pending sync.WaitGroup
}

func (g *requestGate) begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.active >= 32 {
		return false
	}
	g.active++
	g.pending.Add(1)
	return true
}
func (g *requestGate) end()  { g.mu.Lock(); g.active--; g.mu.Unlock(); g.pending.Done() }
func (g *requestGate) stop() { g.mu.Lock(); g.closed = true; g.mu.Unlock() }
