package recovery

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// OwnedRootStore exposes only root initialization bound to a current owner
// connection. It has no administrative authorization or task mutation method.
type OwnedRootStore interface {
	initializationStore
	controlStore
	namespaceStore
	CheckOwnedRoot(context.Context) error
	OwnerPrincipal() domain.PrincipalID
	Binding() domain.OwnedRootBinding
}

type OwnedInitializer struct {
	phases *Initializer
	lookup domain.RootInitializationLookup
}

func NewOwnedInitializer(store OwnedRootStore, link gateway.Link, id domain.GatewayID, now func() time.Time, observer gateway.RoutingObserver) (*OwnedInitializer, error) {
	if store == nil || link == nil || domain.Token(string(id)) != nil || now == nil || observer == nil {
		return nil, domain.ErrInvalid
	}
	binding := store.Binding()
	if binding.Validate() != nil || domain.Token(string(store.OwnerPrincipal())) != nil {
		return nil, domain.ErrInvalid
	}
	check := func(ctx context.Context, tx domain.Transmission) (routing.AuthorizationDecision, time.Time, error) {
		when := now()
		_, err := store.CheckConnection(ctx, tx.Credential, tx.Connection, when)
		return gateway.AuthorizationObservation(err), when, err
	}
	wire := &client{store: store, authorize: store.CheckOwnedRoot, authorizeConnection: check, principal: store.OwnerPrincipal(), link: link, now: now, random: rand.Reader, observer: observer}
	service := &Service{store: store, wire: wire, gateway: id}
	root := binding.Route
	lookup := domain.RootInitializationLookup{RootRoute: &root}
	return &OwnedInitializer{phases: &Initializer{store: store, namespace: rootInitialization{service}, now: now}, lookup: lookup}, nil
}

// Advance performs at most one existing durable phase, with no caller-supplied
// route override, new task identity or background supervision.
func (i *OwnedInitializer) Advance(ctx context.Context) (domain.RootInitializationProgress, error) {
	return i.phases.Advance(ctx, i.lookup)
}

func (i *OwnedInitializer) Progress(ctx context.Context) (domain.RootInitializationProgress, error) {
	return i.phases.Progress(ctx, i.lookup)
}
