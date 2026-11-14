// Package workspaces coordinates explicit device-local pinning and dated
// workspace metadata. Native owns filesystem policy and immutable pins;
// Registry owns correlation/routes; no task is launched or supervised here.
package workspaces

import (
	"context"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type Store interface {
	AuthorizeOwnedDevice(context.Context, domain.OwnedDeviceRequest) (domain.OwnedDeviceAuthorization, error)
	LookupProjectResolution(context.Context, domain.Actor, domain.DeviceID, domain.ResolutionID) (domain.ProjectResolution, bool, error)
	BeginProjectResolution(context.Context, domain.Actor, domain.ProjectResolutionStart) (domain.ProjectResolution, error)
	RecordProjectResolutionPin(context.Context, domain.Actor, domain.ProjectResolutionPin) (domain.ProjectResolution, error)
	RegisterResolvedProject(context.Context, domain.Actor, domain.ProjectResolutionCheck) (domain.ProjectResolution, error)
	GetResolvedProject(context.Context, domain.Actor, domain.Destination, domain.Scope) (domain.ProjectPin, error)
	CheckResolvedProject(context.Context, domain.Actor, domain.ProjectResolutionPin, domain.Scope) error
	CheckProjectResolution(context.Context, domain.Actor, domain.ProjectResolutionCheck, domain.Scope) error
	AcquireProjectMetadata(context.Context, domain.Actor, domain.ResolutionID, domain.Scope, routing.Request) error
}
type (
	Presence interface {
		Snapshot(domain.DeviceID) (gateway.LinkSnapshot, error)
	}
	Controls interface {
		Exchange(context.Context, gateway.MetadataCall) (protocol.Reply, domain.Transmission, error)
		ObserveAuthorizationFailure(domain.Actor, protocol.Operation, error)
	}
	Initializer interface {
		Advance(context.Context) (domain.RootInitializationProgress, error)
	}
	RootFactory func(context.Context, domain.OwnedRootBinding) (Initializer, error)
)

type Options struct {
	Store     Store
	Presence  Presence
	Controls  Controls
	Roots     RootFactory
	GatewayID domain.GatewayID
	Now       func() time.Time
}
type Service struct{ options Options }

func New(options Options) (*Service, error) {
	if options.Store == nil || options.Presence == nil || options.Controls == nil || options.Roots == nil || options.Now == nil || domain.Token(string(options.GatewayID)) != nil {
		return nil, domain.ErrInvalid
	}
	return &Service{options: options}, nil
}

type Inventory struct {
	Device        domain.DeviceID
	Online        bool
	DelegateReady bool
	ObservedAt    time.Time
	Workspaces    []protocol.WorkspaceCapability
	ProjectBudget *protocol.ProjectBudget
}

type (
	ResolveInput struct {
		Device  domain.DeviceID
		Request protocol.ResolveProjectRequest
	}
	Resolution struct {
		Device  domain.DeviceID
		Request domain.ResolutionID
		Project domain.ProjectPin
	}
)

func (s *Service) authorize(ctx context.Context, actor domain.Actor, device domain.DeviceID, scope domain.Scope) error {
	_, err := s.options.Store.AuthorizeOwnedDevice(ctx, domain.OwnedDeviceRequest{Actor: actor, Device: device, Scope: scope})
	return err
}

func (s *Service) snapshot(device domain.DeviceID) (gateway.LinkSnapshot, error) {
	snapshot, err := s.options.Presence.Snapshot(device)
	if err != nil {
		return snapshot, err
	}
	if snapshot.Credential.Device != device || snapshot.Credential.Validate() != nil || snapshot.Connection.Validate() != nil || snapshot.ObservedAt.IsZero() {
		return gateway.LinkSnapshot{}, domain.Reject(domain.EvidenceInvalid)
	}
	if snapshot.WireVersion != protocol.WireVersion2 {
		return gateway.LinkSnapshot{}, &gateway.RemoteError{Failure: protocol.Failure{Code: "incompatible_delegate"}}
	}
	if snapshot.CapabilitiesV2 == nil || snapshot.CapabilitiesV2.Validate() != nil {
		return gateway.LinkSnapshot{}, domain.Reject(domain.EvidenceInvalid)
	}
	return snapshot, nil
}

func binding(snapshot gateway.LinkSnapshot, root domain.RootGuard) domain.OwnedRootBinding {
	return domain.OwnedRootBinding{Route: domain.RootRoute{Device: snapshot.Credential.Device, Root: root}, Credential: snapshot.Credential, Connection: snapshot.Connection}
}

func (s *Service) check(ctx context.Context, actor domain.Actor, id domain.ResolutionID, root domain.RootGuard, tx domain.Transmission, scope domain.Scope) error {
	current, err := s.liveBinding(root, tx)
	if err != nil {
		return err
	}
	return s.options.Store.CheckProjectResolution(ctx, actor, domain.ProjectResolutionCheck{Request: id, Binding: current, Now: s.options.Now()}, scope)
}

func (s *Service) liveBinding(root domain.RootGuard, tx domain.Transmission) (domain.OwnedRootBinding, error) {
	snapshot, err := s.snapshot(tx.Credential.Device)
	if err != nil {
		return domain.OwnedRootBinding{}, err
	}
	if snapshot.Credential != tx.Credential || snapshot.Connection != tx.Connection || snapshot.CapabilitiesV2.Root == nil || snapshot.CapabilitiesV2.Root.Root != string(root) {
		return domain.OwnedRootBinding{}, domain.Reject(domain.Conflict)
	}
	return binding(snapshot, root), nil
}
