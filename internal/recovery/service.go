package recovery

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type Store interface {
	exchangeStore
	namespaceStore
}

type namespaceStore interface {
	PrepareRecoveryBarrier(context.Context, domain.BarrierPreparation) (domain.BarrierPlan, error)
	CheckReopen(context.Context, domain.ReopenCheck) error
}

type Service struct {
	store   namespaceStore
	wire    *client
	gateway domain.GatewayID
}

func New(store Store, link gateway.Link, id domain.GatewayID, now func() time.Time, observer gateway.RoutingObserver) (*Service, error) {
	if store == nil || link == nil || domain.Token(string(id)) != nil || now == nil || observer == nil {
		return nil, domain.ErrInvalid
	}
	return &Service{store: store, wire: defaultClient(store, link, now, observer), gateway: id}, nil
}

// Inspect reads current Delegate namespace state, never the advertised cache.
func (s *Service) Inspect(ctx context.Context, route domain.Destination, expected domain.ContextBinding) (protocol.ProjectCapability, domain.Transmission, error) {
	body, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(s.gateway)}, protocol.MaxFrameBytes)
	if err != nil || expected.Validate() != nil {
		return protocol.ProjectCapability{}, domain.Transmission{}, domain.ErrInvalid
	}
	var report protocol.ProjectCapability
	_, tx, err := s.wire.exchange(ctx, route, protocol.Command{Operation: protocol.ContextInspect, Project: string(route.Project), Body: body}, func(context.Context, domain.Transmission) error { return nil }, func(reply protocol.Reply, _ domain.Transmission) error {
		var candidate protocol.ProjectCapability
		if protocol.DecodeStrict(reply.Body, &candidate, protocol.MaxFrameBytes) != nil || candidate.Validate() != nil || candidate.Alias != string(route.Project) || candidate.Context.Root != string(expected.Root) || candidate.Context.Project != string(expected.Project) {
			return domain.Reject(domain.EvidenceInvalid)
		}
		if candidate.ContractVersion != protocol.Version || !protocol.NativeFeaturesCompatible(candidate.Features) {
			return domain.Reject(domain.EvidenceInvalid)
		}
		report = candidate
		return nil
	})
	if err != nil {
		return protocol.ProjectCapability{}, tx, err
	}
	return report, tx, nil
}

// InspectRoot verifies namespace state without attesting a live project. Saved
// task evidence and root recovery remain available after project removal.
func (s *Service) InspectRoot(ctx context.Context, route domain.Destination, expected domain.RootGuard) (protocol.RootCapability, domain.Transmission, error) {
	return s.inspectRoot(ctx, controlRoute{project: &route}, expected)
}

func (s *Service) inspectRoot(ctx context.Context, route controlRoute, expected domain.RootGuard) (protocol.RootCapability, domain.Transmission, error) {
	body, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(s.gateway), RootOnly: true}, protocol.MaxFrameBytes)
	if err != nil || domain.ContextToken(string(expected)) != nil {
		return protocol.RootCapability{}, domain.Transmission{}, domain.ErrInvalid
	}
	var report protocol.RootCapability
	_, tx, err := s.wire.exchangeRoute(ctx, route, route.command(protocol.ContextInspect, body), func(context.Context, domain.Transmission) error { return nil }, func(reply protocol.Reply, _ domain.Transmission) error {
		var candidate protocol.RootCapability
		if protocol.DecodeStrict(reply.Body, &candidate, protocol.MaxFrameBytes) != nil || candidate.Validate() != nil || candidate.Root != string(expected) || (candidate.Origin != nil && candidate.Origin.GatewayID != string(s.gateway)) {
			return domain.Reject(domain.EvidenceInvalid)
		}
		report = candidate
		return nil
	})
	if err != nil {
		return protocol.RootCapability{}, tx, err
	}
	return report, tx, nil
}

// Barrier persists the expected and replacement generations before any send.
// Its queued guard accepts only the same durable plan and live connection.
func (s *Service) Barrier(ctx context.Context, route domain.Destination, input domain.BarrierPreparation) (protocol.OriginStateReport, error) {
	return s.barrier(ctx, controlRoute{project: &route}, input)
}

func (s *Service) barrier(ctx context.Context, route controlRoute, input domain.BarrierPreparation) (protocol.OriginStateReport, error) {
	if route.validate() != nil || route.device() != input.Destination.Device {
		return protocol.OriginStateReport{}, domain.ErrInvalid
	}
	plan, err := s.store.PrepareRecoveryBarrier(ctx, input)
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	body, err := protocol.Encode(protocol.OriginBarrierRequest{GatewayID: string(s.gateway), RecoveryID: string(plan.Destination.Recovery), ExpectedGeneration: string(plan.ExpectedGeneration), Generation: string(plan.Generation), ExpectedRoot: string(plan.Destination.Root)}, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	var report protocol.OriginStateReport
	_, _, err = s.wire.exchangeRoute(ctx, route, route.command(protocol.OriginBarrier, body), func(call context.Context, tx domain.Transmission) error {
		if tx.Credential != input.Credential || tx.Connection != input.Connection {
			return domain.Reject(domain.Conflict)
		}
		check := input
		check.Now = tx.Now
		current, checkErr := s.store.PrepareRecoveryBarrier(call, check)
		if checkErr != nil {
			return checkErr
		}
		if current != plan {
			return domain.Reject(domain.Conflict)
		}
		return nil
	}, func(reply protocol.Reply, _ domain.Transmission) error {
		var acceptErr error
		report, acceptErr = originReply(reply, s.gateway, plan.Destination.Recovery, plan.Generation, false)
		return acceptErr
	})
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	return report, nil
}

// Reopen cannot bypass Registry approval: every send rechecks its revision,
// complete inventory receipt and exact authenticated destination.
func (s *Service) Reopen(ctx context.Context, route domain.Destination, expectedRoot domain.RootGuard, target domain.ReopenTarget) (protocol.OriginStateReport, error) {
	return s.reopen(ctx, controlRoute{project: &route}, expectedRoot, target)
}

func (s *Service) reopen(ctx context.Context, route controlRoute, expectedRoot domain.RootGuard, target domain.ReopenTarget) (protocol.OriginStateReport, error) {
	if route.validate() != nil || route.device() != target.Destination.Device || domain.ContextToken(string(expectedRoot)) != nil || expectedRoot != target.Destination.Root {
		return protocol.OriginStateReport{}, domain.ErrInvalid
	}
	body, err := protocol.Encode(protocol.OriginReopenRequest{GatewayID: string(s.gateway), RecoveryID: string(target.Destination.Recovery), Generation: string(target.Generation), CompletenessReceipt: hex.EncodeToString(target.Completeness[:]), ExpectedRoot: string(target.Destination.Root)}, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	var reopened protocol.OriginStateReport
	_, _, err = s.wire.exchangeRoute(ctx, route, route.command(protocol.OriginReopen, body), func(call context.Context, tx domain.Transmission) error {
		return s.store.CheckReopen(call, domain.ReopenCheck{Target: target, Credential: tx.Credential, Connection: tx.Connection, Now: tx.Now})
	}, func(reply protocol.Reply, _ domain.Transmission) error {
		var acceptErr error
		reopened, acceptErr = originReply(reply, s.gateway, target.Destination.Recovery, target.Generation, true)
		return acceptErr
	})
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	// Only root namespace evidence is needed here. Project availability and
	// execution readiness are separate, including when every workspace is gone.
	current, _, err := s.inspectRoot(ctx, route, expectedRoot)
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	if current.Origin == nil || !current.Origin.AdmissionOpen || current.Origin.Generation != string(target.Generation) || current.Origin.RecoveryID != string(target.Destination.Recovery) {
		return protocol.OriginStateReport{}, domain.Reject(domain.Conflict)
	}
	return reopened, nil
}

func originReply(reply protocol.Reply, gatewayID domain.GatewayID, recoveryID domain.RecoveryID, generation domain.AdmissionGeneration, open bool) (protocol.OriginStateReport, error) {
	var report protocol.OriginStateReport
	if protocol.DecodeStrict(reply.Body, &report, protocol.MaxFrameBytes) != nil || report.Validate() != nil || report.GatewayID != string(gatewayID) || report.RecoveryID != string(recoveryID) || report.Generation != string(generation) || report.AdmissionOpen != open {
		return protocol.OriginStateReport{}, domain.Reject(domain.EvidenceInvalid)
	}
	return report, nil
}

// Inventory reads one root-wide canonical page. Receipt application remains a
// separate Registry transaction; no wire success establishes task ownership.
func (s *Service) Inventory(ctx context.Context, route domain.Destination, plan domain.BarrierPlan, cursor string) (protocol.OriginInventoryReport, error) {
	report, _, err := s.inventory(ctx, route, plan, cursor)
	return report, err
}

func (s *Service) inventory(ctx context.Context, route domain.Destination, plan domain.BarrierPlan, cursor string) (protocol.OriginInventoryReport, domain.Transmission, error) {
	return s.inventoryRoute(ctx, controlRoute{project: &route}, plan, cursor)
}

func (s *Service) inventoryRoute(ctx context.Context, route controlRoute, plan domain.BarrierPlan, cursor string) (protocol.OriginInventoryReport, domain.Transmission, error) {
	if route.validate() != nil || route.device() != plan.Destination.Device {
		return protocol.OriginInventoryReport{}, domain.Transmission{}, domain.ErrInvalid
	}
	request := protocol.OriginInventoryRequest{GatewayID: string(s.gateway), Generation: string(plan.Generation), Cursor: cursor, Limit: domain.MaxPageLimit, ExpectedRoot: string(plan.Destination.Root)}
	body, err := protocol.Encode(request, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.OriginInventoryReport{}, domain.Transmission{}, err
	}
	var report protocol.OriginInventoryReport
	_, transmission, err := s.wire.exchangeRoute(ctx, route, route.command(protocol.OriginInventory, body), func(call context.Context, tx domain.Transmission) error {
		current, checkErr := s.store.PrepareRecoveryBarrier(call, domain.BarrierPreparation{Destination: plan.Destination, Credential: tx.Credential, Connection: tx.Connection, ExpectedGeneration: plan.ExpectedGeneration, Now: tx.Now})
		if checkErr != nil {
			return checkErr
		}
		if current != plan {
			return domain.Reject(domain.Conflict)
		}
		return nil
	}, func(reply protocol.Reply, _ domain.Transmission) error {
		var candidate protocol.OriginInventoryReport
		if protocol.DecodeStrict(reply.Body, &candidate, protocol.MaxFrameBytes) != nil || candidate.ValidateFor(request) != nil {
			return domain.Reject(domain.EvidenceInvalid)
		}
		report = candidate
		return nil
	})
	if err != nil {
		return protocol.OriginInventoryReport{}, transmission, err
	}
	return report, transmission, nil
}
