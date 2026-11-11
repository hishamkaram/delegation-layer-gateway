package recovery

import (
	"context"
	"encoding/hex"
	"slices"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type Store interface {
	exchangeStore
	PrepareRecoveryBarrier(context.Context, domain.BarrierPreparation) (domain.BarrierPlan, error)
	CheckReopen(context.Context, domain.ReopenCheck) error
}

type Service struct {
	store   Store
	wire    *client
	gateway domain.GatewayID
}

func New(store Store, link gateway.Link, id domain.GatewayID, now func() time.Time) (*Service, error) {
	if store == nil || link == nil || domain.Token(string(id)) != nil || now == nil {
		return nil, domain.ErrInvalid
	}
	return &Service{store: store, wire: defaultClient(store, link, now), gateway: id}, nil
}

// Inspect reads current Delegate namespace state, never the advertised cache.
func (s *Service) Inspect(ctx context.Context, route domain.Destination, expected domain.ContextBinding) (protocol.ProjectCapability, domain.Transmission, error) {
	body, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(s.gateway)}, protocol.MaxFrameBytes)
	if err != nil || expected.Validate() != nil {
		return protocol.ProjectCapability{}, domain.Transmission{}, domain.ErrInvalid
	}
	reply, tx, err := s.wire.exchange(ctx, route, protocol.Command{Operation: protocol.ContextInspect, Project: string(route.Project), Body: body}, func(context.Context, domain.Transmission) error { return nil })
	if err != nil {
		return protocol.ProjectCapability{}, tx, err
	}
	var report protocol.ProjectCapability
	if protocol.DecodeStrict(reply.Body, &report, protocol.MaxFrameBytes) != nil || report.Validate() != nil || report.Alias != string(route.Project) || report.Context.Root != string(expected.Root) || report.Context.Project != string(expected.Project) {
		return protocol.ProjectCapability{}, tx, domain.Reject(domain.EvidenceInvalid)
	}
	if report.ContractVersion != protocol.Version || !slices.Contains(report.Features, "namespace-admission-v1") {
		return protocol.ProjectCapability{}, tx, domain.Reject(domain.EvidenceInvalid)
	}
	return report, tx, nil
}

// InspectRoot verifies namespace state without attesting a live project. Saved
// task evidence and root recovery remain available after project removal.
func (s *Service) InspectRoot(ctx context.Context, route domain.Destination, expected domain.RootGuard) (protocol.RootCapability, domain.Transmission, error) {
	body, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(s.gateway), RootOnly: true}, protocol.MaxFrameBytes)
	if err != nil || domain.ContextToken(string(expected)) != nil {
		return protocol.RootCapability{}, domain.Transmission{}, domain.ErrInvalid
	}
	reply, tx, err := s.wire.exchange(ctx, route, protocol.Command{Operation: protocol.ContextInspect, Project: string(route.Project), Body: body}, func(context.Context, domain.Transmission) error { return nil })
	if err != nil {
		return protocol.RootCapability{}, tx, err
	}
	var report protocol.RootCapability
	if protocol.DecodeStrict(reply.Body, &report, protocol.MaxFrameBytes) != nil || report.Validate() != nil || report.Root != string(expected) || (report.Origin != nil && report.Origin.GatewayID != string(s.gateway)) {
		return protocol.RootCapability{}, tx, domain.Reject(domain.EvidenceInvalid)
	}
	return report, tx, nil
}

// Barrier persists the expected and replacement generations before any send.
// Its queued guard accepts only the same durable plan and live connection.
func (s *Service) Barrier(ctx context.Context, route domain.Destination, input domain.BarrierPreparation) (protocol.OriginStateReport, error) {
	if route.Device != input.Destination.Device || route.Validate() != nil {
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
	reply, _, err := s.wire.exchange(ctx, route, protocol.Command{Operation: protocol.OriginBarrier, Project: string(route.Project), Body: body}, func(call context.Context, tx domain.Transmission) error {
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
	})
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	return originReply(reply, s.gateway, plan.Destination.Recovery, plan.Generation, false)
}

// Reopen cannot bypass Registry approval: every send rechecks its revision,
// complete inventory receipt and exact authenticated destination.
func (s *Service) Reopen(ctx context.Context, route domain.Destination, expectedRoot domain.RootGuard, target domain.ReopenTarget) (protocol.OriginStateReport, error) {
	if route.Validate() != nil || route.Device != target.Destination.Device || domain.ContextToken(string(expectedRoot)) != nil || expectedRoot != target.Destination.Root {
		return protocol.OriginStateReport{}, domain.ErrInvalid
	}
	body, err := protocol.Encode(protocol.OriginReopenRequest{GatewayID: string(s.gateway), RecoveryID: string(target.Destination.Recovery), Generation: string(target.Generation), CompletenessReceipt: hex.EncodeToString(target.Completeness[:]), ExpectedRoot: string(target.Destination.Root)}, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	reply, _, err := s.wire.exchange(ctx, route, protocol.Command{Operation: protocol.OriginReopen, Project: string(route.Project), Body: body}, func(call context.Context, tx domain.Transmission) error {
		return s.store.CheckReopen(call, domain.ReopenCheck{Target: target, Credential: tx.Credential, Connection: tx.Connection, Now: tx.Now})
	})
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	reopened, err := originReply(reply, s.gateway, target.Destination.Recovery, target.Generation, true)
	if err != nil {
		return protocol.OriginStateReport{}, err
	}
	// Only root namespace evidence is needed here. Project availability and
	// execution readiness are separate, including when every workspace is gone.
	current, _, err := s.InspectRoot(ctx, route, expectedRoot)
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
	if route.Validate() != nil || route.Device != plan.Destination.Device {
		return protocol.OriginInventoryReport{}, domain.Transmission{}, domain.ErrInvalid
	}
	request := protocol.OriginInventoryRequest{GatewayID: string(s.gateway), Generation: string(plan.Generation), Cursor: cursor, Limit: domain.MaxPageLimit, ExpectedRoot: string(plan.Destination.Root)}
	body, err := protocol.Encode(request, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.OriginInventoryReport{}, domain.Transmission{}, err
	}
	reply, transmission, err := s.wire.exchange(ctx, route, protocol.Command{Operation: protocol.OriginInventory, Project: string(route.Project), Body: body}, func(call context.Context, tx domain.Transmission) error {
		current, checkErr := s.store.PrepareRecoveryBarrier(call, domain.BarrierPreparation{Destination: plan.Destination, Credential: tx.Credential, Connection: tx.Connection, ExpectedGeneration: plan.ExpectedGeneration, Now: tx.Now})
		if checkErr != nil {
			return checkErr
		}
		if current != plan {
			return domain.Reject(domain.Conflict)
		}
		return nil
	})
	if err != nil {
		return protocol.OriginInventoryReport{}, transmission, err
	}
	var report protocol.OriginInventoryReport
	if protocol.DecodeStrict(reply.Body, &report, protocol.MaxFrameBytes) != nil || report.ValidateFor(request) != nil {
		return protocol.OriginInventoryReport{}, transmission, domain.Reject(domain.EvidenceInvalid)
	}
	return report, transmission, nil
}
