package registry

import (
	"context"
	"database/sql"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

// MarkPossibleSendRouted commits both execution correlation and routing resource
// reservation in one SQLite transaction. The legacy method denies new sends.
func (s *Store) MarkPossibleSendRouted(ctx context.Context, actor domain.Actor, input domain.Transmission, route routing.Request) (domain.SendDecision, error) {
	if _, err := validateRoutingRequest(route); err != nil {
		return domain.SendDecision{}, err
	}
	if route.Credential != input.Credential || routingGeneration(route.Call.Generation) != input.Connection || !route.Now.Equal(input.Now) || route.Call.OperationID != string(input.Operation) {
		return domain.SendDecision{}, domain.ErrInvalid
	}
	if route.Call.Operation != protocol.Admit && route.Call.Operation != protocol.Continue {
		return domain.SendDecision{}, domain.ErrInvalid
	}
	return s.markPossibleSend(ctx, actor, input, &route)
}

func validateRoutingAdmission(ctx context.Context, tx *sql.Tx, actor domain.Actor, route routing.Request, c domain.Correlation, r domain.FrozenRequest) error {
	if c.Route.Version == 1 && route.ProtocolVersion() != protocol.WireVersion2 {
		return domain.ErrInvalid
	}
	command, err := validateRoutingRequest(route)
	if err != nil {
		return err
	}
	if command.Project != string(c.Destination.Project) {
		return domain.Reject(domain.EvidenceInvalid)
	}
	switch c.Kind {
	case domain.RequestKindContinuation:
		if command.Operation != protocol.Continue {
			return domain.Reject(domain.EvidenceInvalid)
		}
		return validateRoutingContinuation(ctx, tx, actor, command, c, r)
	case "", domain.RequestKindDispatch:
		if command.Operation != protocol.Admit {
			return domain.Reject(domain.EvidenceInvalid)
		}
		return validateRoutingDispatch(command, c, r)
	default:
		return domain.Reject(domain.EvidenceInvalid)
	}
}

func validateRoutingDispatch(command protocol.Command, c domain.Correlation, r domain.FrozenRequest) error {
	var actual protocol.Admission
	if protocol.DecodeStrict(command.Body, &actual, protocol.MaxFrameBytes) != nil || actual.Validate() != nil {
		return domain.ErrInvalid
	}
	task, err := routingTaskBinding(c, domain.Digest{})
	if err != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	expected := protocol.Admission{Task: task, Provider: string(r.Provider), Model: protocol.Selection{Kind: string(r.Model.Kind), Value: r.Model.Value}, Effort: protocol.Selection{Kind: string(r.Effort.Kind), Value: r.Effort.Value}, Permission: string(r.Permission), BudgetSeconds: r.BudgetSeconds, Brief: r.Brief}
	if r.Native.Version == 1 {
		native := r.Native
		expected.Native = protocol.NativeOptions{Version: 1, Provider: string(native.Provider), Model: protocol.Selection{Kind: string(native.Model.Kind), Value: native.Model.Value}, Effort: protocol.Selection{Kind: string(native.Effort.Kind), Value: native.Effort.Value}, Permission: native.Permission, Budget: native.Budget, ReviewTarget: native.ReviewTarget, NativeTimeout: native.NativeTimeout, OutputSilenceTimeout: native.OutputSilenceTimeout}
		expected.Model, expected.Effort = protocol.Selection{}, protocol.Selection{}
	}
	if actual != expected {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func routingTaskBinding(c domain.Correlation, spec domain.Digest) (protocol.TaskBinding, error) {
	origin, err := protocol.OriginFromCorrelation(c)
	if err != nil {
		return protocol.TaskBinding{}, domain.Reject(domain.EvidenceInvalid)
	}
	route, err := protocol.TaskRouteFromDomain(c.Route)
	if err != nil {
		return protocol.TaskBinding{}, domain.Reject(domain.EvidenceInvalid)
	}
	value := protocol.TaskBinding{TaskID: string(c.Task), Context: protocol.ContextBinding{Root: string(c.Context.Root), Project: string(c.Context.Project)}, Origin: origin, Route: route}
	if spec != (domain.Digest{}) {
		value.SpecSHA256 = spec.Hex()
	}
	return value, nil
}

func validateRoutingContinuation(ctx context.Context, tx *sql.Tx, actor domain.Actor, command protocol.Command, c domain.Correlation, r domain.FrozenRequest) error {
	var actual protocol.Continuation
	if protocol.DecodeStrict(command.Body, &actual, protocol.MaxFrameBytes) != nil || actual.Validate() != nil {
		return domain.ErrInvalid
	}
	parent, err := continuationPredecessor(ctx, tx, actor, c)
	if err != nil {
		return err
	}
	task, err := routingTaskBinding(c, domain.Digest{})
	if err != nil {
		return err
	}
	predecessor, err := routingTaskBinding(parent.Correlation, parent.SpecDigest)
	if err != nil {
		return err
	}
	o := r.Continuation
	expected := protocol.Continuation{Task: task, Predecessor: predecessor, Overrides: protocol.ContinuationOverrides{Version: o.Version, Budget: o.Budget, Model: o.Model, Effort: o.Effort, OutputSilenceTimeout: o.OutputSilenceTimeout}, SelectionExplicit: r.SelectionExplicit, BriefPresent: r.BriefPresent, Brief: r.Brief}
	if actual != expected {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}
