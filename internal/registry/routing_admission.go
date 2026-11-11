package registry

import (
	"context"
	"encoding/hex"

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
	if route.Credential != input.Credential || routingGeneration(route.Call.Generation) != input.Connection || !route.Now.Equal(input.Now) || route.Call.Operation != protocol.Admit || route.Call.OperationID != string(input.Operation) {
		return domain.SendDecision{}, domain.ErrInvalid
	}
	return s.markPossibleSend(ctx, actor, input, &route)
}

func validateRoutingAdmission(route routing.Request, c domain.Correlation, r domain.FrozenRequest) error {
	command, err := validateRoutingRequest(route)
	if err != nil {
		return err
	}
	var actual protocol.Admission
	if protocol.DecodeStrict(command.Body, &actual, protocol.MaxFrameBytes) != nil || actual.Validate() != nil {
		return domain.ErrInvalid
	}
	expected := protocol.Admission{Task: protocol.TaskBinding{TaskID: string(c.Task), Context: protocol.ContextBinding{Root: string(c.Context.Root), Project: string(c.Context.Project)}, Origin: protocol.Origin{GatewayID: string(c.Gateway), AdmissionGeneration: string(c.AdmissionGeneration), OperationID: string(c.Operation), PrincipalRef: string(c.Owner.Principal), RequestSHA256: hex.EncodeToString(c.RequestDigest[:])}}, Provider: string(r.Provider), Model: protocol.Selection{Kind: string(r.Model.Kind), Value: r.Model.Value}, Effort: protocol.Selection{Kind: string(r.Effort.Kind), Value: r.Effort.Value}, Permission: string(r.Permission), BudgetSeconds: r.BudgetSeconds, Brief: r.Brief}
	if command.Project != string(c.Destination.Project) || actual != expected {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}
