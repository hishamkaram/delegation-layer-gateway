package registry

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

const fixtureProcessBoot = "11111111111111111111111111111111"

func (f *fixture) reconcileRouting(t *testing.T, active []protocol.ControlCall) routing.Readiness {
	t.Helper()
	report := protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: fixtureProcessBoot, BarrierID: strings.Repeat("a", 32), Generation: protocol.Generation{BootEpoch: string(f.connection.BootEpoch), Counter: f.connection.Counter}, Complete: true, Active: active}
	status, err := f.store.ReconcileRouting(t.Context(), f.credential, report, f.now)
	return must(t, status, err)
}

func fixtureAdmission(c domain.Correlation, r domain.FrozenRequest) protocol.Admission {
	return protocol.Admission{Task: protocol.TaskBinding{TaskID: string(c.Task), Context: protocol.ContextBinding{Root: string(c.Context.Root), Project: string(c.Context.Project)}, Origin: protocol.Origin{GatewayID: string(c.Gateway), AdmissionGeneration: string(c.AdmissionGeneration), OperationID: string(c.Operation), PrincipalRef: string(c.Owner.Principal), RequestSHA256: hex.EncodeToString(c.RequestDigest[:])}}, Provider: string(r.Provider), Model: protocol.Selection{Kind: string(r.Model.Kind), Value: r.Model.Value}, Effort: protocol.Selection{Kind: string(r.Effort.Kind), Value: r.Effort.Value}, Permission: string(r.Permission), BudgetSeconds: r.BudgetSeconds, Brief: r.Brief}
}

func (f *fixture) admissionRoute(ctx context.Context, input domain.Transmission) (routing.Request, error) {
	var data, requestData []byte
	if err := f.store.db.QueryRowContext(ctx, "SELECT correlation,request FROM operations WHERE id=?", input.Operation).Scan(&data, &requestData); err != nil {
		return routing.Request{}, err
	}
	c, err := decode[domain.Correlation](data)
	if err != nil {
		return routing.Request{}, err
	}
	request, err := decode[domain.FrozenRequest](requestData)
	if err != nil {
		return routing.Request{}, err
	}
	body, err := encode(fixtureAdmission(c, request))
	if err != nil {
		return routing.Request{}, err
	}
	payload, err := encode(protocol.Command{Operation: protocol.Admit, Project: string(c.Destination.Project), Body: body})
	if err != nil {
		return routing.Request{}, err
	}
	hash := domain.Hash([]byte(input.Operation))
	number := binary.BigEndian.Uint64(hash[:8])
	if number == 0 {
		number = 1
	}
	digest := domain.Hash(payload)
	return routing.Request{Credential: input.Credential, ProcessBoot: fixtureProcessBoot, Call: protocol.ControlCall{Generation: protocol.Generation{BootEpoch: string(input.Connection.BootEpoch), Counter: input.Connection.Counter}, RequestID: "g:" + strconv.FormatUint(number, 10), OperationID: string(input.Operation), Operation: protocol.Admit, RequestSHA256: hex.EncodeToString(digest[:])}, Payload: payload, Now: input.Now}, nil
}

// Legacy task-state tests model a CLI control that settles immediately after
// admission; Delegate execution remains reserved independently until its proof.
func (f *fixture) markSettledControl(ctx context.Context, actor domain.Actor, input domain.Transmission) (domain.SendDecision, error) {
	var state domain.DeliveryState
	if err := f.store.db.QueryRowContext(ctx, "SELECT state FROM operations WHERE id=?", input.Operation).Scan(&state); err != nil {
		return domain.SendDecision{}, err
	}
	if state != domain.Prepared {
		return f.store.MarkPossibleSend(ctx, actor, input)
	}
	route, err := f.admissionRoute(ctx, input)
	if err != nil {
		return domain.SendDecision{}, err
	}
	decision, err := f.store.MarkPossibleSendRouted(ctx, actor, input, route)
	if err == nil && decision.Kind == domain.SendOnce {
		err = f.store.CompleteRouting(ctx, input.Credential, input.Connection, protocol.ControlCompletion{ProcessBoot: route.ProcessBoot, Call: route.Call, Disposition: protocol.ControlSettled}, input.Now)
	}
	return decision, err
}
