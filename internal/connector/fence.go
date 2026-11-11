package connector

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// resolveOrFence keeps complete tasks out of preparation-recovery exclusion.
// Delegate alone decides whether an absent or incomplete identity can be fenced.
func (a *Adapter) resolveOrFence(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	passive := r
	passive.command.Operation = protocol.Resolve
	response, err := a.invoke(ctx, passive, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if partialFenceProbe(response, r.task.TaskID) {
		// This failed observation supplies no evidence. In particular, ignore any
		// receipt left in it and send only the original request's frozen guards.
		if _, err := a.verifiedRoot(ctx, r, owner); err != nil {
			return failed(r.command.Operation, err)
		}
		return a.invokeReply(ctx, r, owner)
	}
	if response.exitCode != 0 || response.Error != "" || response.Failure != nil {
		return failed(r.command.Operation, ErrPending)
	}
	verified := r.translate(response)
	if verified.Error != nil {
		return verified
	}
	switch response.Connector.Resolution {
	case "existing", "permanently_refused":
		return verified
	case "absent":
		return a.invokeReply(ctx, r, owner)
	default:
		return failed(r.command.Operation, ErrEvidence)
	}
}

func partialFenceProbe(response cliResponse, task string) bool {
	return response.exitCode == 3 && response.Error == "" && response.Failure == nil && response.TaskID == task && response.Connector != nil && response.Connector.ContractVersion == 1 && response.Connector.Resolution == "unresolved"
}
