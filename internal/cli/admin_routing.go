package cli

import (
	"context"
	"io"
	"net/http"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func routingAdminAction(ctx context.Context, socket, action, output string, data []byte, stdout io.Writer) (bool, error) {
	switch action {
	case "routing-drain-target":
		return true, adminRequest[adminapi.RoutingTargetInput, adminapi.RoutingDrainTarget](ctx, socket, http.MethodPost, "/v1/routing/drain-target", data, output, false, stdout, validRoutingDrainTarget)
	case "attest-routing-drained":
		return true, adminRequest[adminapi.RoutingDrainInput, adminapi.RoutingDrainResponse](ctx, socket, http.MethodPost, "/v1/routing/drain", data, output, false, stdout, validRoutingDrainResponse)
	default:
		return false, nil
	}
}

func validRoutingDrainTarget(input adminapi.RoutingTargetInput, output adminapi.RoutingDrainTarget) bool {
	return output.Validate() == nil && output.DeviceID == input.DeviceID
}

func validRoutingDrainResponse(input adminapi.RoutingDrainInput, output adminapi.RoutingDrainResponse) bool {
	if output.Validate() != nil || output.Target.DeviceID != input.DeviceID || output.Target.RecoveryID != input.RecoveryID || output.Target.Credential != input.ExpectedCredential || output.Target.ProcessBoot != input.ExpectedProcessBoot {
		return false
	}
	switch output.Disposition {
	case routing.Drained:
		return output.Target.Connection == input.ExpectedConnection
	case routing.AlreadySatisfied:
		return true
	default:
		return false
	}
}
