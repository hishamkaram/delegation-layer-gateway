package connector

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Registry owns authenticated device routing. Connector verifies that the
// immutable Origin, route and requested body describe that same Native intent.
func compactTask(task protocol.TaskBinding, gateway domain.GatewayID) (domain.Correlation, error) {
	parsed, err := domain.ParseOriginBinding(task.Origin.Binding)
	if err != nil {
		return domain.Correlation{}, ErrEvidence
	}
	origin, err := task.Origin.DomainOrigin()
	if err != nil {
		return domain.Correlation{}, ErrEvidence
	}
	key := domain.NativeTaskKey{Device: parsed.Destination.Device, Root: domain.RootGuard(task.Context.Root), Task: domain.TaskID(task.TaskID)}
	c, err := domain.VerifyOriginBinding(gateway, key, origin)
	if err != nil || string(c.Context.Project) != task.Context.Project || string(c.Destination.Project) != task.Origin.OperationID {
		return domain.Correlation{}, ErrEvidence
	}
	route, err := protocol.TaskRouteFromDomain(c.Route)
	if err != nil || route != task.Route {
		return domain.Correlation{}, ErrEvidence
	}
	return c, nil
}

func matchesCompactBrief(binding, brief string) bool {
	c, err := domain.ParseOriginBinding(binding)
	if err != nil || len(brief) != 64 {
		return false
	}
	var observed domain.Digest
	if _, err := hex.Decode(observed[:], []byte(brief)); err != nil {
		return false
	}
	return domain.RequestedBriefMatches(c, observed)
}

func (r request) validateCompactIntent() error {
	c, err := compactTask(r.task, r.config.GatewayID)
	if err != nil {
		return err
	}
	var body domain.FrozenRequest
	switch {
	case r.admission != nil:
		if c.Kind != domain.RequestKindDispatch {
			return ErrEvidence
		}
		n := r.admission.Native
		body = domain.FrozenRequest{Native: domain.NativeOptions{Version: n.Version, Provider: domain.ProviderID(n.Provider), Model: domain.Selection{Kind: domain.SelectionKind(n.Model.Kind), Value: n.Model.Value}, Effort: domain.Selection{Kind: domain.SelectionKind(n.Effort.Kind), Value: n.Effort.Value}, Permission: n.Permission, Budget: n.Budget, ReviewTarget: n.ReviewTarget, NativeTimeout: n.NativeTimeout, OutputSilenceTimeout: n.OutputSilenceTimeout}, Brief: r.admission.Brief, BriefPresent: true}
	case r.continuation != nil:
		body, err = continuationIntent(*r.continuation, c, r.config.GatewayID)
		if err != nil {
			return err
		}
	default:
		return nil // Historical controls have no execution body to reconstruct.
	}
	digest, err := domain.RequestDigest(c, body)
	if err != nil || digest != c.RequestDigest {
		return ErrEvidence
	}
	return nil
}

func continuationIntent(value protocol.Continuation, c domain.Correlation, gateway domain.GatewayID) (domain.FrozenRequest, error) {
	prior, err := value.Predecessor.Origin.DomainOrigin()
	if err != nil || c.Kind != domain.RequestKindContinuation || string(c.Predecessor.Operation) != value.Predecessor.Origin.OperationID || string(c.Predecessor.Task) != value.Predecessor.TaskID || c.Predecessor.SpecDigest.Hex() != value.Predecessor.SpecSHA256 || c.Predecessor.RequestDigest != prior.RequestDigest {
		return domain.FrozenRequest{}, ErrEvidence
	}
	if value.Predecessor.Origin.Binding != "" {
		predecessor, predecessorErr := compactTask(value.Predecessor, gateway)
		if predecessorErr != nil || predecessor.Destination.Device != c.Destination.Device {
			return domain.FrozenRequest{}, ErrEvidence
		}
	}
	o := value.Overrides
	return domain.FrozenRequest{Continuation: domain.ContinuationOverrides{Version: o.Version, Budget: o.Budget, Model: o.Model, Effort: o.Effort, OutputSilenceTimeout: o.OutputSilenceTimeout}, BriefPresent: value.BriefPresent, Brief: value.Brief, SelectionExplicit: value.SelectionExplicit}, nil
}

func (r request) continuationInvocation(ctx context.Context, owner *controlOwner) (invocation, error) {
	value := r.continuation
	if value == nil || r.scoped == nil || r.scoped.scope.ExpectedWorkspace == "" {
		return invocation{}, ErrEvidence
	}
	prior, err := protocol.Encode(value.Predecessor.Origin, protocol.NativeInputRecordBytes)
	if err != nil {
		return invocation{}, ErrEvidence
	}
	priorFile, err := owner.file("predecessor-origin.json", prior)
	if err != nil {
		return invocation{}, err
	}
	origin, err := protocol.Encode(r.task.Origin, protocol.NativeInputRecordBytes)
	if err != nil {
		return invocation{}, ErrEvidence
	}
	originFile, err := owner.file("successor-origin.json", origin)
	if err != nil {
		return invocation{}, err
	}
	args := []string{"--task", value.Predecessor.TaskID, "--id", r.task.TaskID, "--expected-root", r.project.RootToken, "--expected-project-sha256", strings.TrimPrefix(value.Predecessor.Context.Project, "ctx1_"), "--expected-spec-sha256", value.Predecessor.SpecSHA256, "--expected-origin", priorFile, "--origin", originFile, "--include-workspace-constraint"}
	if value.BriefPresent {
		brief, briefErr := owner.file("brief.txt", []byte(value.Brief))
		if briefErr != nil {
			return invocation{}, briefErr
		}
		args = append(args, "--brief", brief)
	}
	o := value.Overrides
	for _, option := range []struct{ flag, value string }{{"--budget", o.Budget}, {"--model", o.Model}, {"--effort", o.Effort}, {"--output-silence-timeout", o.OutputSilenceTimeout}} {
		if option.value != "" {
			args = append(args, option.flag, option.value)
		}
	}
	call, err := r.common(ctx, "continue", args...)
	call.classifyArgumentExit2 = true
	return call, err
}
