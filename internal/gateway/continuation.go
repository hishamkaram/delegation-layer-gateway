package gateway

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"slices"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type ContinuationPreparation struct {
	RequestID   domain.RequestID
	Device      domain.DeviceID
	Predecessor domain.OperationID
	Selection   *protocol.FileSelection
	Overrides   domain.ContinuationOverrides
	Brief       *string
}

// continuationStore exposes only the dispatch-authorized immutable predecessor
// and known Native spec. It grants no accepted result or task-read authority.
type continuationStore interface {
	GetForContinuation(context.Context, domain.Actor, domain.OperationID) (domain.RecoveryView, error)
}

func (s *Service) PrepareContinuation(ctx context.Context, actor domain.Actor, input ContinuationPreparation) (prepared domain.PreparedOperation, err error) {
	attempt := s.startObservation(actor, routing.PrepareClass)
	defer func() { attempt.finish(err) }()
	request, selector, err := input.request()
	if actor.Validate() != nil || err != nil {
		return prepared, domain.ErrInvalid
	}
	brief := domain.Digest{}
	if request.BriefPresent {
		brief = domain.Hash([]byte(request.Brief))
	}
	fingerprint, err := domain.ContinuationInputDigestV1(input.Device, input.Predecessor, selector, request.SelectionExplicit, input.Overrides, request.BriefPresent, brief)
	if err != nil {
		return prepared, err
	}
	// A replay wins before parent lookup, current filesystem state or entropy.
	previous, found, err := s.store.LookupPreparation(ctx, actor, input.Device, input.RequestID, fingerprint)
	attempt.authorize(err)
	if err != nil || found {
		if err == nil {
			attempt.bind(previous.Correlation)
		}
		return previous, err
	}
	parent, err := s.continuationPredecessor(ctx, actor, input.Predecessor)
	if err != nil {
		return prepared, err
	}
	if parent.Correlation.Destination.Device != input.Device {
		return prepared, domain.Reject(domain.NotFound)
	}
	observed, err := s.continuationSelection(ctx, actor, input, selector, parent.Correlation)
	if err != nil {
		return prepared, err
	}
	plan, err := s.newContinuation(actor, input, request, parent, observed, fingerprint, brief)
	if err != nil {
		return prepared, err
	}
	prepared, err = s.store.Prepare(ctx, actor, plan)
	if err == nil {
		attempt.bind(prepared.Correlation)
		attempt.value.Prepared = true
	} else {
		s.observeClassAuthorizationFailure(actor, routing.PrepareClass, err)
	}
	return prepared, err
}

func (s *Service) continuationSelection(ctx context.Context, actor domain.Actor, input ContinuationPreparation, selector domain.RequestSelector, prior domain.Correlation) (protocol.SelectionObservation, error) {
	selection := protocol.FileSelection{ScopeID: prior.Route.ScopeID, RelativePath: prior.Route.RelativePath}
	if input.Selection != nil {
		selection = protocol.FileSelection{ScopeID: selector.ScopeID, RelativePath: selector.RelativePath}
	}
	inspector, ok := s.targeted.(SelectionInspector)
	if !ok {
		return protocol.SelectionObservation{}, &RemoteError{Failure: protocol.Failure{Code: "unsupported_feature"}}
	}
	selected := protocol.SelectionRequest{Selection: selection}
	observed, err := inspector.PrepareSelection(ctx, actor, input.Device, selected)
	if err != nil {
		return protocol.SelectionObservation{}, err
	}
	if err = validatePreparationSelection(observed, selected); err != nil {
		return protocol.SelectionObservation{}, err
	}
	if !slices.Contains(observed.Features, protocol.FeatureGuardedContinuation) {
		return protocol.SelectionObservation{}, &RemoteError{Failure: protocol.Failure{Code: "delegate_upgrade_required"}}
	}
	if observed.Context.Root != string(prior.Context.Root) || observed.Context.Project != string(prior.Context.Project) || observed.WorkspaceGuard != prior.Route.WorkspaceGuard {
		return protocol.SelectionObservation{}, domain.Reject(domain.Conflict)
	}
	return observed, nil
}

func (i ContinuationPreparation) request() (domain.FrozenRequest, domain.RequestSelector, error) {
	request := domain.FrozenRequest{Continuation: i.Overrides, BriefPresent: i.Brief != nil, SelectionExplicit: i.Selection != nil}
	if i.Brief != nil {
		request.Brief = *i.Brief
	}
	selector := domain.RequestSelector{}
	if domain.TaskID(i.RequestID).Validate() != nil || domain.CredentialToken(string(i.Device)) != nil || domain.Token(string(i.Predecessor)) != nil || request.Validate() != nil {
		return request, selector, domain.ErrInvalid
	}
	if i.Selection != nil {
		selection := *i.Selection
		if selection.RelativePath == "" && selection.RelativePathBase64 == "" {
			selection.RelativePath = "."
		}
		if (protocol.SelectionRequest{Selection: selection}).Validate() != nil {
			return request, selector, domain.ErrInvalid
		}
		selector = domain.RequestSelector{ScopeID: selection.ScopeID, RelativePath: selection.RelativePath}
	}
	return request, selector, nil
}

func (s *Service) continuationPredecessor(ctx context.Context, actor domain.Actor, id domain.OperationID) (domain.RecoveryView, error) {
	store, ok := s.store.(continuationStore)
	if !ok {
		return domain.RecoveryView{}, &RemoteError{Failure: protocol.Failure{Code: "unsupported_feature"}}
	}
	return store.GetForContinuation(ctx, actor, id)
}

func (s *Service) newContinuation(actor domain.Actor, input ContinuationPreparation, request domain.FrozenRequest, parent domain.RecoveryView, observed protocol.SelectionObservation, fingerprint, brief domain.Digest) (domain.Preparation, error) {
	var entropy [32]byte
	if _, err := io.ReadFull(s.random, entropy[:]); err != nil {
		return domain.Preparation{}, errors.New("operation entropy unavailable")
	}
	operation := domain.OperationID(hex.EncodeToString(entropy[:16]))
	prior := parent.Correlation
	c := domain.Correlation{
		RequestVersion: domain.CompactRequestVersion, Kind: domain.RequestKindContinuation, BriefPresent: request.BriefPresent, BriefDigest: brief,
		Operation: operation, Task: domain.TaskID(hex.EncodeToString(entropy[16:])), Gateway: s.gateway, AdmissionGeneration: domain.AdmissionGeneration(observed.AdmissionGeneration), Owner: domain.OperationOwner{Kind: domain.Owned, Principal: actor.Principal}, Destination: domain.Destination{Device: input.Device, Project: domain.ProjectAlias(operation)}, Context: prior.Context,
		Route:       domain.OperationRoute{Version: 1, InputFormat: domain.ContinuationInputV1, RequestID: input.RequestID, InputDigest: fingerprint, ScopeID: observed.Selection.ScopeID, RelativePath: observed.Selection.RelativePath, WorkspaceGuard: observed.WorkspaceGuard},
		Predecessor: domain.ContinuationPredecessor{Operation: prior.Operation, Task: prior.Task, SpecDigest: parent.SpecDigest, RequestDigest: prior.RequestDigest},
	}
	digest, err := domain.RequestDigest(c, request)
	if err != nil {
		return domain.Preparation{}, err
	}
	c.RequestDigest = digest
	command, err := continuationCommand(c, request, parent)
	if err != nil {
		return domain.Preparation{}, err
	}
	if err = preflight(command, string(operation)); err != nil {
		return domain.Preparation{}, err
	}
	return domain.Preparation{Correlation: c, Request: request, Now: s.now()}, nil
}

func continuationCommand(c domain.Correlation, r domain.FrozenRequest, parent domain.RecoveryView) (protocol.Command, error) {
	p := parent.Correlation
	if c.Kind != domain.RequestKindContinuation || c.Predecessor != (domain.ContinuationPredecessor{Operation: p.Operation, Task: p.Task, SpecDigest: parent.SpecDigest, RequestDigest: p.RequestDigest}) || c.Destination.Device != p.Destination.Device || c.Context != p.Context || c.Route.WorkspaceGuard != p.Route.WorkspaceGuard {
		return protocol.Command{}, domain.Reject(domain.EvidenceInvalid)
	}
	task, err := binding(c, domain.Digest{})
	if err != nil {
		return protocol.Command{}, err
	}
	predecessor, err := binding(p, parent.SpecDigest)
	if err != nil {
		return protocol.Command{}, err
	}
	o := r.Continuation
	value := protocol.Continuation{Task: task, Predecessor: predecessor, Overrides: protocol.ContinuationOverrides{Version: o.Version, Budget: o.Budget, Model: o.Model, Effort: o.Effort, OutputSilenceTimeout: o.OutputSilenceTimeout}, SelectionExplicit: r.SelectionExplicit, BriefPresent: r.BriefPresent, Brief: r.Brief}
	if value.Validate() != nil {
		return protocol.Command{}, domain.ErrInvalid
	}
	body, err := protocol.Encode(value, protocol.MaxFrameBytes)
	return protocol.Command{Operation: protocol.Continue, Project: string(c.Destination.Project), Body: body}, err
}
