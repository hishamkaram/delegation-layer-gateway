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

// SelectionInspector obtains dated Native context without retaining a pin.
// Implementations use an owned-device route; no arbitrary local paths enter it.
type SelectionInspector interface {
	PrepareSelection(context.Context, domain.Actor, domain.DeviceID, protocol.SelectionRequest) (protocol.SelectionObservation, error)
}

type SelectedPreparation struct {
	RequestID domain.RequestID
	Device    domain.DeviceID
	Selection protocol.FileSelection
	Request   domain.FrozenRequest
}

func (i SelectedPreparation) validate() error {
	selection := protocol.SelectionRequest{Selection: i.Selection}
	if domain.TaskID(i.RequestID).Validate() != nil || domain.CredentialToken(string(i.Device)) != nil || selection.Validate() != nil || i.Request.Native.Validate() != nil || i.Request.Validate() != nil {
		return domain.ErrInvalid
	}
	return nil
}

func (s *Service) PrepareSelected(ctx context.Context, actor domain.Actor, input SelectedPreparation) (prepared domain.PreparedOperation, err error) {
	attempt := s.startObservation(actor, routing.PrepareClass)
	defer func() { attempt.finish(err) }()
	request := protocol.SelectionRequest{Selection: input.Selection}
	if input.Selection.RelativePath == "" && input.Selection.RelativePathBase64 == "" {
		input.Selection.RelativePath = "."
		request.Selection = input.Selection
	}
	if actor.Validate() != nil || input.validate() != nil {
		return domain.PreparedOperation{}, domain.ErrInvalid
	}
	fingerprint, err := domain.DispatchInputDigestV1(input.Device, domain.RequestSelector{ScopeID: input.Selection.ScopeID, RelativePath: input.Selection.RelativePath, RelativePathBase64: input.Selection.RelativePathBase64}, input.Request.Options(), domain.Hash([]byte(input.Request.Brief)))
	if err != nil {
		return domain.PreparedOperation{}, domain.ErrInvalid
	}
	// The durable key wins before live paths, connectivity or current discovery.
	// A lost preparation acknowledgement must never mint replacement work.
	previous, found, err := s.store.LookupPreparation(ctx, actor, input.Device, input.RequestID, fingerprint)
	attempt.authorize(err)
	if err != nil || found {
		if err == nil {
			attempt.bind(previous.Correlation)
		}
		return previous, err
	}
	inspector, ok := s.targeted.(SelectionInspector)
	if !ok {
		return domain.PreparedOperation{}, &RemoteError{Failure: protocol.Failure{Code: "unsupported_feature"}}
	}
	observed, err := inspector.PrepareSelection(ctx, actor, input.Device, request)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	if err = validatePreparationSelection(observed, request); err != nil {
		return domain.PreparedOperation{}, err
	}
	plan, err := s.newSelectedPreparation(actor, input, observed, fingerprint)
	if err != nil {
		return domain.PreparedOperation{}, err
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

// newSelectedPreparation builds and frame-checks the immutable draft. Only the
// Registry's later transaction publishes it; this function owns no task state.
func (s *Service) newSelectedPreparation(actor domain.Actor, input SelectedPreparation, observed protocol.SelectionObservation, fingerprint domain.Digest) (domain.Preparation, error) {
	var entropy [32]byte
	if _, err := io.ReadFull(s.random, entropy[:]); err != nil {
		return domain.Preparation{}, errors.New("operation entropy unavailable")
	}
	operation := domain.OperationID(hex.EncodeToString(entropy[:16]))
	correlation := domain.Correlation{
		RequestVersion: domain.CompactRequestVersion, Kind: domain.RequestKindDispatch, BriefPresent: true,
		Operation: operation, Task: domain.TaskID(hex.EncodeToString(entropy[16:])), Gateway: s.gateway, AdmissionGeneration: domain.AdmissionGeneration(observed.AdmissionGeneration), Owner: domain.OperationOwner{Kind: domain.Owned, Principal: actor.Principal}, Destination: domain.Destination{Device: input.Device, Project: domain.ProjectAlias(operation)}, Context: domain.ContextBinding{Root: domain.RootGuard(observed.Context.Root), Project: domain.ProjectGuard(observed.Context.Project)}, BriefDigest: domain.Hash([]byte(input.Request.Brief)),
		Route: domain.OperationRoute{Version: 1, InputFormat: domain.DispatchInputV1, RequestID: input.RequestID, InputDigest: fingerprint, ScopeID: input.Selection.ScopeID, RelativePath: input.Selection.RelativePath, WorkspaceGuard: observed.WorkspaceGuard},
	}
	input.Request.BriefPresent = true
	digest, err := domain.RequestDigest(correlation, input.Request)
	correlation.RequestDigest = digest
	if err != nil {
		return domain.Preparation{}, err
	}
	command, err := admissionCommand(correlation, input.Request)
	if err != nil {
		return domain.Preparation{}, err
	}
	if err = preflight(command, string(operation)); err != nil {
		return domain.Preparation{}, err
	}
	return domain.Preparation{Correlation: correlation, Request: input.Request, Now: s.now()}, nil
}

func validatePreparationSelection(observed protocol.SelectionObservation, request protocol.SelectionRequest) error {
	if observed.ValidateFor(request) != nil || !observed.AdmissionOpen {
		return domain.Reject(domain.EvidenceInvalid)
	}
	for _, feature := range []string{protocol.FeatureNativeOptions, protocol.FeatureProjectHashGuard, protocol.FeatureOriginBinding} {
		if !slices.Contains(observed.Features, feature) {
			return &RemoteError{Failure: protocol.Failure{Code: "delegate_upgrade_required"}}
		}
	}
	return nil
}

func wireNativeOptions(o domain.NativeOptions) protocol.NativeOptions {
	if o.Version == 0 {
		return protocol.NativeOptions{}
	}
	return protocol.NativeOptions{Version: o.Version, Provider: string(o.Provider), Model: protocol.Selection{Kind: string(o.Model.Kind), Value: o.Model.Value}, Effort: protocol.Selection{Kind: string(o.Effort.Kind), Value: o.Effort.Value}, Permission: o.Permission, Budget: o.Budget, ReviewTarget: o.ReviewTarget, NativeTimeout: o.NativeTimeout, OutputSilenceTimeout: o.OutputSilenceTimeout}
}

func (s *Service) authorizeCorrelation(ctx context.Context, actor domain.Actor, c domain.Correlation, scope domain.Scope) error {
	if c.Route.Version == 1 {
		if c.Owner.Kind != domain.Owned || c.Owner.Principal != actor.Principal {
			return domain.Reject(domain.NotFound)
		}
		_, err := s.store.AuthorizeOwnedDevice(ctx, domain.OwnedDeviceRequest{Actor: actor, Device: c.Destination.Device, Scope: scope})
		return err
	}
	_, err := s.store.Authorize(ctx, domain.AuthorizationRequest{Actor: actor, Destination: c.Destination, Scope: scope})
	return err
}

func validateSelectedSnapshot(snapshot LinkSnapshot, c domain.Correlation) error {
	if snapshot.WireVersion != protocol.WireVersion2 {
		return &RemoteError{Failure: protocol.Failure{Code: "connector_upgrade_required"}}
	}
	if snapshot.Credential.Device != c.Destination.Device || snapshot.CapabilitiesV2 == nil || snapshot.CapabilitiesV2.Validate() != nil || snapshot.CapabilitiesV2.Root == nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	root := snapshot.CapabilitiesV2.Root
	if root.Root != string(c.Context.Root) || root.Origin == nil || !root.Origin.AdmissionOpen || root.Origin.GatewayID != string(c.Gateway) || root.Origin.Generation != string(c.AdmissionGeneration) {
		return domain.Reject(domain.Conflict)
	}
	for _, feature := range []string{protocol.FeatureNativeOptions, protocol.FeatureProjectHashGuard, protocol.FeatureOriginBinding} {
		if !slices.Contains(root.Features, feature) {
			return &RemoteError{Failure: protocol.Failure{Code: "delegate_upgrade_required"}}
		}
	}
	if c.Kind == domain.RequestKindContinuation && !slices.Contains(root.Features, protocol.FeatureGuardedContinuation) {
		return &RemoteError{Failure: protocol.Failure{Code: "delegate_upgrade_required"}}
	}
	return nil
}
