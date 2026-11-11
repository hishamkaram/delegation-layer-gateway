package gateway

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type RemoteError struct{ Failure protocol.Failure }

func (e *RemoteError) Error() string { return e.Failure.Code }

func (s *Service) acceptReply(ctx context.Context, actor domain.Actor, c domain.Correlation, transmission domain.Transmission, reply protocol.Reply, scope domain.Scope, cancellation domain.CancellationID) (domain.OperationView, error) {
	if reply.Validate() != nil {
		return domain.OperationView{}, domain.Reject(domain.EvidenceInvalid)
	}
	if _, err := s.store.Authorize(ctx, domain.AuthorizationRequest{Actor: actor, Destination: c.Destination, Scope: scope}); err != nil {
		return domain.OperationView{}, err
	}
	if reply.Error != nil {
		return domain.OperationView{}, &RemoteError{Failure: *reply.Error}
	}
	var observation protocol.TaskObservation
	if err := protocol.DecodeStrict(reply.Body, &observation, protocol.MaxFrameBytes); err != nil {
		return domain.OperationView{}, domain.Reject(domain.EvidenceInvalid)
	}
	if observation.Validate() != nil || !observationMatches(observation, c) {
		return domain.OperationView{}, domain.Reject(domain.EvidenceInvalid)
	}
	cache, err := ObservationFromReply(reply, observation, cancellation, s.now())
	if err != nil {
		return domain.OperationView{}, err
	}
	return s.store.ApplyResolution(ctx, domain.ValidatedResolution{ValidatedObservation: domain.ValidatedObservation{Correlation: c, Connection: transmission.Connection, Credential: transmission.Credential, Observation: cache, Now: s.now()}, DurableRequest: cache.Kind != domain.Unknown})
}

func observationKind(reply protocol.Reply, observation protocol.TaskObservation, cancellation domain.CancellationID) domain.ObservationKind {
	kind := domain.Unknown
	if observation.Resolution == "permanently_refused" {
		kind = domain.Refused
	}
	if observation.Resolution == "existing" {
		kind = domain.Existing
	}
	// Publication precedes worker Wait in Delegate. Accepted bytes never
	// substitute for canonical execution closure when releasing a reservation.
	if observation.ExecutionClosure != nil || confirmedCancellation(reply, observation, cancellation) {
		kind = domain.Terminal
	}
	return kind
}

// ObservationFromReply projects a validated, identity-matched wire response into
// dated evidence. The caller owns authorization and immutable binding checks.
func ObservationFromReply(reply protocol.Reply, observation protocol.TaskObservation, cancellation domain.CancellationID, now time.Time) (domain.DelegateObservation, error) {
	kind := observationKind(reply, observation, cancellation)
	cache := domain.DelegateObservation{Kind: kind, ObservedAt: now}
	if confirmedCancellation(reply, observation, cancellation) {
		cache.ConfirmedStop = &domain.StopConfirmation{Cancellation: cancellation}
	}
	if kind != domain.Terminal {
		cache.ClosurePending = domain.ClosurePending(observation.ExecutionClosurePending)
	}
	if observation.ExecutionClosure != nil {
		digest, err := decodeDigest(observation.ExecutionClosure.ReferenceSHA256)
		if err != nil {
			return cache, err
		}
		cache.Closure = &domain.ClosureEvidence{Kind: domain.ClosureKind(observation.ExecutionClosure.Kind), Reference: digest}
	}
	if observation.Task.SpecSHA256 != "" {
		digest, err := decodeDigest(observation.Task.SpecSHA256)
		if err != nil {
			return cache, err
		}
		cache.SpecDigest = digest
	}
	if observation.Result != nil {
		digest, err := decodeDigest(observation.Result.SHA256)
		if err != nil {
			return cache, err
		}
		cache.Result = &domain.ResultDescriptor{Digest: digest, Bytes: observation.Result.Length}
	}
	return cache, nil
}

func confirmedCancellation(reply protocol.Reply, observation protocol.TaskObservation, cancellation domain.CancellationID) bool {
	return reply.Operation == protocol.Cancel && observation.Resolution == "existing" && cancellation.Validate() == nil && observation.Stop != nil && observation.Stop.RequestID == string(cancellation) && observation.Stop.Requested && observation.Stop.Terminated
}

func observationMatches(o protocol.TaskObservation, c domain.Correlation) bool {
	task := o.Task
	if task.TaskID != string(c.Task) || task.Context.Root != string(c.Context.Root) || task.Context.Project != string(c.Context.Project) {
		return false
	}
	if task.Origin.GatewayID != string(c.Gateway) || task.Origin.AdmissionGeneration != string(c.AdmissionGeneration) || task.Origin.OperationID != string(c.Operation) || task.Origin.PrincipalRef != string(c.Owner.Principal) || task.Origin.RequestSHA256 != hex.EncodeToString(c.RequestDigest[:]) {
		return false
	}
	return o.Resolution != "existing" || o.BriefSHA256 == hex.EncodeToString(c.BriefDigest[:])
}

func decodeDigest(value string) (domain.Digest, error) {
	var digest domain.Digest
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, domain.Reject(domain.EvidenceInvalid)
	}
	copy(digest[:], decoded)
	return digest, nil
}
