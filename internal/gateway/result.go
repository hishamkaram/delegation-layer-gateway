package gateway

import (
	"context"
	"encoding/hex"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func (s *Service) ReadResult(ctx context.Context, actor domain.Actor, id domain.OperationID, descriptor protocol.Descriptor, offset int64, limit int) (result protocol.ResultRange, err error) {
	attempt := s.startObservation(actor, routing.ControlClass(protocol.ResultChunk))
	defer func() { attempt.finish(err) }()
	view, err := s.store.GetOperation(ctx, actor, id)
	attempt.authorize(err)
	if err != nil {
		return protocol.ResultRange{}, err
	}
	attempt.bind(view.Correlation)
	if !acceptedDescriptor(view, descriptor) {
		return protocol.ResultRange{}, &RemoteError{Failure: protocol.Failure{Code: "result_unavailable", Retryable: false}}
	}
	request := protocol.RangeRequest{Task: binding(view.Correlation, view.Observation.SpecDigest), Descriptor: descriptor, Offset: offset, Limit: limit}
	if err = request.Validate(); err != nil {
		return protocol.ResultRange{}, err
	}
	body, err := protocol.Encode(request, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.ResultRange{}, err
	}
	reply, transmission, err := s.control(ctx, actor, view.Correlation, domain.TaskRead, protocol.Command{Operation: protocol.ResultChunk, Project: string(view.Correlation.Destination.Project), Body: body}, attempt, nil)
	if err != nil {
		return protocol.ResultRange{}, err
	}
	if reply.Error != nil {
		return protocol.ResultRange{}, &RemoteError{Failure: *reply.Error}
	}
	if protocol.DecodeStrict(reply.Body, &result, protocol.MaxFrameBytes) != nil || result.ValidateFor(request) != nil {
		return protocol.ResultRange{}, domain.Reject(domain.EvidenceInvalid)
	}
	// Recheck owner/grants after the scan/transport wait, before releasing bytes.
	current, err := s.store.GetOperation(ctx, actor, id)
	if err != nil {
		s.observeAuthorizationFailure(actor, protocol.ResultChunk, err)
		return protocol.ResultRange{}, err
	}
	if !acceptedDescriptor(current, descriptor) || current.Observation.SpecDigest != view.Observation.SpecDigest {
		return protocol.ResultRange{}, domain.Reject(domain.Conflict)
	}
	if _, err = s.store.CheckConnection(ctx, transmission.Credential, transmission.Connection, s.now()); err != nil {
		return protocol.ResultRange{}, err
	}
	return result, nil
}

func acceptedDescriptor(view domain.OperationView, descriptor protocol.Descriptor) bool {
	if descriptor.Validate() != nil || view.Observation == nil || view.Observation.Result == nil || view.Observation.SpecDigest == (domain.Digest{}) {
		return false
	}
	result := view.Observation.Result
	return result.Bytes == descriptor.Length && hex.EncodeToString(result.Digest[:]) == descriptor.SHA256
}
