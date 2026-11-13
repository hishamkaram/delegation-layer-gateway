package server

import (
	"context"
	"encoding/base64"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func (r *Runtime) renewals(ctx context.Context) error {
	for {
		received, err := r.hub.Receive(ctx)
		if err != nil {
			return failed(err)
		}
		r.handleRenewal(ctx, received)
	}
}

func (r *Runtime) renewalUnavailable(device domain.DeviceID) {
	r.recorder.Record(observability.Event{Code: observability.RenewalUnavailable, Device: device})
}

func (r *Runtime) handleRenewal(ctx context.Context, received *transport.Received) {
	metadata := received.Metadata()
	call, cancel := context.WithTimeout(ctx, r.controlTimeout)
	defer cancel()
	frame, err := received.Claim(call)
	if err != nil {
		r.renewalUnavailable(metadata.Credential.Device)
		if discardErr := received.Discard(); discardErr != nil {
			r.renewalUnavailable(metadata.Credential.Device)
		}
		return
	}
	request, csr, parseErr := checkedRenewal(frame, metadata)
	if parseErr != nil {
		r.renewalUnavailable(metadata.Credential.Device)
		return
	}
	if _, err = r.store.CheckConnection(call, metadata.Credential, metadata.Connection, r.now()); err != nil {
		r.rejectRenewal(call, received, request)
		return
	}
	receipt, err := r.enrollment.Renew(call, metadata.Credential, domain.RequestID(request.RenewalID), csr)
	if err != nil {
		r.rejectRenewal(call, received, request)
		return
	}
	if receipt.Intent.Credential != metadata.Credential {
		r.rejectRenewal(call, received, request)
		return
	}
	r.recorder.Record(observability.Event{Code: observability.RenewalIssued, Device: metadata.Credential.Device})
	// Issuance is durable even if a newer connection wins before reply. Replays
	// retain the same semantic ID+CSR and recover the original certificate receipt.
	if _, err = r.store.CheckConnection(call, metadata.Credential, metadata.Connection, r.now()); err != nil {
		r.renewalUnavailable(metadata.Credential.Device)
		return
	}
	result := protocol.RenewalResult{DeviceID: request.DeviceID, RenewalID: request.RenewalID, Epoch: string(receipt.Intent.Credential.Epoch), Generation: receipt.Intent.Credential.Generation, CertificateDERBase64: base64.StdEncoding.EncodeToString(receipt.CertificateDER)}
	if err = received.ReplyRenewal(call, result); err != nil {
		r.renewalUnavailable(metadata.Credential.Device)
	}
}

func (r *Runtime) rejectRenewal(ctx context.Context, received *transport.Received, request protocol.Renewal) {
	r.renewalUnavailable(domain.DeviceID(request.DeviceID))
	result := protocol.RenewalResult{DeviceID: request.DeviceID, RenewalID: request.RenewalID, Error: &protocol.Failure{Code: "pending", Retryable: true}}
	if err := received.ReplyRenewal(ctx, result); err != nil {
		r.renewalUnavailable(domain.DeviceID(request.DeviceID))
	}
}

func checkedRenewal(frame protocol.Frame, metadata transport.Metadata) (protocol.Renewal, []byte, error) {
	var request protocol.Renewal
	expected := protocol.Generation{BootEpoch: string(metadata.Connection.BootEpoch), Counter: metadata.Connection.Counter}
	if frame.Type != protocol.RenewCertificate || frame.OperationID != "" || frame.RequestID != metadata.RequestID || frame.Generation != expected || protocol.DecodeStrict(frame.Payload, &request, 32<<10) != nil {
		return request, nil, ErrUnavailable
	}
	csr, err := request.CSR()
	if err != nil || request.DeviceID != string(metadata.Credential.Device) || request.CredentialGeneration != metadata.Credential.Generation {
		return request, nil, ErrUnavailable
	}
	return request, csr, nil
}
