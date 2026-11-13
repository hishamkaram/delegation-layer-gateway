package deviceruntime

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func serveRenewalLostACK(ctx context.Context, f *networkFixture) error {
	var first protocol.Renewal
	var originalDER []byte
	var originalGeneration protocol.Generation
	for attempt := 0; attempt < 2; attempt++ {
		received, frame, request, csr, err := receiveRenewalAttempt(ctx, f)
		if err != nil {
			return err
		}

		if attempt == 0 {
			first = request
			originalGeneration = frame.Generation
		} else if request != first || frame.Generation == originalGeneration {
			return ErrRenewal
		}

		receipt, err := issueRenewalAttempt(ctx, f, request, csr)
		if err != nil {
			return err
		}
		if attempt == 0 {
			originalDER = receipt.CertificateDER
			if err = f.hub.Disconnect("device"); err != nil {
				return err
			}
			continue
		}
		if !bytes.Equal(originalDER, receipt.CertificateDER) {
			return ErrRenewal
		}
		result := protocol.RenewalResult{DeviceID: string(receipt.Intent.Credential.Device), RenewalID: request.RenewalID, Epoch: string(receipt.Intent.Credential.Epoch), Generation: receipt.Intent.Credential.Generation, CertificateDERBase64: base64.StdEncoding.EncodeToString(receipt.CertificateDER)}
		if err = received.ReplyRenewal(ctx, result); err != nil {
			return err
		}
	}
	return nil
}

func TestRunRenewsOverWSSWithStableLostACKIntent(t *testing.T) {
	f := newNetworkFixture(t, domain.Regular, 21*24*time.Hour)
	prior, priorErr := f.identity.StoredCredentialRef()
	require(t, priorErr)
	workerCtx, stopWorker := context.WithCancel(t.Context())
	workerDone := make(chan error, 1)
	go func() { workerDone <- serveRenewalLostACK(workerCtx, f) }()
	var workerJoined bool
	t.Cleanup(func() {
		stopWorker()
		if !workerJoined {
			require(t, <-workerDone)
		}
	})
	_, _, join := startRun(t, f)
	select {
	case err := <-workerDone:
		workerJoined = true
		require(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("renewal replay never reached exact completion")
	}
	snapshot := waitSnapshot(t, f, 3)
	if snapshot.CredentialMode != domain.Regular {
		t.Fatal("renewal guessed credential mode")
	}
	roots, err := f.cfg.DeviceRoots()
	require(t, err)
	certificate, ref, err := f.identity.Certificate(roots, time.Now())
	require(t, err)
	if ref != prior || certificate.Leaf.NotBefore.Before(f.ca.now) {
		t.Fatal("renewal did not atomically install current same-generation certificate")
	}
	if _, err = f.identity.PendingRenewal(); !errors.Is(err, deviceidentity.ErrAbsent) {
		t.Fatal("acknowledged renewal intent not consumed")
	}
	join()
}

func receiveRenewalAttempt(ctx context.Context, f *networkFixture) (*transport.Received, protocol.Frame, protocol.Renewal, []byte, error) {
	received, err := f.hub.Receive(ctx)
	if err != nil {
		return nil, protocol.Frame{}, protocol.Renewal{}, nil, err
	}
	frame, err := received.Claim(ctx)
	if err != nil {
		return nil, protocol.Frame{}, protocol.Renewal{}, nil, err
	}
	var request protocol.Renewal
	if frame.Type != protocol.RenewCertificate || protocol.DecodeStrict(frame.Payload, &request, 32<<10) != nil {
		return nil, protocol.Frame{}, protocol.Renewal{}, nil, ErrRenewal
	}
	csr, err := request.CSR()
	if err != nil {
		return nil, protocol.Frame{}, protocol.Renewal{}, nil, err
	}
	return received, frame, request, csr, nil
}

func issueRenewalAttempt(ctx context.Context, f *networkFixture, request protocol.Renewal, csr []byte) (domain.CertificateReceipt, error) {
	snapshot, err := f.hub.Snapshot("device")
	if err != nil {
		return domain.CertificateReceipt{}, err
	}
	return f.renewal.Renew(ctx, snapshot.Credential, domain.RequestID(request.RenewalID), csr)
}
