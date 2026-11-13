package deviceruntime

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func nextRenewal(store *deviceidentity.Store, certificate *x509.Certificate, now time.Time) (time.Duration, error) {
	if _, err := store.PendingRenewal(); err == nil {
		return 0, nil
	} else if !errors.Is(err, deviceidentity.ErrAbsent) {
		return 0, failed(ErrRenewal, err)
	}
	if certificate == nil {
		return 0, ErrRenewal
	}
	delay := certificate.NotBefore.Add(domain.RenewalAfter).Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, nil
}

// renew persists one ID+CSR before reserving a frame. All uncertainty leaves the
// intent intact; a reconnect retries the same semantic request with a new frame.
func renew(ctx context.Context, cfg Configuration, store *deviceidentity.Store, client *transport.Client, roots *x509.CertPool, now func() time.Time) error {
	certificate, ref, err := store.Certificate(roots, now())
	if err != nil || ref.Device != cfg.DeviceID() || certificate.Leaf == nil {
		return failed(ErrRenewal, err)
	}
	intent, err := store.BeginRenewal(ref, rand.Reader)
	if err != nil {
		return failed(ErrRenewal, err)
	}
	request := protocol.Renewal{DeviceID: string(ref.Device), RenewalID: intent.ID, CredentialGeneration: ref.Generation, CSRDERBase64: base64.StdEncoding.EncodeToString(intent.CSRDER)}
	if _, err = request.CSR(); err != nil {
		return failed(ErrRenewal, err)
	}
	payload, err := protocol.Encode(request, 32<<10)
	if err != nil {
		return failed(ErrRenewal, err)
	}
	observation, cancel := context.WithTimeout(ctx, cfg.NetworkTimeout())
	defer cancel()
	reservation, err := client.Reserve(observation, protocol.Frame{Version: client.WireVersion(), Type: protocol.RenewCertificate, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload})
	if err != nil {
		return failed(ErrRenewal, err)
	}
	if err = reservation.Publish(observation, nil); err != nil {
		return failed(ErrRenewal, err)
	}
	frame, err := reservation.Await(observation)
	if err != nil {
		return failed(ErrRenewal, err)
	}
	generation := client.Generation()
	if frame.Type != protocol.RenewCertificateResult || frame.OperationID != "" || frame.RequestID != reservation.Frame().RequestID || frame.Generation != (protocol.Generation{BootEpoch: string(generation.BootEpoch), Counter: generation.Counter}) {
		return ErrRenewal
	}
	return installRenewal(frame.Payload, intent, store, roots, now())
}

func installRenewal(data []byte, intent deviceidentity.RenewalIntent, store *deviceidentity.Store, roots *x509.CertPool, now time.Time) error {
	var result protocol.RenewalResult
	if protocol.DecodeStrict(data, &result, 32<<10) != nil || result.Validate() != nil || result.Error != nil || result.DeviceID != string(intent.Credential.Device) || result.RenewalID != intent.ID || result.Epoch != string(intent.Credential.Epoch) || result.Generation != intent.Credential.Generation {
		return ErrRenewal
	}
	der, err := base64.StdEncoding.Strict().DecodeString(result.CertificateDERBase64)
	if err != nil || base64.StdEncoding.EncodeToString(der) != result.CertificateDERBase64 {
		return ErrRenewal
	}
	if err = store.CompleteRenewal(intent.ID, der, roots, now); err != nil {
		return failed(ErrRenewal, err)
	}
	return nil
}
