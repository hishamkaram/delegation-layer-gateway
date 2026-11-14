// Package deviceruntime composes connector-local identity, CLI ownership and
// outbound networking. Delegate remains the execution and outcome authority.
package deviceruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connectorconfig"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

var (
	ErrConfiguration = errors.New("device_runtime_configuration_invalid")
	ErrEnrollment    = errors.New("device_enrollment_failed")
	ErrConnection    = errors.New("device_connection_failed")
	ErrRenewal       = errors.New("device_renewal_failed")
	ErrCleanup       = errors.New("device_cleanup_unconfirmed")
)

type failure struct{ kind, cause error }

func (e failure) Error() string      { return e.kind.Error() }
func (e failure) Unwrap() []error    { return []error{e.kind, e.cause} }
func failed(kind, cause error) error { return failure{kind: kind, cause: cause} }

// Enroll persists the private key and exact CSR before token transmission. A
// lost response retries that CSR; the token is never placed in argv or logs.
func Enroll(ctx context.Context, cfg *connectorconfig.Config, store *deviceidentity.Store, token string) error {
	if store == nil {
		return ErrConfiguration
	}
	return enrollWith(ctx, cfg, store, token, store.InstallEnrollment)
}

type enrollmentInstaller func([]byte, domain.CredentialRef, *x509.CertPool, time.Time) error

// Reenroll is an explicit operator replacement, including expired local records.
// It never runs from Run or renewal recovery and never acknowledges a renewal.
func Reenroll(ctx context.Context, cfg *connectorconfig.Config, store *deviceidentity.Store, token string) error {
	if ctx == nil || cfg == nil || store == nil {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	prior, err := store.StoredCredentialRef()
	if err != nil || prior.Device != cfg.DeviceID() {
		return failed(ErrEnrollment, err)
	}
	install := func(der []byte, next domain.CredentialRef, roots *x509.CertPool, now time.Time) error {
		if next == prior {
			certificate, current, readErr := store.Certificate(roots, now)
			if readErr != nil {
				return readErr
			}
			if current != prior || len(certificate.Certificate) != 1 || !bytes.Equal(certificate.Certificate[0], der) {
				return deviceidentity.ErrConflict
			}
			return nil // Exact current valid DER retry; no state or pending intent changes.
		}
		return store.ReplaceEnrollment(der, prior, next, roots, now)
	}
	return enrollWith(ctx, cfg, store, token, install)
}

func enrollWith(ctx context.Context, cfg *connectorconfig.Config, store *deviceidentity.Store, token string, install enrollmentInstaller) (result error) {
	if ctx == nil || cfg == nil || store == nil {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return ErrEnrollment
	}
	csr, err := store.EnsureKey(rand.Reader)
	if err != nil {
		return failed(ErrEnrollment, err)
	}
	roots, err := cfg.Roots()
	if err != nil {
		return failed(ErrEnrollment, err)
	}
	encoded, err := json.Marshal(protocol.EnrollmentRequest{Token: token, CSRDERBase64: base64.StdEncoding.EncodeToString(csr)})
	if err != nil {
		return failed(ErrEnrollment, err)
	}
	client, owned := directClient(roots, nil, cfg.NetworkTimeout())
	defer owned.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EnrollmentURL().String(), bytes.NewReader(encoded))
	if err != nil {
		return failed(ErrEnrollment, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return failed(ErrEnrollment, err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			result = failed(ErrEnrollment, errors.Join(result, closeErr))
		}
	}()
	deviceRoots, err := cfg.DeviceRoots()
	if err != nil {
		return failed(ErrEnrollment, err)
	}
	return installEnrollment(response, cfg, deviceRoots, time.Now(), install)
}

func directClient(roots *x509.CertPool, certificate *tls.Certificate, timeout time.Duration) (*http.Client, *http.Transport) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	owned := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true}
	return &http.Client{Transport: owned, Timeout: timeout, Jar: nil, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, owned
}

// installEnrollment borrows the body; enrollWith owns its close.
func installEnrollment(response *http.Response, cfg *connectorconfig.Config, roots *x509.CertPool, now time.Time, install enrollmentInstaller) (result error) {
	data, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxEnrollmentBodyBytes+1))
	if err != nil || response.StatusCode != http.StatusOK || len(data) > protocol.MaxEnrollmentBodyBytes {
		return failed(ErrEnrollment, err)
	}
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || media != "application/json" {
		return ErrEnrollment
	}
	var output protocol.EnrollmentResponse
	if protocol.DecodeStrict(data, &output, protocol.MaxEnrollmentBodyBytes) != nil || output.DeviceID != string(cfg.DeviceID()) || output.Mode.Validate() != nil {
		return ErrEnrollment
	}
	ref := domain.CredentialRef{Device: domain.DeviceID(output.DeviceID), Epoch: domain.CredentialEpoch(output.Epoch), Generation: output.Generation}
	der, err := base64.StdEncoding.Strict().DecodeString(output.CertificateDERBase64)
	if err != nil || len(der) == 0 || len(der) > 16<<10 || base64.StdEncoding.EncodeToString(der) != output.CertificateDERBase64 || ref.Validate() != nil {
		return ErrEnrollment
	}
	if err = install(der, ref, roots, now); err != nil {
		return failed(ErrEnrollment, err)
	}
	return nil
}
