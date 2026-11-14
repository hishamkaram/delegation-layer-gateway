package deviceclient

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
)

// Status reads a dated local profile observation. A running identity owner is
// reported as in use/unknown; it is not evidence of online or offline state.
func Status(ctx context.Context, profileDirectory string) (status ConnectionStatus, result error) {
	if ctx == nil {
		return status, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return status, failed(ErrTransport, err)
	}
	profile, err := openProfile(profileDirectory, false, false)
	if err != nil {
		return status, err
	}
	defer func() {
		if closeErr := profile.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrProfile, closeErr))
		}
	}()
	if profile.value == nil {
		return status, ErrProfile
	}
	value := *profile.value
	status = ConnectionStatus{GatewayID: value.Descriptor.GatewayID, GatewayURL: value.Descriptor.PublicURL, CredentialState: "absent", ObservedAt: time.Now().UTC()}
	directory := filepath.Join(profileDirectory, "identity")
	if _, err = os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return status, nil
	} else if err != nil {
		return status, ErrProfile
	}
	identity, err := deviceidentity.Open(directory)
	if identityBusyOnly(err) {
		status.IdentityInUse = true
		status.CredentialState = "unknown"
		return status, nil
	}
	if err != nil {
		return status, failed(ErrProfile, err)
	}
	defer func() {
		if err := identity.Close(); err != nil {
			result = errors.Join(result, failed(ErrProfile, err))
		}
	}()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(value.Descriptor.DeviceCAPEM)) {
		return status, ErrProfile
	}
	return observe(identity, value, roots)
}

func observe(identity *deviceidentity.Store, p profile, roots *x509.CertPool) (ConnectionStatus, error) {
	now := time.Now().UTC()
	status := ConnectionStatus{GatewayID: p.Descriptor.GatewayID, GatewayURL: p.Descriptor.PublicURL, CredentialState: "pending", ObservedAt: now}
	intent, intentErr := identity.EnrollmentIntent()
	if intentErr == nil {
		status.OwnerPrincipal = intent.OwnerPrincipal
	} else if !errors.Is(intentErr, deviceidentity.ErrAbsent) {
		return status, failed(ErrProfile, intentErr)
	}
	ref, expiry, err := identity.CredentialMetadata()
	if err != nil {
		if errors.Is(err, deviceidentity.ErrAbsent) {
			return status, nil
		}
		return status, failed(ErrProfile, err)
	}
	status.DeviceID = string(ref.Device)
	status.CredentialGeneration = ref.Generation
	status.CertificateExpiresAt = expiry
	if _, _, err = identity.Certificate(roots, now); err != nil {
		if !errors.Is(err, deviceidentity.ErrInvalid) && !errors.Is(err, deviceidentity.ErrAbsent) {
			return status, failed(ErrProfile, err)
		}
		status.CredentialState = "unusable"
	} else {
		status.CredentialState = "valid"
	}
	return status, nil
}
