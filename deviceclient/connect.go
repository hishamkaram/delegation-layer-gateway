package deviceclient

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

// Connect discovers and pins the Gateway, then durably enrolls one identity.
// A failed/uncertain request is retried with its original request ID and CSR.
func Connect(ctx context.Context, input ConnectOptions) (status ConnectionStatus, result error) {
	if ctx == nil {
		return status, ErrConfiguration
	}
	options, err := checkedOptions(input)
	if err != nil {
		return status, err
	}
	client, transport, err := httpClient(options.PrivateCAFile)
	if err != nil {
		return status, err
	}
	defer transport.CloseIdleConnections()
	descriptor, issuer, err := discover(ctx, client, options.GatewayURL)
	if err != nil {
		return status, err
	}
	store, err := openProfile(options.ProfileDirectory, true, true)
	if err != nil {
		return status, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrPersistence, closeErr))
		}
	}()
	next, err := pinnedProfile(options, descriptor, issuer, store.value, rand.Reader)
	if err != nil {
		return status, err
	}
	if store.value == nil {
		if err = store.save(next); err != nil {
			return status, err
		}
	}
	return enrollProfile(ctx, client, store, next, options)
}

func enrollProfile(ctx context.Context, client *http.Client, profileStore *profileStore, next profile, options ConnectOptions) (status ConnectionStatus, result error) {
	options.DeviceName = next.DeviceName
	identity, err := deviceidentity.Open(filepath.Join(options.ProfileDirectory, "identity"))
	if err != nil {
		return status, failed(ErrProfile, err)
	}
	defer func() {
		if closeErr := identity.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrPersistence, closeErr))
		}
	}()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(next.Descriptor.DeviceCAPEM)) {
		return status, ErrDiscovery
	}
	if _, err = identity.EnsureKey(rand.Reader); err != nil {
		return status, failed(ErrPersistence, err)
	}
	var token enrollmentToken
	if options.EnrollmentTokenFile != "" || options.EnrollmentTokenReader != nil {
		token, err = readToken(ctx, options)
		if err != nil {
			return status, err
		}
	}
	intent, needsEnroll, err := selectIntent(identity, options, next.Descriptor.GatewayID, roots, token)
	if err != nil {
		return status, err
	}
	if needsEnroll {
		if options.EnrollmentTokenFile != "" || options.EnrollmentTokenReader != nil {
			err = enrollToken(ctx, client, identity, intent, next.Descriptor, token, roots)
		} else {
			var issuerErr error
			next, issuerErr = profileStore.withIssuer(ctx, client, next)
			if issuerErr != nil {
				return status, issuerErr
			}
			err = enrollSelf(ctx, client, identity, intent, next.Descriptor, next.Issuer, options, roots)
		}
		if err != nil {
			return status, err
		}
	}
	return observe(identity, next, roots)
}

func selectIntent(identity *deviceidentity.Store, options ConnectOptions, gatewayID string, roots *x509.CertPool, token enrollmentToken) (deviceidentity.EnrollmentIntent, bool, error) {
	previous, pendingErr := identity.EnrollmentIntent()
	if pendingErr != nil && !errors.Is(pendingErr, deviceidentity.ErrAbsent) {
		return previous, false, failed(ErrProfile, pendingErr)
	}
	_, ref, validErr := identity.Certificate(roots, time.Now())
	if pendingErr == nil && !previous.Completed {
		if err := matchesPending(previous, options, gatewayID, token); err != nil {
			return previous, false, err
		}
		return previous, true, nil
	}

	reuse, err := credentialDisposition(validErr, previous, options.ReplaceExisting, token)
	if err != nil || reuse {
		return previous, false, err
	}

	plan := deviceidentity.EnrollmentPlan{GatewayID: gatewayID, Name: options.DeviceName}
	if validErr == nil {
		plan.Prior = ref
	} else if !errors.Is(validErr, deviceidentity.ErrAbsent) {
		var metadataErr error
		plan.Prior, metadataErr = identity.StoredCredentialRef()
		if metadataErr != nil {
			return previous, false, failed(ErrProfile, metadataErr)
		}
	}
	// Bind token retries without retaining the raw credential.
	if token.Token != "" {
		plan.TokenDevice = domain.DeviceID(token.DeviceID)
		plan.TokenSHA256 = domain.Hash([]byte(token.Token))
	}
	if plan.Validate() != nil {
		return previous, false, ErrConflict
	}
	intent, err := identity.BeginEnrollment(plan, rand.Reader)
	if err != nil {
		return intent, false, failed(ErrPersistence, err)
	}
	return intent, true, nil
}

func credentialDisposition(validErr error, previous deviceidentity.EnrollmentIntent, replace bool, token enrollmentToken) (bool, error) {
	if sameCompletedToken(previous, token) {
		if validErr == nil {
			return true, nil
		}
		return false, ErrReplacementRequired
	}
	if validErr == nil {
		// Repeating a completed explicit replacement reuses the valid credential.
		return !replace || previous.Plan.Prior != (domain.CredentialRef{}), nil
	}
	if !errors.Is(validErr, deviceidentity.ErrAbsent) && !replace {
		return false, ErrReplacementRequired
	}
	return false, nil
}

func sameCompletedToken(previous deviceidentity.EnrollmentIntent, token enrollmentToken) bool {
	return previous.Completed && previous.Plan.TokenDevice != "" && string(previous.Plan.TokenDevice) == token.DeviceID && token.Token != "" && previous.Plan.TokenSHA256 == domain.Hash([]byte(token.Token))
}

func matchesPending(previous deviceidentity.EnrollmentIntent, options ConnectOptions, gatewayID string, token enrollmentToken) error {
	if previous.Plan.GatewayID != gatewayID || previous.Plan.Name != options.DeviceName {
		return ErrConflict
	}
	if previous.Plan.Prior != (domain.CredentialRef{}) && !options.ReplaceExisting {
		return ErrReplacementRequired
	}
	tokenMode := options.EnrollmentTokenFile != "" || options.EnrollmentTokenReader != nil
	if tokenMode != (previous.Plan.TokenDevice != "") {
		return ErrConflict
	}
	if tokenMode && (string(previous.Plan.TokenDevice) != token.DeviceID || previous.Plan.TokenSHA256 != domain.Hash([]byte(token.Token))) {
		return ErrConflict
	}
	return nil
}

func enrollSelf(ctx context.Context, client *http.Client, identity *deviceidentity.Store, intent deviceidentity.EnrollmentIntent, d contract.Descriptor, issuer issuerEndpoints, options ConnectOptions, roots *x509.CertPool) error {
	if options.PresentChallenge == nil {
		return ErrConfiguration
	}
	scopes := []string{string(domain.DeviceEnroll)}
	if intent.Plan.Prior != (domain.CredentialRef{}) {
		scopes = append(scopes, string(domain.DeviceManage))
	}
	token, err := authorizeDevice(ctx, client, d, issuer, scopes, options.PresentChallenge)
	if err != nil {
		return err
	}

	request := contract.EnrollmentRequest{RequestID: intent.RequestID, Name: intent.Plan.Name, CSRDERBase64: base64.StdEncoding.EncodeToString(intent.CSRDER)}
	if intent.Plan.Prior != (domain.CredentialRef{}) {
		request.ReplaceDeviceID = string(intent.Plan.Prior.Device)
		request.ExpectedGeneration = intent.Plan.Prior.Generation
	}
	var response contract.EnrollmentResponse
	if err = requestJSON(ctx, client, http.MethodPost, d.SelfEnrollmentURL, token, request, &response, true); err != nil {
		return err
	}
	if response.RequestID != intent.RequestID {
		return ErrEnrollment
	}
	return complete(identity, intent, response.OwnerPrincipal, response.EnrollmentResponse, roots)
}

func enrollToken(ctx context.Context, client *http.Client, identity *deviceidentity.Store, intent deviceidentity.EnrollmentIntent, d contract.Descriptor, token enrollmentToken, roots *x509.CertPool) error {
	if string(intent.Plan.TokenDevice) != token.DeviceID {
		return ErrConflict
	}
	request := protocol.EnrollmentRequest{Token: token.Token, CSRDERBase64: base64.StdEncoding.EncodeToString(intent.CSRDER), RequireOwned: true}
	var response protocol.EnrollmentResponse
	if err := requestJSON(ctx, client, http.MethodPost, d.EnrollmentURL, "", request, &response, true); err != nil {
		return err
	}
	return complete(identity, intent, "", response, roots)
}

func complete(identity *deviceidentity.Store, intent deviceidentity.EnrollmentIntent, owner string, response protocol.EnrollmentResponse, roots *x509.CertPool) error {
	expected := domain.CredentialRef{Device: domain.DeviceID(response.DeviceID), Epoch: domain.CredentialEpoch(response.Epoch), Generation: response.Generation}
	der, err := base64.StdEncoding.DecodeString(response.CertificateDERBase64)
	if err != nil || base64.StdEncoding.EncodeToString(der) != response.CertificateDERBase64 || response.Mode != domain.Regular || expected.Validate() != nil {
		return ErrEnrollment
	}
	if intent.Plan.Prior == (domain.CredentialRef{}) && intent.Plan.TokenDevice == "" && response.Generation != 1 {
		return ErrEnrollment
	}
	if err = identity.CompleteEnrollment(intent.RequestID, owner, der, expected, roots, time.Now()); err != nil {
		return failed(ErrEnrollment, err)
	}
	return nil
}
