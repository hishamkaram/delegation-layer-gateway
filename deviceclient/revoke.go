package deviceclient

import (
	"context"
	"errors"
	"net/http"
	"reflect"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

var ErrRevocation = errors.New("gateway_device_revocation_failed")

// RevokeDevice performs a fresh manage-only login after acquiring local identity
// ownership. The verified Gateway owner decides authorization. It preserves all
// local credentials, pins and tasks, including after uncertain delivery.
func RevokeDevice(ctx context.Context, directory string, present func(context.Context, Challenge) error) (result error) {
	if ctx == nil || present == nil {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return failed(ErrTransport, err)
	}
	store, err := openProfile(directory, false, true)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrPersistence, closeErr))
		}
	}()
	if store.value == nil {
		return ErrProfile
	}
	identity, err := openExistingIdentity(directory)
	if err != nil {
		return err
	}

	defer func() {
		if closeErr := identity.Close(); closeErr != nil {
			result = errors.Join(result, failed(ErrPersistence, closeErr))
		}
	}()
	return revokeWithProfile(ctx, store, identity, present)
}

func revokeWithProfile(ctx context.Context, store *profileStore, identity *deviceidentity.Store, present func(context.Context, Challenge) error) error {
	ref, err := identity.StoredCredentialRef()
	if err != nil {
		return failed(ErrEnrollment, err)
	}
	current := *store.value
	client, transport, err := httpClient(current.PrivateCAFile)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	descriptor, _, err := discover(ctx, client, current.Descriptor.PublicURL)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(descriptor, current.Descriptor) {
		return ErrTrustChanged
	}
	current, err = store.withIssuer(ctx, client, current)
	if err != nil {
		return err
	}
	token, err := authorizeDevice(ctx, client, current.Descriptor, current.Issuer, []string{string(domain.DeviceManage)}, present)
	if err != nil {
		return err
	}
	request := contract.RevocationRequest{DeviceID: string(ref.Device)}
	var response contract.RevocationResponse
	if err = requestJSON(ctx, client, http.MethodPost, current.Descriptor.RevokeURL, token, request, &response, true); err != nil {
		return err
	}
	if response.DeviceID != request.DeviceID || !response.Revoked {
		return ErrRevocation
	}
	return nil
}
