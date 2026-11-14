package deviceclient

import (
	"context"
	"net/http"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceauth"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

// authorizeDevice is the single SDK device-auth composition. The existing
// bounded issuer client owns polling; presentation remains caller-controlled.
func authorizeDevice(ctx context.Context, client *http.Client, d contract.Descriptor, issuer issuerEndpoints, scopes []string, present func(context.Context, Challenge) error) (string, error) {
	if present == nil {
		return "", ErrConfiguration
	}
	auth, err := deviceauth.New(deviceauth.Config{ClientID: d.NativeClientID, DeviceEndpoint: issuer.Device, TokenEndpoint: issuer.Token, Audience: d.Audience, Scopes: scopes, HTTPClient: client})
	if err != nil {
		return "", failed(ErrConfiguration, err)
	}
	challenge, err := auth.Begin(ctx)
	if err != nil {
		return "", failed(ErrDenied, err)
	}
	if err = present(ctx, Challenge{UserCode: challenge.UserCode(), VerificationURI: challenge.VerificationURI(), VerificationURIComplete: challenge.VerificationURIComplete(), ExpiresAt: challenge.ExpiresAt()}); err != nil {
		return "", failed(ErrDenied, err)
	}
	token, err := auth.Await(ctx, challenge)
	if err != nil {
		return "", failed(ErrDenied, err)
	}
	return token, nil
}
