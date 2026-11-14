// Package deviceauth performs a bounded issuer-native device authorization.
// The caller owns transport cleanup, browser interaction and durable enrollment
// identity. This package retains authorization secrets only in memory.
package deviceauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
)

const (
	DefaultFlowTimeout = 10 * time.Minute
	MaxFlowTimeout     = 15 * time.Minute
	MaxRequestTimeout  = 30 * time.Second
	MaxResponseBytes   = 64 << 10
	maxIntervalSeconds = 300
	maxExpirySeconds   = 24 * 60 * 60
)

var (
	ErrConfiguration = errors.New("device_auth_invalid_configuration")
	ErrResponse      = errors.New("device_auth_invalid_response")
	ErrTransport     = errors.New("device_auth_transport_failed")
	ErrDenied        = errors.New("device_auth_access_denied")
	ErrExpired       = errors.New("device_auth_expired")
	ErrCancelled     = errors.New("device_auth_cancelled")
	ErrIssuer        = errors.New("device_auth_issuer_rejected")
	ErrConsumed      = errors.New("device_auth_challenge_consumed")
)

// Config contains verified issuer endpoints, not discovery or browser policy.
// HTTPClient must be nonnil; the caller owns its transport and cleanup. New
// copies the client value, bounds its timeout and disallows redirects.
type Config struct {
	ClientID       string
	DeviceEndpoint string
	TokenEndpoint  string
	Audience       string
	Scopes         []string
	HTTPClient     *http.Client
	FlowTimeout    time.Duration
}

// Client is immutable after construction and may begin independent flows.
type Client struct {
	oauth       oauth2.Config
	http        http.Client
	audience    string
	flowTimeout time.Duration
}

// Challenge is an immutable authorization response belonging to one Client.
// Only one Await may consume it. DeviceCode is deliberately not exported.
type Challenge struct {
	authorization oauth2.DeviceAuthResponse
	owner         *Client
	consumed      *atomic.Bool
}

func (c *Challenge) UserCode() string                { return c.authorization.UserCode }
func (c *Challenge) VerificationURI() string         { return c.authorization.VerificationURI }
func (c *Challenge) VerificationURIComplete() string { return c.authorization.VerificationURIComplete }
func (c *Challenge) ExpiresAt() time.Time            { return c.authorization.Expiry }

// String and GoString prevent ordinary formatted diagnostics from exposing
// either the device secret or the user-facing authorization code.
func (c *Challenge) String() string   { return "device_auth_challenge" }
func (c *Challenge) GoString() string { return c.String() }

func New(input Config) (*Client, error) {
	if !validConfig(input) {
		return nil, ErrConfiguration
	}
	if input.FlowTimeout == 0 {
		input.FlowTimeout = DefaultFlowTimeout
	}
	httpClient := *input.HTTPClient
	if httpClient.Timeout <= 0 || httpClient.Timeout > MaxRequestTimeout {
		httpClient.Timeout = MaxRequestTimeout
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		oauth: oauth2.Config{
			ClientID: input.ClientID,
			Scopes:   slices.Clone(input.Scopes),
			Endpoint: oauth2.Endpoint{
				DeviceAuthURL: input.DeviceEndpoint,
				TokenURL:      input.TokenEndpoint,
				AuthStyle:     oauth2.AuthStyleInParams,
			},
		},
		http:        httpClient,
		audience:    input.Audience,
		flowTimeout: input.FlowTimeout,
	}, nil
}

// Begin requests one device code. The finite flow deadline starts before this
// request and cannot be extended by a delayed Await or a fresh caller context.
func (c *Client) Begin(ctx context.Context) (challenge *Challenge, result error) {
	if c == nil || ctx == nil {
		return nil, ErrConfiguration
	}
	start := time.Now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(c.flowTimeout))
	defer cancel()
	deadline, _ := ctx.Deadline()
	values := url.Values{"client_id": {c.oauth.ClientID}, "audience": {c.audience}, "scope": {strings.Join(c.oauth.Scopes, " ")}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauth.Endpoint.DeviceAuthURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, ErrConfiguration
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, transportError(ctx)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			challenge = nil
			result = errors.Join(result, ErrTransport)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, transportError(ctx)
	}
	if len(body) > MaxResponseBytes {
		return nil, ErrResponse
	}
	if response.StatusCode != http.StatusOK {
		return nil, issuerResponseError(body)
	}
	content, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || content != "application/json" {
		return nil, ErrResponse
	}
	authorization, err := parseResponse(body, start, deadline)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, transportError(ctx)
	}
	return &Challenge{authorization: authorization, owner: c, consumed: &atomic.Bool{}}, nil
}

// Await polls through the pinned OAuth implementation. It neither retries an
// ended flow nor starts a replacement. The access token is returned only to its
// caller; neither issuer bodies nor authorization secrets appear in errors.
func (c *Client) Await(ctx context.Context, challenge *Challenge) (string, error) {
	if c == nil || ctx == nil || challenge == nil || challenge.owner != c || challenge.consumed == nil {
		return "", ErrConfiguration
	}
	if !challenge.consumed.CompareAndSwap(false, true) {
		return "", ErrConsumed
	}
	ctx, cancel := context.WithDeadline(ctx, challenge.authorization.Expiry)
	defer cancel()
	if ctx.Err() != nil {
		return "", transportError(ctx)
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &c.http)
	token, err := c.oauth.DeviceAccessToken(ctx, &challenge.authorization)
	if err != nil {
		return "", tokenError(ctx, err)
	}
	if token == nil || !strings.EqualFold(token.TokenType, "Bearer") || !visible(token.AccessToken, 16<<10, false) {
		return "", ErrResponse
	}
	return token.AccessToken, nil
}

func transportError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return errors.Join(ErrCancelled, context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.Join(ErrExpired, context.DeadlineExceeded)
	}
	return ErrTransport
}

func tokenError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return transportError(ctx)
	}
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) {
		return issuerErrorCode(retrieve.ErrorCode)
	}
	var network *url.Error
	if errors.As(err, &network) {
		return ErrTransport
	}
	return ErrResponse
}

func issuerResponseError(body []byte) error {
	var response struct {
		Code string `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil {
		return ErrIssuer
	}
	return issuerErrorCode(response.Code)
}

func issuerErrorCode(code string) error {
	switch code {
	case "access_denied":
		return ErrDenied
	case "expired_token":
		return ErrExpired
	case "invalid_client", "invalid_scope", "unauthorized_client", "unsupported_grant_type":
		return ErrConfiguration
	default:
		return ErrIssuer
	}
}
