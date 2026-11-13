package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

const (
	MaxTokenBytes         = 16 << 10
	MaxJWKSBytes          = 256 << 10
	MaxJWKSKeys           = 100
	DefaultCacheTTL       = 5 * time.Minute
	DefaultRequestTimeout = 5 * time.Second
	MinimumRefresh        = 30 * time.Second
)

// PrincipalResolver is fulfilled by registry.Store. Resolution does not grant
// device/project rights; every consumer still authorizes against current grants.
type PrincipalResolver interface {
	ResolvePrincipal(context.Context, domain.ExternalSubject) (domain.Principal, error)
}

type Config struct {
	Issuer          string
	Audience        string
	JWKSURL         string
	CacheTTL        time.Duration
	RefreshInterval time.Duration
	RequestTimeout  time.Duration
}

// Authenticator owns one immutable JWKS snapshot and its invalidation times.
// Refreshes are single-flight and caller-owned, with no background goroutines.
// The injected client transport and clock must support concurrent calls.
type Authenticator struct {
	config    Config
	client    http.Client
	now       func() time.Time
	resolver  PrincipalResolver
	validator *validator.Validator
	refresh   chan struct{}
	mu        sync.RWMutex
	keys      jwk.Set
	expires   time.Time
	nextFetch time.Time
}

type keyIDContext struct{}

func NewAuthenticator(config Config, client *http.Client, now func() time.Time, resolver PrincipalResolver) (*Authenticator, error) {
	config, err := checkedConfig(config)
	if err != nil || client == nil || now == nil || resolver == nil {
		return nil, reject(InvalidConfiguration, err)
	}
	owned := *client
	owned.Timeout = config.RequestTimeout
	owned.Jar = nil
	owned.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	a := &Authenticator{config: config, client: owned, now: now, resolver: resolver, refresh: make(chan struct{}, 1)}
	a.validator, err = validator.New(
		validator.WithKeyFunc(a.verificationKeys),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuer(config.Issuer),
		validator.WithAudience(config.Audience),
		validator.WithCustomClaims(func() *scopeClaims { return &scopeClaims{} }),
		validator.WithRegisteredClaimsValidator(checkRegisteredClaims),
	)
	if err != nil {
		return nil, reject(InvalidConfiguration, err)
	}
	return a, nil
}

func checkedConfig(c Config) (Config, error) {
	for _, value := range []string{c.Issuer, c.Audience, c.JWKSURL} {
		if !fixedHTTPS(value) {
			return Config{}, domain.ErrInvalid
		}
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	if c.RefreshInterval == 0 {
		c.RefreshInterval = MinimumRefresh
	}
	if c.CacheTTL <= 0 || c.CacheTTL > DefaultCacheTTL || c.RequestTimeout <= 0 || c.RequestTimeout > DefaultRequestTimeout || c.RefreshInterval < MinimumRefresh || c.RefreshInterval > DefaultCacheTTL {
		return Config{}, domain.ErrInvalid
	}
	return c, nil
}

func fixedHTTPS(value string) bool {
	u, err := url.Parse(value)
	return err == nil && len(value) <= 2048 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == ""
}

// VerifiedToken carries only signature-validated claims needed by the HTTP edge.
// The registry remains the authority for principal revocation and grants.
type VerifiedToken struct {
	Actor     domain.Actor
	ExpiresAt time.Time
}

func (a *Authenticator) Authenticate(ctx context.Context, token string) (domain.Actor, error) {
	verified, err := a.AuthenticateToken(ctx, token)
	return verified.Actor, err
}

func (a *Authenticator) AuthenticateToken(ctx context.Context, token string) (VerifiedToken, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedToken{}, reject(InvalidToken, err)
	}
	kid, err := tokenKeyID(token)
	if err != nil {
		return VerifiedToken{}, reject(InvalidToken, err)
	}
	verified, err := a.validator.ValidateToken(context.WithValue(ctx, keyIDContext{}, kid), token)
	if err != nil {
		return VerifiedToken{}, authenticationError(err)
	}
	claims, ok := verified.(*validator.ValidatedClaims)
	if !ok || claims == nil {
		return VerifiedToken{}, reject(InvalidToken, nil)
	}
	if claims.RegisteredClaims.Issuer != a.config.Issuer {
		return VerifiedToken{}, reject(InvalidToken, nil)
	}
	scopes, ok := claims.CustomClaims.(*scopeClaims)
	if !ok || scopes == nil {
		return VerifiedToken{}, reject(InvalidToken, nil)
	}
	subject := domain.ExternalSubject{Issuer: claims.RegisteredClaims.Issuer, Subject: claims.RegisteredClaims.Subject}
	principal, err := a.resolver.ResolvePrincipal(ctx, subject)
	if err != nil {
		return VerifiedToken{}, reject(PrincipalUnavailable, err)
	}
	if principal.Revoked {
		return VerifiedToken{}, reject(PrincipalRevoked, nil)
	}
	if principal.Subject != subject {
		return VerifiedToken{}, reject(PrincipalUnavailable, nil)
	}
	actor := domain.Actor{Principal: principal.ID, Scopes: append(domain.ScopeSet(nil), scopes.scopes...)}
	if err := actor.Validate(); err != nil {
		return VerifiedToken{}, reject(PrincipalUnavailable, err)
	}
	return VerifiedToken{Actor: actor, ExpiresAt: time.Unix(claims.RegisteredClaims.Expiry, 0)}, nil
}

func authenticationError(err error) error {
	var identityError *Error
	if errors.As(err, &identityError) {
		return identityError
	}
	return reject(InvalidToken, err)
}

func tokenKeyID(token string) (string, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return "", domain.ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", domain.ErrInvalid
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", domain.ErrInvalid
	}
	var h struct {
		Algorithm string          `json:"alg"`
		KeyID     string          `json:"kid"`
		JKU       json.RawMessage `json:"jku"`
		X5U       json.RawMessage `json:"x5u"`
		JWK       json.RawMessage `json:"jwk"`
		X5C       json.RawMessage `json:"x5c"`
		Critical  json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return "", domain.ErrInvalid
	}
	if h.Algorithm != "RS256" || domain.Token(h.KeyID) != nil || len(h.JKU)+len(h.X5U)+len(h.JWK)+len(h.X5C)+len(h.Critical) != 0 {
		return "", domain.ErrInvalid
	}
	return h.KeyID, nil
}

func checkRegisteredClaims(c validator.RegisteredClaims) error {
	if c.Expiry <= 0 || !utf8.ValidString(c.Subject) {
		return domain.ErrInvalid
	}
	for _, char := range c.Subject {
		if char < ' ' || char == 127 {
			return domain.ErrInvalid
		}
	}
	return (domain.ExternalSubject{Issuer: c.Issuer, Subject: c.Subject}).Validate()
}

type scopeClaims struct {
	Scope  string `json:"scope"`
	scopes domain.ScopeSet
}

func (c *scopeClaims) Validate(_ context.Context) error {
	if len(c.Scope) == 0 || len(c.Scope) > 1024 {
		return domain.ErrInvalid
	}
	for _, char := range c.Scope {
		if char < ' ' || char > '~' || char == '"' || char == '\\' {
			return domain.ErrInvalid
		}
	}
	seen := make(map[domain.Scope]bool)
	for _, value := range strings.Split(c.Scope, " ") {
		scope := domain.Scope(value)
		if scope.Validate() == nil && !seen[scope] {
			c.scopes = append(c.scopes, scope)
			seen[scope] = true
		}
	}
	if len(c.scopes) == 0 {
		return domain.ErrInvalid
	}
	return c.scopes.Validate()
}

func (a *Authenticator) cached(kid string, now time.Time) jwk.Set {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.keys != nil && now.Before(a.expires) {
		if _, ok := a.keys.LookupKeyID(kid); ok {
			return a.keys
		}
	}
	return nil
}

// The any result is required by Auth0's public WithKeyFunc contract; every
// successful value comes from jwk.Parse and remains an immutable jwk.Set.
func (a *Authenticator) verificationKeys(ctx context.Context) (any, error) {
	kid, ok := ctx.Value(keyIDContext{}).(string)
	if !ok {
		return nil, reject(InvalidToken, nil)
	}
	if keys := a.cached(kid, a.now()); keys != nil {
		return keys, nil
	}
	select {
	case a.refresh <- struct{}{}:
		defer func() { <-a.refresh }()
	case <-ctx.Done():
		return nil, reject(KeysUnavailable, ctx.Err())
	}
	now := a.now()
	if keys := a.cached(kid, now); keys != nil {
		return keys, nil
	}
	a.mu.Lock()
	if now.Before(a.nextFetch) {
		a.mu.Unlock()
		return nil, reject(KeysUnavailable, nil)
	}
	a.nextFetch = now.Add(a.config.RefreshInterval)
	a.mu.Unlock()
	keys, err := a.fetch(ctx)
	if err != nil {
		return nil, reject(KeysUnavailable, err)
	}
	a.mu.Lock()
	a.keys, a.expires = keys, a.now().Add(a.config.CacheTTL)
	a.mu.Unlock()
	if _, ok := keys.LookupKeyID(kid); !ok {
		return nil, reject(InvalidToken, nil)
	}
	return keys, nil
}

func (a *Authenticator) fetch(ctx context.Context) (jwk.Set, error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := a.client.Do(request)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, MaxJWKSBytes+1))
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK || len(data) > MaxJWKSBytes {
		return nil, domain.ErrInvalid
	}
	return parseKeys(data)
}

func parseKeys(data []byte) (jwk.Set, error) {
	var envelope struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Keys) == 0 || len(envelope.Keys) > MaxJWKSKeys {
		return nil, domain.ErrInvalid
	}
	set, err := jwk.Parse(data)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok {
			return nil, domain.ErrInvalid
		}
		kid, ok := key.KeyID()
		if !ok || domain.Token(kid) != nil || seen[kid] {
			return nil, domain.ErrInvalid
		}
		seen[kid] = true
	}
	return set, nil
}
