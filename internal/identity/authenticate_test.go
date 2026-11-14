package identity_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
)

type resolverFunc func(context.Context, domain.ExternalSubject) (domain.Principal, error)

func (f resolverFunc) ResolvePrincipal(ctx context.Context, s domain.ExternalSubject) (domain.Principal, error) {
	return f(ctx, s)
}

type testClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = c.value.Add(d)
}

type keyServer struct {
	mu       sync.Mutex
	body     []byte
	status   int
	requests int
}

func (s *keyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if r.URL.Path != "/keys" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "max-age=604800")
	w.WriteHeader(s.status)
	if _, err := w.Write(s.body); err != nil {
		return
	}
}

func TestConcurrentJWKSFetchHasOneOwner(t *testing.T) {
	key := rsaKey(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	var requests atomic.Int64
	body := jwksBody(t, key, "one")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		once.Do(func() { close(started) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if _, err := w.Write(body); err != nil {
			return
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	a := authenticator(t, server, &testClock{value: time.Now()}, validResolver)
	token := jwtToken(t, key, map[string]any{"alg": "RS256", "kid": "one"}, goodClaims(server.URL+"/"))
	const callers = 12
	results := make(chan error, callers)
	var workers sync.WaitGroup
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); workers.Wait() })
	for range callers {
		workers.Go(func() { _, err := a.Authenticate(t.Context(), token); results <- err })
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("JWKS request did not reach owner gate")
	}
	releaseOnce.Do(func() { close(release) })
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("fetches=%d, want one shared fetch", requests.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := a.Authenticate(ctx, token)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestAuthenticationConfigurationBounds(t *testing.T) {
	valid := identity.Config{Issuer: "https://issuer.example/", Audience: "https://gateway.example/mcp", JWKSURL: "https://issuer.example/keys"}
	for _, test := range []struct {
		name   string
		change func(*identity.Config)
	}{
		{"plaintext issuer", func(c *identity.Config) { c.Issuer = "http://issuer.example/" }},
		{"token URL", func(c *identity.Config) { c.JWKSURL = "https://issuer.example/keys?secret=value" }},
		{"cache too long", func(c *identity.Config) { c.CacheTTL = 6 * time.Minute }},
		{"refresh too frequent", func(c *identity.Config) { c.RefreshInterval = time.Second }},
		{"timeout too long", func(c *identity.Config) { c.RequestTimeout = 6 * time.Second }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := valid
			test.change(&c)
			_, err := identity.NewAuthenticator(c, &http.Client{}, time.Now, resolverFunc(validResolver))
			requireCode(t, err, identity.InvalidConfiguration)
		})
	}
}

func (s *keyServer) set(body []byte, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
	s.status = status
}
func (s *keyServer) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.requests }

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func encodeJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func jwksBody(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	return encodeJSON(t, map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
}

func jwtToken(t *testing.T, key *rsa.PrivateKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	unsigned := base64.RawURLEncoding.EncodeToString(encodeJSON(t, header)) + "." + base64.RawURLEncoding.EncodeToString(encodeJSON(t, claims))
	hash := crypto.SHA256.New()
	if _, err := hash.Write([]byte(unsigned)); err != nil {
		t.Fatal(err)
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func goodClaims(issuer string) map[string]any {
	return map[string]any{"iss": issuer, "aud": "https://gateway.example/mcp", "sub": "auth0|subject", "exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix(), "scope": "openid task:read task:dispatch"}
}

func validResolver(_ context.Context, subject domain.ExternalSubject) (domain.Principal, error) {
	return domain.Principal{ID: "principal-one", Subject: subject}, nil
}

func authenticator(t *testing.T, server *httptest.Server, clock *testClock, resolver resolverFunc) *identity.Authenticator {
	t.Helper()
	a, err := identity.NewAuthenticator(identity.Config{Issuer: server.URL + "/", Audience: "https://gateway.example/mcp", JWKSURL: server.URL + "/keys"}, server.Client(), clock.now, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func requireCode(t *testing.T, err error, code identity.ErrorCode) {
	t.Helper()
	var typed *identity.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error=%v, want %s", err, code)
	}
}

func TestAuthenticateTLSAndClaims(t *testing.T) {
	key := rsaKey(t)
	state := &keyServer{body: jwksBody(t, key, "key-one"), status: http.StatusOK}
	server := httptest.NewTLSServer(state)
	t.Cleanup(server.Close)
	clock := &testClock{value: time.Now()}
	a := authenticator(t, server, clock, validResolver)
	claims := goodClaims(server.URL + "/")
	expiry := time.Now().Add(45 * time.Minute).Truncate(time.Second)
	claims["exp"] = expiry.Unix()
	header := map[string]any{"alg": "RS256", "kid": "key-one"}
	token := jwtToken(t, key, header, claims)
	actor, err := a.Authenticate(t.Context(), token)
	if err != nil || actor.Principal != "principal-one" || !actor.Scopes.Has(domain.TaskRead) || !actor.Scopes.Has(domain.TaskDispatch) {
		t.Fatalf("actor=%+v error=%v", actor, err)
	}
	verified, verificationErr := a.AuthenticateToken(t.Context(), token)
	if verificationErr != nil || !verified.ExpiresAt.Equal(expiry) || verified.Actor.Principal != actor.Principal {
		t.Fatalf("verified token expiry/actor lost: %+v %v", verified, verificationErr)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "https://attacker.example/" }},
		{"audience", func(c map[string]any) { c["aud"] = "https://other.example/" }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{"not yet valid", func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{"missing expiry", func(c map[string]any) { delete(c, "exp") }},
		{"empty subject", func(c map[string]any) { c["sub"] = " " }},
		{"control subject", func(c map[string]any) { c["sub"] = "subject\nprivate" }},
		{"missing scope", func(c map[string]any) { delete(c, "scope") }},
		{"no gateway scope", func(c map[string]any) { c["scope"] = "openid profile" }},
		{"wrong scope type", func(c map[string]any) { c["scope"] = []string{"task:read"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := goodClaims(server.URL + "/")
			test.mutate(c)
			_, tokenErr := a.Authenticate(t.Context(), jwtToken(t, key, header, c))
			requireCode(t, tokenErr, identity.InvalidToken)
		})
	}
	if state.count() != 1 {
		t.Fatalf("requests=%d, cached claims should not refetch", state.count())
	}
	for _, header := range []map[string]any{{"alg": "HS256", "kid": "key-one"}, {"alg": "RS256"}, {"alg": "RS256", "kid": "key-one", "jku": "https://private-canary.example/"}} {
		_, headerErr := a.Authenticate(t.Context(), jwtToken(t, key, header, claims))
		requireCode(t, headerErr, identity.InvalidToken)
	}
	_, err = a.Authenticate(t.Context(), strings.Repeat("x", identity.MaxTokenBytes+1))
	requireCode(t, err, identity.InvalidToken)
	_, err = a.Authenticate(t.Context(), token[:len(token)-10]+"aaaaaaaaaa")
	requireCode(t, err, identity.InvalidToken)
}

func TestManagementScopesAuthenticateWithoutTaskAuthority(t *testing.T) {
	key := rsaKey(t)
	server := httptest.NewTLSServer(&keyServer{body: jwksBody(t, key, "one"), status: http.StatusOK})
	t.Cleanup(server.Close)
	a := authenticator(t, server, &testClock{value: time.Now()}, validResolver)
	header := map[string]any{"alg": "RS256", "kid": "one"}
	management := goodClaims(server.URL + "/")
	management["scope"] = "device:enroll device:manage"
	manager, err := a.Authenticate(t.Context(), jwtToken(t, key, header, management))
	if err != nil || len(manager.Scopes) != 2 || !manager.Scopes.Has(domain.DeviceEnroll) || !manager.Scopes.Has(domain.DeviceManage) {
		t.Fatalf("management token lost its exact authority: %v", err)
	}
	for _, scope := range manager.Scopes {
		if scope.IsTask() {
			t.Fatal("management authentication invented task authority")
		}
	}
}

func TestJWKSRotationFailureAndHardCacheBound(t *testing.T) {
	one, two := rsaKey(t), rsaKey(t)
	state := &keyServer{body: jwksBody(t, one, "one"), status: http.StatusOK}
	server := httptest.NewTLSServer(state)
	t.Cleanup(server.Close)
	clock := &testClock{value: time.Now()}
	a := authenticator(t, server, clock, validResolver)
	tokenOne := jwtToken(t, one, map[string]any{"alg": "RS256", "kid": "one"}, goodClaims(server.URL+"/"))
	tokenTwo := jwtToken(t, two, map[string]any{"alg": "RS256", "kid": "two"}, goodClaims(server.URL+"/"))
	if _, err := a.Authenticate(t.Context(), tokenOne); err != nil {
		t.Fatal(err)
	}
	state.set(jwksBody(t, two, "two"), http.StatusServiceUnavailable)
	if _, err := a.Authenticate(t.Context(), tokenOne); err != nil {
		t.Fatal("fresh cache unavailable:", err)
	}
	_, err := a.Authenticate(t.Context(), tokenTwo)
	requireCode(t, err, identity.KeysUnavailable)
	if state.count() != 1 {
		t.Fatal("unknown kid bypassed minimum refresh interval")
	}
	clock.advance(31 * time.Second)
	_, err = a.Authenticate(t.Context(), tokenTwo)
	requireCode(t, err, identity.KeysUnavailable)
	if _, cachedErr := a.Authenticate(t.Context(), tokenOne); cachedErr != nil {
		t.Fatal("failed refresh invalidated still-fresh key:", cachedErr)
	}
	clock.advance(5 * time.Minute)
	_, err = a.Authenticate(t.Context(), tokenOne)
	requireCode(t, err, identity.KeysUnavailable)
	if state.count() != 3 {
		t.Fatalf("requests=%d; server max-age must not extend hard cache bound", state.count())
	}
	state.set(jwksBody(t, two, "two"), http.StatusOK)
	clock.advance(31 * time.Second)
	if _, err := a.Authenticate(t.Context(), tokenTwo); err != nil {
		t.Fatal("rotation recovery:", err)
	}
}

func TestPrincipalAuthorityAndRedactedErrors(t *testing.T) {
	key := rsaKey(t)
	server := httptest.NewTLSServer(&keyServer{body: jwksBody(t, key, "one"), status: http.StatusOK})
	t.Cleanup(server.Close)
	token := jwtToken(t, key, map[string]any{"alg": "RS256", "kid": "one"}, goodClaims(server.URL+"/"))
	for _, test := range []struct {
		name     string
		resolver resolverFunc
		code     identity.ErrorCode
	}{
		{"revoked", func(_ context.Context, s domain.ExternalSubject) (domain.Principal, error) {
			return domain.Principal{ID: "one", Subject: s, Revoked: true}, nil
		}, identity.PrincipalRevoked},
		{"mapping error", func(context.Context, domain.ExternalSubject) (domain.Principal, error) {
			return domain.Principal{}, errors.New("private-mapping-canary")
		}, identity.PrincipalUnavailable},
		{"wrong binding", func(context.Context, domain.ExternalSubject) (domain.Principal, error) {
			return domain.Principal{ID: "one"}, nil
		}, identity.PrincipalUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := authenticator(t, server, &testClock{value: time.Now()}, test.resolver)
			_, err := a.Authenticate(t.Context(), token)
			requireCode(t, err, test.code)
			if strings.Contains(fmt.Sprintf("%+v", err), "private-mapping-canary") {
				t.Fatal("error leaked mapping data")
			}
		})
	}
}

func TestJWKSRedirectAndLimits(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	t.Cleanup(target.Close)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	t.Cleanup(server.Close)
	key := rsaKey(t)
	token := jwtToken(t, key, map[string]any{"alg": "RS256", "kid": "one"}, goodClaims(server.URL+"/"))
	client := server.Client()
	a, err := identity.NewAuthenticator(identity.Config{Issuer: server.URL + "/", Audience: "https://gateway.example/mcp", JWKSURL: server.URL + "/keys"}, client, time.Now, resolverFunc(validResolver))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Authenticate(t.Context(), token)
	requireCode(t, err, identity.KeysUnavailable)
	if targetCalls.Load() != 0 || client.CheckRedirect != nil || client.Timeout != 0 {
		t.Fatal("redirect followed or caller client mutated")
	}
	for _, body := range [][]byte{[]byte(strings.Repeat(" ", identity.MaxJWKSBytes+1)), encodeJSON(t, map[string]any{"keys": make([]any, identity.MaxJWKSKeys+1)})} {
		s := httptest.NewTLSServer(&keyServer{body: body, status: http.StatusOK})
		a := authenticator(t, s, &testClock{value: time.Now()}, validResolver)
		token := jwtToken(t, key, map[string]any{"alg": "RS256", "kid": "one"}, goodClaims(s.URL+"/"))
		_, err := a.Authenticate(t.Context(), token)
		s.Close()
		requireCode(t, err, identity.KeysUnavailable)
	}
}
