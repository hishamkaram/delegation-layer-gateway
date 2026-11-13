package adminapi_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
)

func allowOwnedTokenOwner(t *testing.T, f *fixture) adminapi.OwnerPolicyView {
	t.Helper()
	input := adminapi.OwnerPolicyInput{Issuer: "https://issuer.example/", Subject: "alice", Scopes: domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60, MaxDevices: 2}
	data, err := json.Marshal(input)
	check(t, err)
	var view adminapi.OwnerPolicyView
	f.call(t, http.MethodPost, "/v1/users/allow", string(data), &view)
	return view
}

func TestOwnedTokenBootstrapIsPrivateAndCannotAdoptLegacyIdentity(t *testing.T) {
	f := newFixture(t, nil)
	f.device(t)
	allowOwnedTokenOwner(t, f)
	body := `{"issuer":"https://issuer.example/","subject":"alice","name":"Workstation"}`
	public := httptest.NewRecorder()
	f.handler.ServeHTTP(public, httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/devices/enrollment-tokens", strings.NewReader(body)))
	if public.Code != http.StatusForbidden {
		t.Fatal("public handler minted private owner token")
	}
	status, _ := f.request(t, http.MethodPost, "/v1/devices/enrollment-tokens", `{"issuer":"https://issuer.example/","subject":"alice","name":"Workstation","device_id":"device"}`)
	if status != http.StatusBadRequest {
		t.Fatal("owner bootstrap accepted legacy adoption selector")
	}
	status, _ = f.request(t, http.MethodPost, "/v1/devices/enrollment-tokens", `{"issuer":"https://other-issuer.example/","subject":"alice","name":"Workstation"}`)
	if status != http.StatusForbidden {
		t.Fatal("unapproved issuer/subject inherited owner eligibility")
	}
	var result adminapi.Enrollment
	f.call(t, http.MethodPost, "/v1/devices/enrollment-tokens", body, &result)
	if result.DeviceID == "device" || result.DeviceID == "" || result.Token == "" || !result.ExpiresAt.Equal(f.now.Add(domain.EnrollmentTTL)) {
		t.Fatal("private bootstrap did not create a fresh bounded identity")
	}
}

func TestOwnedTokenUnixBootstrapRedeemsRealCAOverTLS(t *testing.T) {
	f := newFixture(t, nil)
	owner := allowOwnedTokenOwner(t, f)
	var token adminapi.Enrollment
	f.call(t, http.MethodPost, "/v1/devices/enrollment-tokens", `{"issuer":"https://issuer.example/","subject":"alice","name":"Headless Mac"}`, &token)
	ca, roots := ownedEnrollmentCA(t, f.now)
	service, err := enrollment.New(f.store, ca, rand.Reader, func() time.Time { return f.now })
	check(t, err)
	handler, err := enrollment.HTTPHandler(service, func() time.Time { return f.now }, false)
	check(t, err)
	endpoint := httptest.NewTLSServer(handler)
	t.Cleanup(endpoint.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	check(t, err)
	response := redeemOwnedToken(t, endpoint, token.Token, csr)
	certDER, err := base64.StdEncoding.DecodeString(response.CertificateDERBase64)
	check(t, err)
	leaf, err := x509.ParseCertificate(certDER)
	check(t, err)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: f.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	check(t, err)
	ref, err := devicecert.CredentialFromCertificate(leaf)
	check(t, err)
	if string(ref.Device) != token.DeviceID || ref.Generation != 1 || response.Mode != domain.Regular {
		t.Fatal("token/CSR signed another device credential")
	}
	replay := redeemOwnedToken(t, endpoint, token.Token, csr)
	if replay.CertificateDERBase64 != response.CertificateDERBase64 {
		t.Fatal("redemption retry changed accepted certificate")
	}
	assertHeadlessOwnedRootEligible(t, f, owner, ref)
}

func assertHeadlessOwnedRootEligible(t *testing.T, f *fixture, owner adminapi.OwnerPolicyView, ref domain.CredentialRef) {
	t.Helper()
	generation, err := f.store.NextConnectionGeneration(t.Context(), ref, "headless-boot", f.now)
	check(t, err)
	route := domain.OwnedRootBinding{Route: domain.RootRoute{Device: ref.Device, Root: domain.RootGuard(guard("selected-native-root"))}, Credential: ref, Connection: generation}
	port, err := registry.NewOwnedRootPort(t.Context(), f.store, route, func() time.Time { return f.now })
	check(t, err)
	if string(port.OwnerPrincipal()) != owner.PrincipalID {
		t.Fatal("first headless token did not gain its eligible owned-root attribution")
	}
}

func redeemOwnedToken(t *testing.T, server *httptest.Server, token string, csr []byte) protocol.EnrollmentResponse {
	t.Helper()
	payload, err := json.Marshal(protocol.EnrollmentRequest{Token: token, CSRDERBase64: base64.StdEncoding.EncodeToString(csr)})
	check(t, err)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/v1/enroll", bytes.NewReader(payload))
	check(t, err)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	check(t, err)
	defer func() { check(t, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK {
		t.Fatal("owned token TLS redemption rejected", response.StatusCode)
	}
	var receipt protocol.EnrollmentResponse
	check(t, json.NewDecoder(response.Body).Decode(&receipt))
	return receipt
}

func ownedEnrollmentCA(t *testing.T, now time.Time) (*devicecert.CertificateAuthority, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned token fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	check(t, err)
	leaf, err := x509.ParseCertificate(der)
	check(t, err)
	ca, err := devicecert.NewCertificateAuthority(leaf, key)
	check(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return ca, roots
}

func TestOwnedTokenUnknownSubjectDoesNotMaterializeMapping(t *testing.T) {
	f := newFixture(t, nil)
	allowOwnedTokenOwner(t, f)
	address := url.URL{Scheme: "file", Path: filepath.Join(filepath.Dir(f.socket), "registry.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", address.String())
	check(t, err)
	defer func() { check(t, db.Close()) }()
	var before, after int
	check(t, db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM principals").Scan(&before))
	status, _ := f.request(t, http.MethodPost, "/v1/devices/enrollment-tokens", `{"issuer":"https://issuer.example/","subject":"unknown","name":"New device"}`)
	if status != http.StatusForbidden {
		t.Fatal("unknown owner not denied before token creation")
	}
	check(t, db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM principals").Scan(&after))
	if after != before {
		t.Fatal("private token request materialized unknown mapping")
	}
}
