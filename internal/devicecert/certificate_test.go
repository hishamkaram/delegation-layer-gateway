package devicecert_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func ecKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func certificateAuthority(t *testing.T) (*devicecert.CertificateAuthority, *x509.Certificate) {
	t.Helper()
	key := ecKey(t, elliptic.P256())
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := devicecert.NewCertificateAuthority(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	return ca, certificate
}

func csr(t *testing.T, key *ecdsa.PrivateKey, request *x509.CertificateRequest) []byte {
	t.Helper()
	encoded, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func issuance(t *testing.T, key *ecdsa.PrivateKey, request []byte) domain.IssuanceIntent {
	t.Helper()
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Second)
	return domain.IssuanceIntent{ID: "issuance-one", Serial: []byte{1, 2, 3}, Credential: domain.CredentialRef{Device: "device-one", Epoch: "epoch-one", Generation: 7}, Mode: domain.Regular, CSRHash: domain.Hash(request), PublicKeyHash: domain.Hash(public), NotBefore: start, NotAfter: start.Add(domain.CertificateLifetime)}
}

func TestSignReservedCredentialAndVerifyTLSClient(t *testing.T) {
	ca, parent := certificateAuthority(t)
	key := ecKey(t, elliptic.P256())
	request := csr(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored CSR subject"}})
	intent := issuance(t, key, request)
	info, err := devicecert.ParseCSR(request)
	if err != nil || info.CSRHash != intent.CSRHash || info.PublicKeyHash != intent.PublicKeyHash {
		t.Fatalf("CSR reservation hashes=%+v error=%v", info, err)
	}
	der, err := ca.Sign(t.Context(), intent, request, new(big.Int).SetBytes(intent.Serial), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	assertReservedCertificate(t, leaf, parent, intent)
}

func assertReservedCertificate(t *testing.T, leaf, parent *x509.Certificate, intent domain.IssuanceIntent) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(parent)
	if _, clientErr := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: intent.NotBefore.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); clientErr != nil {
		t.Fatal(clientErr)
	}
	if _, serverErr := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: intent.NotBefore.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); serverErr == nil {
		t.Fatal("client identity accepted for server authentication")
	}
	ref, err := devicecert.CredentialFromCertificate(leaf)
	if err != nil || ref != intent.Credential {
		t.Fatalf("binding=%+v error=%v", ref, err)
	}
	if leaf.Subject.CommonName != "" || leaf.IsCA || !leaf.NotBefore.Equal(intent.NotBefore) || !leaf.NotAfter.Equal(intent.NotAfter) || leaf.SerialNumber.Cmp(new(big.Int).SetBytes(intent.Serial)) != 0 {
		t.Fatal("certificate differs from reserved identity")
	}
	if leaf.URIs[0].String() != "spiffe://delegation-layer/device/device-one" || leaf.URIs[1].String() != "urn:delegation-layer:credential:epoch-one:7" {
		t.Fatal("noncanonical SAN identity")
	}
	if domain.Hash(leaf.RawSubjectPublicKeyInfo) != intent.PublicKeyHash {
		t.Fatal("wrong CSR key signed")
	}
}

func TestSigningRejectsUntrustedCSRAndConflictingIntent(t *testing.T) {
	ca, _ := certificateAuthority(t)
	key := ecKey(t, elliptic.P256())
	request := csr(t, key, &x509.CertificateRequest{})
	good := issuance(t, key, request)
	for _, test := range []struct {
		name   string
		change func(*domain.IssuanceIntent)
	}{
		{"zero serial", func(i *domain.IssuanceIntent) { i.Serial = []byte{0} }},
		{"oversize serial", func(i *domain.IssuanceIntent) { i.Serial = make([]byte, 21); i.Serial[0] = 1 }},
		{"wrong request hash", func(i *domain.IssuanceIntent) { i.CSRHash = domain.Hash([]byte("other")) }},
		{"wrong key hash", func(i *domain.IssuanceIntent) { i.PublicKeyHash = domain.Hash([]byte("other")) }},
		{"different lifetime", func(i *domain.IssuanceIntent) { i.NotAfter = i.NotAfter.Add(time.Second) }},
		{"nanosecond validity", func(i *domain.IssuanceIntent) {
			i.NotBefore = i.NotBefore.Add(time.Nanosecond)
			i.NotAfter = i.NotAfter.Add(time.Nanosecond)
		}},
		{"outside CA validity", func(i *domain.IssuanceIntent) {
			i.NotBefore = i.NotBefore.AddDate(2, 0, 0)
			i.NotAfter = i.NotBefore.Add(domain.CertificateLifetime)
		}},
		{"unsafe device URI", func(i *domain.IssuanceIntent) { i.Credential.Device = "one/../../other" }},
		{"unsafe epoch URI", func(i *domain.IssuanceIntent) { i.Credential.Epoch = "one:other" }},
		{"zero generation", func(i *domain.IssuanceIntent) { i.Credential.Generation = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			intent := good
			test.change(&intent)
			_, err := ca.Sign(t.Context(), intent, request, new(big.Int).SetBytes(intent.Serial), rand.Reader)
			requireCode(t, err, devicecert.InvalidCertificate)
		})
	}
	_, err := ca.Sign(t.Context(), good, request, big.NewInt(999), rand.Reader)
	requireCode(t, err, devicecert.InvalidCertificate)
	_, err = ca.Sign(t.Context(), good, request, new(big.Int).SetBytes(good.Serial), nil)
	requireCode(t, err, devicecert.InvalidCertificate)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = ca.Sign(ctx, good, request, new(big.Int).SetBytes(good.Serial), rand.Reader)
	requireCode(t, err, devicecert.SigningFailed)
	for _, test := range []struct {
		name     string
		key      *ecdsa.PrivateKey
		template *x509.CertificateRequest
	}{
		{"requested SAN", key, &x509.CertificateRequest{DNSNames: []string{"attacker.example"}}},
		{"requested extension", key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Value: []byte{5, 0}}}}},
		{"wrong curve", ecKey(t, elliptic.P384()), &x509.CertificateRequest{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := csr(t, test.key, test.template)
			intent := issuance(t, test.key, req)
			_, parseErr := devicecert.ParseCSR(req)
			requireCode(t, parseErr, devicecert.InvalidCertificate)
			_, signErr := ca.Sign(t.Context(), intent, req, new(big.Int).SetBytes(intent.Serial), rand.Reader)
			requireCode(t, signErr, devicecert.InvalidCertificate)
		})
	}
	corrupt := append([]byte(nil), request...)
	corrupt[len(corrupt)-1] ^= 1
	intent := issuance(t, key, corrupt)
	_, parseErr := devicecert.ParseCSR(corrupt)
	requireCode(t, parseErr, devicecert.InvalidCertificate)
	_, err = ca.Sign(t.Context(), intent, corrupt, new(big.Int).SetBytes(intent.Serial), rand.Reader)
	requireCode(t, err, devicecert.InvalidCertificate)
}

func TestCredentialParserRejectsAlternateBindings(t *testing.T) {
	ref := domain.CredentialRef{Device: "device-one", Epoch: "epoch-one", Generation: 7}
	for _, test := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"query", func(c *x509.Certificate) { c.URIs[0].RawQuery = "admin=true" }},
		{"different trust domain", func(c *x509.Certificate) { c.URIs[0].Host = "attacker" }},
		{"escaped path", func(c *x509.Certificate) { c.URIs[0].RawPath = "/device/%64evice-one" }},
		{"leading zero generation", func(c *x509.Certificate) { c.URIs[1].Opaque = "delegation-layer:credential:epoch-one:07" }},
		{"extra DNS identity", func(c *x509.Certificate) { c.DNSNames = []string{"extra.example"} }},
		{"server auth", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{"extra identity", func(c *x509.Certificate) { c.URIs = append(c.URIs, &url.URL{Scheme: "urn", Opaque: "extra"}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			uris, err := devicecert.CredentialURIs(ref)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: uris}
			test.change(leaf)
			_, err = devicecert.CredentialFromCertificate(leaf)
			requireCode(t, err, devicecert.InvalidCertificate)
		})
	}
	_, parent := certificateAuthority(t)
	other := ecKey(t, elliptic.P256())
	_, err := devicecert.NewCertificateAuthority(parent, other)
	requireCode(t, err, devicecert.InvalidConfiguration)
}

func TestParseCSRRejectsMalformedAndOversizedDER(t *testing.T) {
	for _, encoded := range [][]byte{nil, {1, 2, 3}, make([]byte, devicecert.MaxCSRBytes+1)} {
		_, err := devicecert.ParseCSR(encoded)
		requireCode(t, err, devicecert.InvalidCertificate)
	}
}

func requireCode(t *testing.T, err error, code devicecert.ErrorCode) {
	t.Helper()
	var typed *devicecert.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected code %s, got %v", code, err)
	}
}
