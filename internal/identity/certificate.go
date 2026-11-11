package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

const MaxCSRBytes = 16 << 10

type CSRInfo struct {
	CSRHash       domain.Digest
	PublicKeyHash domain.Digest
}

// ParseCSR validates the exact DER before an issuance intent is reserved.
func ParseCSR(encoded []byte) (CSRInfo, error) {
	_, info, err := parseCSR(encoded)
	if err != nil {
		return CSRInfo{}, reject(InvalidCertificate, err)
	}
	return info, nil
}

// CertificateAuthority serializes access to its signer. The caller owns the
// key's storage/lifetime; registry owns issuance idempotency and activation.
type CertificateAuthority struct {
	certificate *x509.Certificate
	signer      crypto.Signer
	gate        chan struct{}
}

func NewCertificateAuthority(certificate *x509.Certificate, signer crypto.Signer) (*CertificateAuthority, error) {
	if certificate == nil || signer == nil {
		return nil, reject(InvalidConfiguration, nil)
	}
	parsed, err := x509.ParseCertificate(bytes.Clone(certificate.Raw))
	if err != nil {
		return nil, reject(InvalidConfiguration, err)
	}
	if !parsed.IsCA || !parsed.BasicConstraintsValid || parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, reject(InvalidConfiguration, nil)
	}
	key, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, reject(InvalidConfiguration, nil)
	}
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(encoded, parsed.RawSubjectPublicKeyInfo) {
		return nil, reject(InvalidConfiguration, err)
	}
	return &CertificateAuthority{certificate: parsed, signer: signer, gate: make(chan struct{}, 1)}, nil
}

// Sign signs only a reserved intent and never persists or activates an identity.
// Serial, validity, credential binding and entropy are supplied explicitly.
func (ca *CertificateAuthority) Sign(ctx context.Context, intent domain.IssuanceIntent, csrDER []byte, serial *big.Int, random io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, reject(SigningFailed, err)
	}
	if err := ca.checkIntent(intent, serial); err != nil {
		return nil, reject(InvalidCertificate, err)
	}
	if random == nil {
		return nil, reject(InvalidCertificate, nil)
	}
	request, err := checkedCSR(intent, csrDER)
	if err != nil {
		return nil, reject(InvalidCertificate, err)
	}
	identities, err := CredentialURIs(intent.Credential)
	if err != nil {
		return nil, reject(InvalidCertificate, err)
	}
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).Set(serial),
		NotBefore:             intent.NotBefore,
		NotAfter:              intent.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  identities,
	}
	select {
	case ca.gate <- struct{}{}:
		defer func() { <-ca.gate }()
	case <-ctx.Done():
		return nil, reject(SigningFailed, ctx.Err())
	}
	encoded, err := x509.CreateCertificate(random, template, ca.certificate, request.PublicKey, ca.signer)
	if err != nil {
		return nil, reject(SigningFailed, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, reject(SigningFailed, err)
	}
	return encoded, nil
}

func (ca *CertificateAuthority) checkIntent(intent domain.IssuanceIntent, serial *big.Int) error {
	if intent.Credential.Validate() != nil || intent.Mode.Validate() != nil || domain.Token(string(intent.ID)) != nil || intent.CSRHash.Validate() != nil || intent.PublicKeyHash.Validate() != nil {
		return domain.ErrInvalid
	}
	if !reservedSerialMatches(intent.Serial, serial) {
		return domain.ErrInvalid
	}
	if intent.NotBefore.IsZero() || intent.NotBefore.Nanosecond() != 0 || intent.NotAfter.Nanosecond() != 0 || intent.NotAfter.Sub(intent.NotBefore) != domain.CertificateLifetime {
		return domain.ErrInvalid
	}
	if intent.NotBefore.Before(ca.certificate.NotBefore) || intent.NotAfter.After(ca.certificate.NotAfter) {
		return domain.ErrInvalid
	}
	return nil
}

func reservedSerialMatches(reserved []byte, serial *big.Int) bool {
	return serial != nil && serial.Sign() > 0 && len(serial.Bytes()) <= 20 && len(reserved) > 0 && len(reserved) <= 20 && new(big.Int).SetBytes(reserved).Cmp(serial) == 0
}

func checkedCSR(intent domain.IssuanceIntent, encoded []byte) (*x509.CertificateRequest, error) {
	request, info, err := parseCSR(encoded)
	if err != nil {
		return nil, err
	}
	if info.CSRHash != intent.CSRHash || info.PublicKeyHash != intent.PublicKeyHash {
		return nil, domain.ErrInvalid
	}
	return request, nil
}

func parseCSR(encoded []byte) (*x509.CertificateRequest, CSRInfo, error) {
	if len(encoded) == 0 || len(encoded) > MaxCSRBytes {
		return nil, CSRInfo{}, domain.ErrInvalid
	}
	request, err := x509.ParseCertificateRequest(encoded)
	if err != nil {
		return nil, CSRInfo{}, err
	}
	if signatureErr := request.CheckSignature(); signatureErr != nil {
		return nil, CSRInfo{}, signatureErr
	}
	if len(request.Extensions) != 0 {
		return nil, CSRInfo{}, domain.ErrInvalid
	}
	key, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, CSRInfo{}, domain.ErrInvalid
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, CSRInfo{}, err
	}
	return request, CSRInfo{CSRHash: domain.Hash(encoded), PublicKeyHash: domain.Hash(publicDER)}, nil
}

// CredentialURIs produces exactly the two approved canonical SAN identities.
func CredentialURIs(ref domain.CredentialRef) ([]*url.URL, error) {
	if ref.Validate() != nil {
		return nil, reject(InvalidCertificate, nil)
	}
	return []*url.URL{
		{Scheme: "spiffe", Host: "delegation-layer", Path: "/device/" + string(ref.Device)},
		{Scheme: "urn", Opaque: "delegation-layer:credential:" + string(ref.Epoch) + ":" + strconv.FormatUint(ref.Generation, 10)},
	}, nil
}

// CredentialFromCertificate validates canonical leaf bindings. The transport
// must first verify its certificate chain, time, epoch and registry revocation.
func CredentialFromCertificate(certificate *x509.Certificate) (domain.CredentialRef, error) {
	if !clientCredentialLeaf(certificate) {
		return domain.CredentialRef{}, reject(InvalidCertificate, nil)
	}
	if len(certificate.URIs) != 2 || len(certificate.DNSNames)+len(certificate.IPAddresses)+len(certificate.EmailAddresses) != 0 {
		return domain.CredentialRef{}, reject(InvalidCertificate, nil)
	}
	device, credential := certificate.URIs[0], certificate.URIs[1]
	if device == nil || credential == nil {
		return domain.CredentialRef{}, reject(InvalidCertificate, nil)
	}
	parts := strings.Split(credential.Opaque, ":")
	if len(parts) != 4 || parts[0] != "delegation-layer" || parts[1] != "credential" {
		return domain.CredentialRef{}, reject(InvalidCertificate, nil)
	}
	generation, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil {
		return domain.CredentialRef{}, reject(InvalidCertificate, err)
	}
	ref := domain.CredentialRef{Device: domain.DeviceID(strings.TrimPrefix(device.Path, "/device/")), Epoch: domain.CredentialEpoch(parts[2]), Generation: generation}
	expected, err := CredentialURIs(ref)
	if err != nil {
		return domain.CredentialRef{}, err
	}
	if device.String() != expected[0].String() || credential.String() != expected[1].String() {
		return domain.CredentialRef{}, reject(InvalidCertificate, nil)
	}
	return ref, nil
}

func clientCredentialLeaf(certificate *x509.Certificate) bool {
	return certificate != nil && !certificate.IsCA && certificate.KeyUsage == x509.KeyUsageDigitalSignature && len(certificate.ExtKeyUsage) == 1 && certificate.ExtKeyUsage[0] == x509.ExtKeyUsageClientAuth && len(certificate.UnknownExtKeyUsage) == 0
}
