//go:build e2e

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

type (
	materialInput struct {
		Directory  string   `json:"directory"`
		Issuer     string   `json:"issuer"`
		Audience   string   `json:"audience"`
		AllowedIPs []string `json:"allowed_ips,omitempty"`
	}
	pairFiles struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	materialOutput struct {
		CA         string    `json:"ca_file"`
		TLS        pairFiles `json:"tls"`
		DeviceCA   pairFiles `json:"device_ca"`
		JWKS       string    `json:"jwks_file"`
		Token      string    `json:"token_file"`
		WrongToken string    `json:"wrong_token_file"`
	}
	fixtureCA struct {
		certificate *x509.Certificate
		key         *ecdsa.PrivateKey
		files       pairFiles
	}
)

func material(input materialInput) (materialOutput, error) {
	var output materialOutput
	addresses, err := validateMaterialInput(input)
	if err != nil {
		return output, err
	}

	now := time.Now().UTC()
	authority, err := newCA(input.Directory, "https-ca", now)
	if err != nil {
		return output, err
	}
	deviceCA, err := newCA(input.Directory, "device-ca", now)
	if err != nil {
		return output, err
	}
	server, err := newServer(input.Directory, authority, now, addresses)
	if err != nil {
		return output, err
	}
	output = materialOutput{CA: authority.files.Certificate, TLS: server, DeviceCA: deviceCA.files, JWKS: filepath.Join(input.Directory, "jwks.json"), Token: filepath.Join(input.Directory, "token.json"), WrongToken: filepath.Join(input.Directory, "wrong-token.json")}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return output, err
	}
	jwks, err := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "local-e2e", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	if err != nil {
		return output, err
	}
	if err = privateWrite(output.JWKS, jwks); err != nil {
		return output, err
	}
	for _, target := range []struct{ path, audience string }{{output.Token, input.Audience}, {output.WrongToken, "https://127.0.0.1/wrong-audience"}} {
		token, tokenErr := signToken(key, input.Issuer, target.audience, now)
		if tokenErr != nil {
			return output, tokenErr
		}
		data, encodeErr := json.Marshal(struct {
			Token string `json:"token"`
		}{token})
		if encodeErr != nil {
			return output, encodeErr
		}
		if err = privateWrite(target.path, data); err != nil {
			return output, err
		}
	}
	return output, nil
}

func validateMaterialInput(input materialInput) ([]netip.Addr, error) {
	info, err := os.Lstat(input.Directory)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(input.Directory) || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("private material directory required")
	}
	addresses, err := fixtureIPs(input.AllowedIPs)
	if err != nil {
		return nil, err
	}
	for _, value := range []string{input.Issuer, input.Audience} {
		if _, parseErr := fixtureEndpoint(value, addresses); parseErr != nil {
			return nil, parseErr
		}
	}
	return addresses, nil
}

func newCA(directory, name string, now time.Time) (fixtureCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fixtureCA{}, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fixtureCA{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return fixtureCA{}, err
	}
	files, err := writePair(directory, name, der, key)
	return fixtureCA{certificate: certificate, key: key, files: files}, err
}

func newServer(directory string, ca fixtureCA, now time.Time, addresses []netip.Addr) (pairFiles, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pairFiles{}, err
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, net.IP(address.AsSlice()))
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "local-process-e2e"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 0, 1), IPAddresses: ips, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		return pairFiles{}, err
	}
	return writePair(directory, "https-server", der, key)
}

func writePair(directory, name string, der []byte, key *ecdsa.PrivateKey) (pairFiles, error) {
	output := pairFiles{Certificate: filepath.Join(directory, name+".pem"), PrivateKey: filepath.Join(directory, name+".key")}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return output, err
	}
	if err = privateWrite(output.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return output, err
	}
	return output, privateWrite(output.PrivateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

func signToken(key *rsa.PrivateKey, issuer, audience string, now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "local-e2e", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": issuer, "sub": "local-e2e-subject", "aud": audience, "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(30 * time.Minute).Unix(), "scope": "inventory:read task:dispatch task:read task:cancel"})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
