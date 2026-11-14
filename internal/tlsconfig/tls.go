// Package tlsconfig loads immutable TLS configuration and the device issuer.
// Device authentication remains subject to current registry authorization.
package tlsconfig

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/devicecert"
)

var ErrInvalid = errors.New("invalid_tls_configuration")

type Bundle struct {
	Public      *tls.Config
	Devices     *tls.Config
	Authority   *devicecert.CertificateAuthority
	DeviceCAPEM string
}

// Load requires a valid server certificate for the configured public hostname,
// a separate device CA and private key, and TLS1.3 for both listener boundaries.
func Load(public, deviceCA config.TLSFiles, hostname string, now time.Time) (Bundle, error) {
	if hostname == "" || now.IsZero() {
		return Bundle{}, ErrInvalid
	}
	server, err := keyPair(public)
	if err != nil {
		return Bundle{}, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(server.Certificate[0])
	if err != nil || leaf.VerifyHostname(hostname) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA {
		return Bundle{}, ErrInvalid
	}
	ca, err := keyPair(deviceCA)
	if err != nil {
		return Bundle{}, ErrInvalid
	}
	certificate, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return Bundle{}, ErrInvalid
	}
	signer, ok := ca.PrivateKey.(crypto.Signer)
	if !ok || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return Bundle{}, ErrInvalid
	}
	authority, err := devicecert.NewCertificateAuthority(certificate, signer)
	if err != nil {
		return Bundle{}, ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	// Project only the validated public certificate. Never publish the input PEM
	// bytes, which could contain unrelated blocks or private operator material.
	publicCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	return Bundle{Public: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, NextProtos: []string{"http/1.1"}}, Devices: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"http/1.1"}}, Authority: authority, DeviceCAPEM: publicCA}, nil
}

func keyPair(files config.TLSFiles) (tls.Certificate, error) {
	certificate, err := readCertificate(files.Certificate)
	if err != nil {
		return tls.Certificate{}, ErrInvalid
	}
	key, err := config.ReadPrivate(files.PrivateKey, 64<<10)
	if err != nil {
		return tls.Certificate{}, ErrInvalid
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil || len(pair.Certificate) == 0 {
		return tls.Certificate{}, ErrInvalid
	}
	return pair, nil
}

func readCertificate(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 1<<20 {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	after, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, errors.Join(ErrInvalid, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	if errors.Join(readErr, closeErr) != nil || len(data) > 1<<20 {
		return nil, ErrInvalid
	}
	return data, nil
}
