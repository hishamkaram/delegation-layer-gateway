//go:build e2e

package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestFixtureMaterialHasRealTLSAndDistinctSignedAudience(t *testing.T) {
	directory := t.TempDir()
	fixtureOK(t, os.Chmod(directory, 0o700))
	input := materialInput{Directory: directory, Issuer: "https://127.0.0.1:19001/", Audience: "https://127.0.0.1:19002/mcp"}
	output, err := material(input)
	fixtureOK(t, err)
	pair, err := tls.LoadX509KeyPair(output.TLS.Certificate, output.TLS.PrivateKey)
	fixtureOK(t, err)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	fixtureOK(t, err)
	roots := x509.NewCertPool()
	ca, err := os.ReadFile(output.CA)
	fixtureOK(t, err)
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture CA invalid")
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1"})
	fixtureOK(t, err)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "another-host.invalid"}); err == nil {
		t.Fatal("fixture certificate accepted wrong host")
	}
	verifyFixtureTokens(t, output, input)
	for _, file := range []string{output.CA, output.TLS.PrivateKey, output.DeviceCA.PrivateKey, output.Token, output.WrongToken, output.JWKS} {
		info, statErr := os.Stat(file)
		fixtureOK(t, statErr)
		if info.Mode().Perm() != 0o600 {
			t.Fatal("fixture material is public")
		}
	}
}

func verifyFixtureTokens(t *testing.T, output materialOutput, input materialInput) {
	t.Helper()
	data, err := os.ReadFile(output.JWKS)
	fixtureOK(t, err)
	var document struct {
		Keys []struct {
			N string `json:"n"`
			E string `json:"e"`
		}
	}
	fixtureOK(t, json.Unmarshal(data, &document))
	if len(document.Keys) != 1 {
		t.Fatal("unexpected fixture key count")
	}
	modulus, err := base64.RawURLEncoding.DecodeString(document.Keys[0].N)
	fixtureOK(t, err)
	key := rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: 65537}
	for _, row := range []struct{ path, audience string }{{output.Token, input.Audience}, {output.WrongToken, "https://127.0.0.1/wrong-audience"}} {
		var token struct {
			Token string `json:"token"`
		}
		fixtureOK(t, readPrivate(row.path, &token))
		parts := strings.Split(token.Token, ".")
		if len(parts) != 3 {
			t.Fatal("invalid fixture JWT")
		}
		signature, decodeErr := base64.RawURLEncoding.DecodeString(parts[2])
		fixtureOK(t, decodeErr)
		hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		fixtureOK(t, rsa.VerifyPKCS1v15(&key, crypto.SHA256, hash[:], signature))
		raw, claimsErr := base64.RawURLEncoding.DecodeString(parts[1])
		fixtureOK(t, claimsErr)
		var claims struct {
			Issuer   string `json:"iss"`
			Audience string `json:"aud"`
			Expires  int64  `json:"exp"`
		}
		fixtureOK(t, json.Unmarshal(raw, &claims))
		if claims.Issuer != input.Issuer || claims.Audience != row.audience || claims.Expires <= time.Now().Unix() {
			t.Fatal("JWT does not bind fixture issuer/audience/lifetime")
		}
	}
}

func TestFixturePrivateInputRejectsUnknownAndSharedData(t *testing.T) {
	directory := t.TempDir()
	for _, row := range []struct {
		name, data string
		mode       os.FileMode
	}{{"unknown", `{"token":"value","secret_extra":true}`, 0o600}, {"multiple", `{"token":"value"} {}`, 0o600}, {"shared", `{"token":"value"}`, 0o644}} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(directory, row.name)
			fixtureOK(t, os.WriteFile(path, []byte(row.data), row.mode))
			fixtureOK(t, os.Chmod(path, row.mode))
			var token struct {
				Token string `json:"token"`
			}
			if readPrivate(path, &token) == nil {
				t.Fatal("invalid private input accepted")
			}
		})
	}
}
