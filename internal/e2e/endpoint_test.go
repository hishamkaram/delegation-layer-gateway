//go:build e2e

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFixtureIPAllowlistIsExplicitAndExact(t *testing.T) {
	defaults, err := fixtureIPs(nil)
	fixtureOK(t, err)
	if len(defaults) != 1 || defaults[0].String() != "127.0.0.1" {
		t.Fatal("loopback default changed")
	}
	addresses, err := fixtureIPs([]string{"192.0.2.10", "::1"})
	fixtureOK(t, err)
	for _, endpoint := range []string{"https://192.0.2.10:9443/mcp", "https://[::1]/mcp"} {
		if _, err = fixtureEndpoint(endpoint, addresses); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = fixtureEndpoint("https://127.0.0.1/mcp", addresses); err == nil {
		t.Fatal("explicit allowlist silently added loopback")
	}
	if _, err = fixtureEndpoint("https://192.0.2.11/mcp", addresses); err == nil {
		t.Fatal("allowlist expanded to neighboring address")
	}
}

func TestFixtureRejectsUnsafeAllowlistAddresses(t *testing.T) {
	cases := [][]string{
		{"*"},
		{"gateway.example"},
		{"0.0.0.0"},
		{"::"},
		{"224.0.0.1"},
		{"ff02::1"},
		{"255.255.255.255"},
		{"169.254.1.1"},
		{"fe80::1%en0"},
		{"::ffff:192.0.2.10"},
		{"127.0.0.1", "127.0.0.1"},
		{"0:0:0:0:0:0:0:1"},
	}
	tooMany := make([]string, 17)
	cases = append(cases, tooMany)
	for _, values := range cases {
		if _, err := fixtureIPs(values); err == nil {
			t.Fatalf("unsafe allowlist accepted: %q", values)
		}
	}
}

func TestFixtureRejectsUnsafeEndpointForms(t *testing.T) {
	addresses, err := fixtureIPs([]string{"127.0.0.1", "::1", "192.0.2.10"})
	fixtureOK(t, err)
	cases := []string{
		"http://127.0.0.1/mcp", "https:127.0.0.1/mcp", "https://user@127.0.0.1/mcp",
		"https://127.0.0.1/mcp?token=private-canary", "https://127.0.0.1/mcp?",
		"https://127.0.0.1/mcp#fragment", "https://127.0.0.1/mcp#",
		"https://127.0.0.1/%6dcp", "https://localhost/mcp", "https://0.0.0.0/mcp",
		"https://192.0.2.11/mcp", "https://127.0.0.1:0/mcp", "https://127.0.0.1:65536/mcp",
		"https://127.0.0.1:/mcp", "https://::1:443/mcp", "https://[fe80::1%25en0]/mcp", "https://[::ffff:127.0.0.1]/mcp",
	}
	for _, endpoint := range cases {
		if _, err := fixtureEndpoint(endpoint, addresses); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
}

func TestMaterialCommandBindsSANsToCallerAllowlist(t *testing.T) {
	directory := t.TempDir()
	fixtureOK(t, os.Chmod(directory, 0o700))
	materialDirectory := filepath.Join(directory, "material")
	fixtureOK(t, os.Mkdir(materialDirectory, 0o700))
	request := materialInput{Directory: materialDirectory, Issuer: "https://127.0.0.1:19001/", Audience: "https://192.0.2.10:19002/mcp", AllowedIPs: []string{"127.0.0.1", "192.0.2.10", "::1"}}
	data, err := json.Marshal(request)
	fixtureOK(t, err)
	input := filepath.Join(directory, "input.json")
	fixtureOK(t, privateWrite(input, data))
	var response bytes.Buffer
	fixtureOK(t, run([]string{"material", "--input", input}, &response))
	var output materialOutput
	fixtureOK(t, json.Unmarshal(response.Bytes(), &output))
	pair, err := tls.LoadX509KeyPair(output.TLS.Certificate, output.TLS.PrivateKey)
	fixtureOK(t, err)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	fixtureOK(t, err)
	if len(leaf.IPAddresses) != 3 || len(leaf.DNSNames) != 0 {
		t.Fatal("certificate added or omitted SANs")
	}
	for _, ip := range request.AllowedIPs {
		fixtureOK(t, leaf.VerifyHostname(ip))
	}
	if err = leaf.VerifyHostname("192.0.2.11"); err == nil {
		t.Fatal("certificate accepted neighboring address")
	}
	verifyFixtureTokens(t, output, request)
}

func TestMaterialRejectsUnlistedIdentityBeforeWritingFiles(t *testing.T) {
	for _, identity := range []string{"issuer", "audience"} {
		t.Run(identity, func(t *testing.T) {
			directory := t.TempDir()
			fixtureOK(t, os.Chmod(directory, 0o700))
			request := materialInput{Directory: directory, Issuer: "https://127.0.0.1/", Audience: "https://127.0.0.1/mcp"}
			if identity == "issuer" {
				request.Issuer = "https://192.0.2.10/"
			} else {
				request.Audience = "https://192.0.2.10/mcp"
			}
			if _, err := material(request); err == nil {
				t.Fatal("unlisted identity accepted")
			}
			files, err := os.ReadDir(directory)
			fixtureOK(t, err)
			if len(files) != 0 {
				t.Fatal("rejected identity wrote credential material")
			}
		})
	}
}
