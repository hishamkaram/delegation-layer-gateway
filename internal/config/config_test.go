package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOptionalDeviceLoginRequiresExplicitReachableWSSIdentity(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatal("legacy configuration changed", err)
	}
	c.DeviceLogin = &DeviceLogin{NativeClientID: "native-public-client", DeviceWSSURL: "wss://gateway.example:8443/device"}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadGateway(strings.NewReader(string(data)))
	if err != nil || decoded.DeviceLogin == nil || *decoded.DeviceLogin != *c.DeviceLogin {
		t.Fatal("device login did not survive strict configuration loading", err)
	}
	for name, mutate := range map[string]func(*Gateway){
		"empty client":       func(c *Gateway) { c.DeviceLogin.NativeClientID = "" },
		"oversize client":    func(c *Gateway) { c.DeviceLogin.NativeClientID = strings.Repeat("a", 129) },
		"client space":       func(c *Gateway) { c.DeviceLogin.NativeClientID = "client secret" },
		"plaintext":          func(c *Gateway) { c.DeviceLogin.DeviceWSSURL = "ws://gateway.example:8443/device" },
		"foreign host":       func(c *Gateway) { c.DeviceLogin.DeviceWSSURL = "wss://other.example:8443/device" },
		"missing port":       func(c *Gateway) { c.DeviceLogin.DeviceWSSURL = "wss://gateway.example/device" },
		"zero port":          func(c *Gateway) { c.DeviceLogin.DeviceWSSURL = "wss://gateway.example:0/device" },
		"overflow port":      func(c *Gateway) { c.DeviceLogin.DeviceWSSURL = "wss://gateway.example:65536/device" },
		"wrong path":         func(c *Gateway) { c.DeviceLogin.DeviceWSSURL = "wss://gateway.example:8443/other" },
		"encoded path":       func(c *Gateway) { c.DeviceLogin.DeviceWSSURL = "wss://gateway.example:8443/%64evice" },
		"query":              func(c *Gateway) { c.DeviceLogin.DeviceWSSURL += "?code=private-canary" },
		"empty query":        func(c *Gateway) { c.DeviceLogin.DeviceWSSURL += "?" },
		"fragment":           func(c *Gateway) { c.DeviceLogin.DeviceWSSURL += "#secret" },
		"credentials":        func(c *Gateway) { c.DeviceLogin.DeviceWSSURL = "wss://secret@gateway.example:8443/device" },
		"different audience": func(c *Gateway) { c.Identity.Audience = "https://gateway.example/other" },
	} {
		t.Run(name, func(t *testing.T) {
			input := c
			login := *c.DeviceLogin
			input.DeviceLogin = &login
			mutate(&input)
			if err := input.Validate(); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("unsafe login configuration accepted or exposed", err)
			}
		})
	}
}

func validConfig() Gateway {
	return Gateway{GatewayID: "gateway-1", PublicURL: "https://gateway.example", PublicAddress: ":443", DeviceAddress: ":8443", TLS: TLSFiles{"/private/server.pem", "/private/server.key"}, DeviceCA: TLSFiles{"/private/ca.pem", "/private/ca.key"}, Database: "/private/gateway.db", AdminSocket: "/private/admin.sock", AuditDirectory: "/private/audit", Identity: Identity{"https://issuer.example/", "https://gateway.example/mcp", "https://issuer.example/.well-known/jwks.json"}, ControlTimeoutSeconds: 30, HTTPTimeoutSeconds: 35}
}

func TestRejectUnsafeGatewayConfiguration(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Gateway){
		"plaintext":            func(c *Gateway) { c.PublicURL = "http://gateway.example" },
		"credentials":          func(c *Gateway) { c.PublicURL = "https://token@gateway.example" },
		"public path":          func(c *Gateway) { c.PublicURL += "/prefix" },
		"query":                func(c *Gateway) { c.Identity.Issuer += "?token=canary" },
		"remote keys":          func(c *Gateway) { c.Identity.JWKSURL = "https://attacker.example/keys" },
		"relative db":          func(c *Gateway) { c.Database = "gateway.db" },
		"shared listener":      func(c *Gateway) { c.DeviceAddress = c.PublicAddress },
		"short outer deadline": func(c *Gateway) { c.HTTPTimeoutSeconds = 34 },
		"unbounded control":    func(c *Gateway) { c.ControlTimeoutSeconds = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := validConfig()
			mutate(&config)
			if err := config.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unsafe config accepted: %v", err)
			}
		})
	}
}

func TestConfigurationUnknownAndOversizedFailClosed(t *testing.T) {
	for _, body := range []string{`{"gateway_id":"g","private_override":true}`, strings.Repeat(" ", 65537)} {
		if _, err := ReadGateway(strings.NewReader(body)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid configuration accepted: %v", err)
		}
	}
}

func TestPrivateFileModeSymlinkAndSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadPrivate(path, 6)
	if err != nil || string(data) != "canary" {
		t.Fatalf("private read: %v", err)
	}
	if _, err = ReadPrivate(path, 5); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize private data accepted")
	}
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(path, 10); !errors.Is(err, ErrInvalid) {
		t.Fatal("public private key accepted")
	}
	link := path + ".link"
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(link, 10); !errors.Is(err, ErrInvalid) {
		t.Fatal("private key symlink accepted")
	}
}
