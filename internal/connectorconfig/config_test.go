package connectorconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type configFixture struct {
	rootDER []byte
	rootKey *ecdsa.PrivateKey
	path    string
	doc     document
	t       *testing.T
}

func fixture(t *testing.T) configFixture {
	t.Helper()
	parent := t.TempDir()
	exe, exeErr := os.Executable()
	if exeErr != nil {
		t.Fatal(exeErr)
	}
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, signErr := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if signErr != nil {
		t.Fatal(signErr)
	}
	caPath := filepath.Join(parent, "ca.pem")
	if writeErr := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	doc := document{Version: 1, GatewayID: "gateway-one", DeviceID: "device-one", EnrollmentURL: "https://gateway.example:443/enroll", WSSURL: "wss://gateway.example:9443/connect", TrustCAFile: caPath, IdentityDirectory: filepath.Join(parent, "identity"), Executable: exe, TemporaryDirectory: parent, ControlTimeout: "30s", NetworkTimeout: "35s", Projects: []projectDocument{{Alias: "project-one", Root: parent, Directory: parent, RootToken: strings.Repeat("a", 64), ProjectToken: "local-PRIVATE-CANARY", Providers: []policyDocument{{Provider: "fixture", Models: []string{"safe-model"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 120, NativeModel: true, NativeEffort: true}}}}}
	f := configFixture{rootDER: der, rootKey: key, path: filepath.Join(parent, "config.json"), doc: doc, t: t}
	f.write()
	return f
}

func (f configFixture) write() {
	f.t.Helper()
	encoded, encodeErr := json.Marshal(f.doc)
	if encodeErr != nil {
		f.t.Fatal(encodeErr)
	}
	if writeErr := os.WriteFile(f.path, encoded, 0o600); writeErr != nil {
		f.t.Fatal(writeErr)
	}
}

func TestLoadImmutableLocalConfiguration(t *testing.T) {
	f := fixture(t)
	config, loadErr := Load(f.path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if config.DeviceID() != "device-one" || config.NetworkTimeout() != 35*time.Second || config.IdentityDirectory() != f.doc.IdentityDirectory || config.EnrollmentURL().Scheme != "https" || config.WSSURL().Scheme != "wss" {
		t.Fatal("parsed configuration differs")
	}
	adapter := config.Adapter()
	adapter.Projects[0].ProjectToken = "mutated"
	adapter.Projects[0].Providers[0].Models[0] = "mutated"
	endpoint := config.WSSURL()
	endpoint.Host = "attacker.example"
	roots, rootsErr := config.Roots()
	before, beforeErr := config.Roots()
	if rootsErr != nil || beforeErr != nil {
		t.Fatal("validated roots failed to reparse")
	}
	roots.AddCert(&x509.Certificate{RawSubject: []byte("extra"), Raw: []byte("test")})
	fresh := config.Adapter()
	freshRoots, freshRootsErr := config.Roots()
	if freshRootsErr != nil {
		t.Fatal(freshRootsErr)
	}
	if fresh.Projects[0].ProjectToken != f.doc.Projects[0].ProjectToken || fresh.Projects[0].Providers[0].Models[0] != "safe-model" || config.WSSURL().Hostname() != "gateway.example" || !freshRoots.Equal(before) || roots.Equal(before) {
		t.Fatal("caller mutated immutable local configuration")
	}
}

func TestStrictConfigurationAndEndpointBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		change func(*document)
	}{
		{"relative_device_CA", func(d *document) { d.DeviceCAFile = "device-ca.pem" }},
		{"missing_device_CA", func(d *document) { d.DeviceCAFile = filepath.Join(d.TemporaryDirectory, "missing-ca.pem") }},
		{"http", func(d *document) { d.EnrollmentURL = "http://gateway.example/enroll" }},
		{"different_host", func(d *document) { d.WSSURL = "wss://other.example/connect" }},
		{"credentials", func(d *document) { d.EnrollmentURL = "https://secret@gateway.example/enroll" }},
		{"bad_host", func(d *document) { d.WSSURL = "wss://gateway..example/connect" }},
		{"unicode_host", func(d *document) { d.EnrollmentURL = "https://gäteway.example/enroll" }},
		{"escaped_control", func(d *document) { d.EnrollmentURL = "https://gateway.example/%0A" }},
		{"query", func(d *document) { d.EnrollmentURL = "https://gateway.example/enroll?token=PRIVATE-CANARY" }},
		{"fragment", func(d *document) { d.WSSURL = "wss://gateway.example/connect#bad" }},
		{"port", func(d *document) { d.WSSURL = "wss://gateway.example:0/connect" }},
		{"unbounded_timeout", func(d *document) { d.NetworkTimeout = "1h" }},
		{"zero_control_timeout", func(d *document) { d.ControlTimeout = "0s" }},
		{"relative_executable", func(d *document) { d.Executable = "delegate" }},
		{"missing_executable", func(d *document) { d.Executable = filepath.Join(d.TemporaryDirectory, "absent") }},
		{"duplicate_alias", func(d *document) { d.Projects = append(d.Projects, d.Projects[0]) }},
		{"zero_ceiling", func(d *document) { d.Projects[0].Providers[0].MaxBudgetSeconds = 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fixture(t)
			c.change(&f.doc)
			f.write()
			_, loadErr := Load(f.path)
			if !errors.Is(loadErr, ErrInvalid) || strings.Contains(loadErr.Error(), "PRIVATE-CANARY") {
				t.Fatal("unsafe configuration was accepted or exposed")
			}
		})
	}
}

func TestPrivateBoundedStrictFiles(t *testing.T) {
	for _, kind := range []string{"public", "symlink", "hardlink", "oversize", "duplicate", "unknown", "CA_junk"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			f = privateConfigFault(t, f, kind)
			if _, loadErr := Load(f.path); !errors.Is(loadErr, ErrInvalid) {
				t.Fatal("unsafe private config file accepted")
			}
		})
	}
}

func TestRaisedFiniteControlTimeoutRetainsOuterMargin(t *testing.T) {
	for _, control := range []string{"45s", "300s"} {
		t.Run(control, func(t *testing.T) {
			f := fixture(t)
			f.doc.ControlTimeout = control
			parsed, parseErr := time.ParseDuration(control)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			f.doc.NetworkTimeout = (parsed + 5*time.Second).String()
			f.write()
			config, loadErr := Load(f.path)
			if loadErr != nil || config.Adapter().ControlTimeout != parsed {
				t.Fatal("finite raised control deadline rejected")
			}
		})
	}
	f := fixture(t)
	f.doc.ControlTimeout = "301s"
	f.doc.NetworkTimeout = "305s"
	f.write()
	if _, loadErr := Load(f.path); !errors.Is(loadErr, ErrInvalid) {
		t.Fatal("control deadline above300s accepted")
	}
	f.doc.ControlTimeout = "30s"
	f.doc.NetworkTimeout = "34s"
	f.write()
	if _, loadErr := Load(f.path); !errors.Is(loadErr, ErrInvalid) {
		t.Fatal("outer deadline lacks5s response margin")
	}
}

func TestNamedTimeoutDefaults(t *testing.T) {
	f := fixture(t)
	f.doc.ControlTimeout = ""
	f.doc.NetworkTimeout = ""
	f.write()
	config, loadErr := Load(f.path)
	if loadErr != nil || config.NetworkTimeout() != DefaultNetworkTimeout || config.Adapter().ControlTimeout != 30*time.Second {
		t.Fatal("named default deadlines not applied")
	}
}

func privateConfigFault(t *testing.T, f configFixture, kind string) configFixture {
	t.Helper()
	switch kind {
	case "public":
		if chmodErr := os.Chmod(f.path, 0o644); chmodErr != nil {
			t.Fatal(chmodErr)
		}
	case "symlink":
		link := f.path + ".link"
		if linkErr := os.Symlink(f.path, link); linkErr != nil {
			t.Fatal(linkErr)
		}
		f.path = link
	case "hardlink":
		if linkErr := os.Link(f.path, f.path+".link"); linkErr != nil {
			t.Fatal(linkErr)
		}
	case "oversize":
		if writeErr := os.WriteFile(f.path, []byte(strings.Repeat("x", MaxConfigBytes+1)), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	default:
		privateJSONFault(t, f, kind)
	}
	return f
}

func privateJSONFault(t *testing.T, f configFixture, kind string) {
	t.Helper()
	switch kind {
	case "duplicate":
		if writeErr := os.WriteFile(f.path, []byte(`{"schema_version":1,"schema_version":1}`), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	case "unknown":
		data, readErr := os.ReadFile(f.path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		data = append([]byte(`{"unrecognized":true,`), data[1:]...)
		if writeErr := os.WriteFile(f.path, data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	case "CA_junk":
		data, readErr := os.ReadFile(f.doc.TrustCAFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(f.doc.TrustCAFile, append(data, []byte("junk")...), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
}

func TestTrustSnapshotsDoNotShareVerifiedCertificatePointers(t *testing.T) {
	f := fixture(t)
	config, loadErr := Load(f.path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	roots, rootsErr := config.Roots()
	if rootsErr != nil {
		t.Fatal(rootsErr)
	}
	ca, parseErr := x509.ParseCertificate(f.rootDER)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, signErr := x509.CreateCertificate(rand.Reader, template, ca, &f.rootKey.PublicKey, f.rootKey)
	if signErr != nil {
		t.Fatal(signErr)
	}
	leaf, leafErr := x509.ParseCertificate(leafDER)
	if leafErr != nil {
		t.Fatal(leafErr)
	}
	chains, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now})
	if verifyErr != nil || len(chains) != 1 || len(chains[0]) != 2 {
		t.Fatal("missing verified root pointer")
	}
	foreign, foreignErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if foreignErr != nil {
		t.Fatal(foreignErr)
	}
	chains[0][1].PublicKey = &foreign.PublicKey
	fresh, freshErr := config.Roots()
	if freshErr != nil {
		t.Fatal(freshErr)
	}
	if _, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: fresh, CurrentTime: now}); verifyErr != nil {
		t.Fatal("caller changed authoritative trust roots through verified certificate pointer")
	}
}

func TestDeviceAuthorityIsSeparateAndImmutable(t *testing.T) {
	transport := fixture(t)
	device := fixture(t)
	transport.doc.DeviceCAFile = device.doc.TrustCAFile
	transport.write()
	cfg, err := Load(transport.path)
	if err != nil {
		t.Fatal(err)
	}
	serverRoots, err := cfg.Roots()
	if err != nil {
		t.Fatal(err)
	}
	deviceRoots, err := cfg.DeviceRoots()
	if err != nil {
		t.Fatal(err)
	}
	if serverRoots.Equal(deviceRoots) {
		t.Fatal("distinct configured authorities were merged")
	}
	serverCA, err := x509.ParseCertificate(transport.rootDER)
	if err != nil {
		t.Fatal(err)
	}
	deviceCA, err := x509.ParseCertificate(device.rootDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = serverCA.Verify(x509.VerifyOptions{Roots: deviceRoots}); err == nil {
		t.Fatal("HTTPS authority entered device trust")
	}
	if _, err = deviceCA.Verify(x509.VerifyOptions{Roots: serverRoots}); err == nil {
		t.Fatal("device authority entered HTTPS trust")
	}
	deviceRoots.AddCert(serverCA)
	fresh, err := cfg.DeviceRoots()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Equal(deviceRoots) {
		t.Fatal("caller expanded configured device trust")
	}
	transport.doc.DeviceCAFile = ""
	transport.write()
	legacy, err := Load(transport.path)
	if err != nil {
		t.Fatal(err)
	}
	legacyDevice, err := legacy.DeviceRoots()
	if err != nil || !legacyDevice.Equal(serverRoots) {
		t.Fatal("omitted device CA changed legacy same-authority configuration")
	}
}
