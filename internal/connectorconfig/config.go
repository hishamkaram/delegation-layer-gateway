// Package connectorconfig loads immutable, connector-local routing pins and
// ceilings. Actual CLI context tokens and filesystem paths stay in this module's
// local Config/connector.Config boundary and never become wire metadata.
package connectorconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const (
	MaxConfigBytes        = 256 << 10
	MaxCABytes            = 128 << 10
	ResponseMargin        = 5 * time.Second
	DefaultNetworkTimeout = connector.DefaultControlTimeout + ResponseMargin
	MaxNetworkTimeout     = connector.MaxControlTimeout + ResponseMargin
)

var ErrInvalid = errors.New("invalid_connector_configuration")

type Config struct {
	adapter           connector.Config
	enrollment        url.URL
	wss               url.URL
	identityDirectory string
	deviceID          domain.DeviceID
	roots             [][]byte
	deviceRoots       [][]byte
	networkTimeout    time.Duration
}

type document struct {
	Version            int               `json:"schema_version"`
	GatewayID          domain.GatewayID  `json:"gateway_id"`
	DeviceID           domain.DeviceID   `json:"expected_device_id"`
	EnrollmentURL      string            `json:"enrollment_url"`
	WSSURL             string            `json:"wss_url"`
	TrustCAFile        string            `json:"trust_ca_file"`
	DeviceCAFile       string            `json:"device_ca_file,omitempty"`
	IdentityDirectory  string            `json:"identity_directory"`
	Executable         string            `json:"delegate_executable"`
	TemporaryDirectory string            `json:"temporary_directory"`
	ControlTimeout     string            `json:"control_timeout"`
	NetworkTimeout     string            `json:"network_timeout"`
	Projects           []projectDocument `json:"projects"`
}

type projectDocument struct {
	Alias        string           `json:"alias"`
	Root         string           `json:"root"`
	Directory    string           `json:"directory"`
	RootToken    string           `json:"root_token"`
	ProjectToken string           `json:"project_token"`
	Providers    []policyDocument `json:"providers"`
}

type policyDocument struct {
	Provider         string              `json:"provider"`
	Models           []string            `json:"models"`
	Efforts          []string            `json:"efforts"`
	Permissions      []domain.Permission `json:"permissions"`
	MaxBudgetSeconds uint32              `json:"max_budget_seconds"`
	NativeModel      bool                `json:"native_model"`
	NativeEffort     bool                `json:"native_effort"`
}

func privateRead(path string, limit int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	file, openErr := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if openErr != nil {
		return nil, ErrInvalid
	}
	info, statErr := file.Stat()
	if statErr != nil || !privateFile(info) || info.Size() > int64(limit) {
		return nil, errors.Join(ErrInvalid, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > limit {
		return nil, ErrInvalid
	}
	return data, nil
}

func privateFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func Load(path string) (*Config, error) {
	data, readErr := privateRead(path, MaxConfigBytes)
	if readErr != nil {
		return nil, ErrInvalid
	}
	var doc document
	if protocol.DecodeStrict(data, &doc, MaxConfigBytes) != nil || doc.Version != 1 {
		return nil, ErrInvalid
	}
	return validated(doc)
}

func validated(doc document) (*Config, error) {
	enrollment, enrollmentErr := endpoint(doc.EnrollmentURL, "https")
	wss, wssErr := endpoint(doc.WSSURL, "wss")
	if enrollmentErr != nil || wssErr != nil || canonicalHost(enrollment.Hostname()) != canonicalHost(wss.Hostname()) {
		return nil, ErrInvalid
	}
	control, network, timeErr := timeouts(doc)
	if timeErr != nil || !privateDirectoryPath(doc.IdentityDirectory) {
		return nil, ErrInvalid
	}
	ref := domain.CredentialRef{Device: doc.DeviceID, Epoch: "configuration", Generation: 1}
	if ref.Validate() != nil || (protocol.HelloBody{GatewayID: string(doc.GatewayID), DeviceID: string(doc.DeviceID)}).Validate() != nil {
		return nil, ErrInvalid
	}
	roots, rootsErr := loadRoots(doc.TrustCAFile)
	if rootsErr != nil {
		return nil, rootsErr
	}
	// Existing same-CA configurations retain their explicit trust file. A
	// separate device authority never expands HTTPS/WSS server trust.
	deviceRoots := roots
	if doc.DeviceCAFile != "" {
		deviceRoots, rootsErr = loadRoots(doc.DeviceCAFile)
		if rootsErr != nil {
			return nil, rootsErr
		}
	}
	adapter := connector.Config{Executable: doc.Executable, TemporaryDirectory: doc.TemporaryDirectory, GatewayID: doc.GatewayID, ControlTimeout: control}
	for _, project := range doc.Projects {
		adapter.Projects = append(adapter.Projects, project.value())
	}
	// Public constructor validates the authoritative adapter configuration. It
	// performs no CLI execution and does not become a second config owner.
	if _, adapterErr := connector.NewAdapter(adapter, time.Now); adapterErr != nil {
		return nil, ErrInvalid
	}
	return &Config{adapter: adapter, enrollment: *enrollment, wss: *wss, identityDirectory: doc.IdentityDirectory, deviceID: doc.DeviceID, roots: roots, deviceRoots: deviceRoots, networkTimeout: network}, nil
}

func timeouts(doc document) (time.Duration, time.Duration, error) {
	if doc.ControlTimeout == "" {
		doc.ControlTimeout = connector.DefaultControlTimeout.String()
	}
	control, controlErr := duration(doc.ControlTimeout, connector.MaxControlTimeout)
	if doc.NetworkTimeout == "" {
		doc.NetworkTimeout = (control + ResponseMargin).String()
	}
	network, networkErr := duration(doc.NetworkTimeout, MaxNetworkTimeout)
	if controlErr != nil || networkErr != nil || network < control+ResponseMargin {
		return 0, 0, ErrInvalid
	}

	return control, network, nil
}

func (p projectDocument) value() connector.Project {
	result := connector.Project{Alias: p.Alias, Root: p.Root, Directory: p.Directory, RootToken: p.RootToken, ProjectToken: p.ProjectToken}
	for _, policy := range p.Providers {
		result.Providers = append(result.Providers, connector.ProviderPolicy{Provider: policy.Provider, Models: append([]string(nil), policy.Models...), Efforts: append([]string(nil), policy.Efforts...), Permissions: append([]domain.Permission(nil), policy.Permissions...), MaxBudgetSeconds: policy.MaxBudgetSeconds, NativeModel: policy.NativeModel, NativeEffort: policy.NativeEffort})
	}
	return result
}

func endpoint(raw, scheme string) (*url.URL, error) {
	parsed, parseErr := url.Parse(raw)
	if parseErr != nil || !endpointShape(parsed, scheme) || !endpointAuthority(parsed) {
		return nil, ErrInvalid
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed, nil
}

func endpointShape(parsed *url.URL, scheme string) bool {
	return parsed.Scheme == scheme && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && parsed.Opaque == "" && parsed.RawPath == "" && !strings.ContainsAny(parsed.Path, "\x00\r\n\\")
}

func endpointAuthority(parsed *url.URL) bool {
	host := parsed.Hostname()
	if canonicalHost(host) == "" || strings.ContainsAny(host, "%\\\x00\r\n") || strings.HasSuffix(parsed.Host, ":") {
		return false
	}
	if strings.Contains(parsed.Host, ":") && net.ParseIP(host) == nil && parsed.Port() == "" {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || value == 0 {
			return false
		}
	}
	return true
}

func canonicalHost(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	value := strings.ToLower(strings.TrimSuffix(host, "."))
	if value == "" || len(value) > 253 {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if !dnsLabel(label) {
			return ""
		}
	}

	return value
}

func dnsLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if !dnsCharacter(c) {
			return false
		}
	}
	return true
}

func dnsCharacter(c rune) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' }

func duration(raw string, maximum time.Duration) (time.Duration, error) {
	parsed, parseErr := time.ParseDuration(raw)
	if parseErr != nil || parsed <= 0 || parsed > maximum {
		return 0, ErrInvalid
	}
	return parsed, nil
}

func privateDirectoryPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		parent, parentErr := os.Stat(filepath.Dir(path))
		return parentErr == nil && parent.IsDir()
	}
	if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func loadRoots(path string) ([][]byte, error) {
	data, readErr := privateRead(path, MaxCABytes)
	if readErr != nil {
		return nil, ErrInvalid
	}
	var roots [][]byte
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalid
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrInvalid
		}
		count++
		if count > 32 {
			return nil, ErrInvalid
		}
		roots = append(roots, bytes.Clone(cert.Raw))
		data = rest
	}
	if count == 0 {
		return nil, ErrInvalid
	}
	return roots, nil
}

func (c *Config) EnrollmentURL() *url.URL   { copy := c.enrollment; return &copy }
func (c *Config) WSSURL() *url.URL          { copy := c.wss; return &copy }
func (c *Config) IdentityDirectory() string { return c.identityDirectory }
func (c *Config) DeviceID() domain.DeviceID { return c.deviceID }

// Roots builds an independent trust snapshot. CertPool.Clone shares parsed
// certificate pointers, which a caller can reach through verified chains.
func (c *Config) Roots() (*x509.CertPool, error) {
	return trustPool(c.roots)
}

// DeviceRoots verifies issued client credentials. When device_ca_file is
// omitted, it reuses the legacy trust_ca_file authority. Callers receive an
// independent snapshot and cannot mutate either configured trust authority.
func (c *Config) DeviceRoots() (*x509.CertPool, error) {
	return trustPool(c.deviceRoots)
}

func trustPool(roots [][]byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, der := range roots {
		cert, parseErr := x509.ParseCertificate(bytes.Clone(der))
		if parseErr != nil {
			return nil, ErrInvalid
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

// NetworkTimeout is the outer response-await deadline. It encloses the local
// control timeout by at least five seconds; connection/handshake timeouts belong
// to the network composition and must not cancel accepted CLI ownership.
func (c *Config) NetworkTimeout() time.Duration { return c.networkTimeout }

func (c *Config) Adapter() connector.Config {
	result := c.adapter
	result.Projects = make([]connector.Project, len(c.adapter.Projects))
	for index, p := range c.adapter.Projects {
		result.Projects[index] = p
		result.Projects[index].Providers = make([]connector.ProviderPolicy, len(p.Providers))
		for i, policy := range p.Providers {
			policy.Models = append([]string(nil), policy.Models...)
			policy.Efforts = append([]string(nil), policy.Efforts...)
			policy.Permissions = append([]domain.Permission(nil), policy.Permissions...)
			result.Projects[index].Providers[i] = policy
		}
	}
	return result
}
