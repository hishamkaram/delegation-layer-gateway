// Package config validates immutable operator configuration. No configuration
// field is supplied by an MCP caller or remote device.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

var ErrInvalid = errors.New("invalid gateway configuration")

type TLSFiles struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type Identity struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	JWKSURL  string `json:"jwks_url"`
}

// DeviceLogin enables public native-client discovery and owner self-service.
// Operators supply the reachable WSS authority explicitly; listener addresses
// may be private and are never a source for public discovery.
type DeviceLogin struct {
	NativeClientID string `json:"native_client_id"`
	DeviceWSSURL   string `json:"device_wss_url"`
}

type Gateway struct {
	GatewayID             string       `json:"gateway_id"`
	PublicURL             string       `json:"public_url"`
	PublicAddress         string       `json:"public_address"`
	DeviceAddress         string       `json:"device_address"`
	TLS                   TLSFiles     `json:"tls"`
	DeviceCA              TLSFiles     `json:"device_ca"`
	Database              string       `json:"database"`
	AdminSocket           string       `json:"admin_socket"`
	AuditDirectory        string       `json:"audit_directory"`
	Identity              Identity     `json:"identity"`
	DeviceLogin           *DeviceLogin `json:"device_login,omitempty"`
	TrustLoopbackProxyIP  bool         `json:"trust_loopback_proxy_client_ip,omitempty"`
	ControlTimeoutSeconds int          `json:"control_timeout_seconds"`
	HTTPTimeoutSeconds    int          `json:"http_timeout_seconds"`
}

func ReadGateway(reader io.Reader) (Gateway, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 65537))
	if err != nil {
		return Gateway{}, fmt.Errorf("read configuration: %w", err)
	}
	config := Gateway{ControlTimeoutSeconds: 30, HTTPTimeoutSeconds: 35}
	if err = protocol.DecodeStrict(data, &config, 65536); err != nil {
		return Gateway{}, ErrInvalid
	}
	if err = config.Validate(); err != nil {
		return Gateway{}, err
	}
	return config, nil
}

func (c Gateway) Validate() error {
	if !opaque(c.GatewayID) {
		return invalid("gateway_id")
	}
	if err := c.validateIdentity(); err != nil {
		return err
	}
	if c.PublicAddress == c.DeviceAddress {
		return invalid("public and mTLS listeners must differ")
	}
	for _, address := range []string{c.PublicAddress, c.DeviceAddress} {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return invalid("listener requires host:port")
		}
	}
	if err := c.validatePaths(); err != nil {
		return err
	}
	if c.ControlTimeoutSeconds < 1 || c.ControlTimeoutSeconds > 300 || c.HTTPTimeoutSeconds < c.ControlTimeoutSeconds+5 || c.HTTPTimeoutSeconds > 305 {
		return invalid("HTTP deadline must enclose the finite control deadline plus five seconds")
	}
	return nil
}

func (c Gateway) validateIdentity() error {
	public, err := HTTPSURL(c.PublicURL)
	if err != nil || public.Path != "" || public.RawPath != "" {
		return invalid("public_url requires HTTPS origin without a path")
	}
	if err = c.Identity.Validate(); err != nil {
		return err
	}
	if c.DeviceLogin != nil {
		return c.DeviceLogin.validate(public, c.Identity.Audience)
	}
	return nil
}

func (c DeviceLogin) validate(public *url.URL, audience string) error {
	if !opaque(c.NativeClientID) || audience != public.String()+"/mcp" {
		return invalid("device_login requires a native client ID and the public MCP audience")
	}
	u, err := url.Parse(c.DeviceWSSURL)
	if err != nil || len(c.DeviceWSSURL) > 2048 || u.Scheme != "wss" || !strings.EqualFold(u.Hostname(), public.Hostname()) || u.Hostname() == "" || u.Path != "/device" || u.RawPath != "" || hasURLExtras(u) {
		return invalid("device_login WSS URL requires the public hostname and /device")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return invalid("device_login WSS URL requires an explicit nonzero port")
	}
	return nil
}

func (c Identity) Validate() error {
	issuer, err := HTTPSURL(c.Issuer)
	if err != nil {
		return invalid("identity issuer")
	}
	keys, err := HTTPSURL(c.JWKSURL)
	if err != nil || keys.Host != issuer.Host {
		return invalid("JWKS must use the configured issuer authority")
	}
	if _, err = HTTPSURL(c.Audience); err != nil {
		return invalid("identity audience")
	}
	return nil
}

func (c Gateway) validatePaths() error {
	for _, path := range []string{c.Database, c.AdminSocket, c.AuditDirectory, c.TLS.Certificate, c.TLS.PrivateKey, c.DeviceCA.Certificate, c.DeviceCA.PrivateKey} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return invalid("file paths must be absolute and clean")
		}
	}
	return nil
}

func HTTPSURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || hasURLExtras(u) {
		return nil, ErrInvalid
	}
	return u, nil
}

func hasURLExtras(u *url.URL) bool {
	return u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != ""
}

// ReadPrivate reads bounded regular private files without exposing their path or
// content in errors. Parent directory access remains an operator prerequisite.
func ReadPrivate(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, invalid("private file unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > limit {
		return nil, invalid("private file requires regular 0600 storage within size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid("private file unavailable")
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(invalid("private file changed during open"), file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > limit {
		return nil, invalid("private file read failed")
	}
	return data, nil
}

func opaque(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", r) {
			return false
		}
	}
	return true
}
func invalid(field string) error { return fmt.Errorf("%s: %w", field, ErrInvalid) }
