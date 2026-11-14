package contract

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func (d Descriptor) Validate() error {
	if d.validateEndpoints() != nil || d.SchemaVersion != 1 || domain.Token(d.GatewayID) != nil || !visible(d.NativeClientID, 1024) {
		return domain.ErrInvalid
	}
	if !validDeviceCA(d.DeviceCAPEM) || !validVersions(d.SupportedWireVersions) || len(d.Capabilities) > 100 {
		return domain.ErrInvalid
	}
	seen := make(map[string]bool, len(d.Capabilities))
	for _, capability := range d.Capabilities {
		if seen[capability] || domain.Token(capability) != nil {
			return domain.ErrInvalid
		}
		seen[capability] = true
	}
	return nil
}

func (d Descriptor) validateEndpoints() error {
	public, err := endpoint(d.PublicURL, "https")
	if err != nil || public.Path != "" {
		return domain.ErrInvalid
	}
	if _, err = endpoint(d.Issuer, "https"); err != nil {
		return domain.ErrInvalid
	}
	if d.Audience != d.PublicURL+"/mcp" || d.EnrollmentURL != d.PublicURL+"/v1/enroll" || d.SelfEnrollmentURL != d.PublicURL+EnrollmentPath || d.RevokeURL != d.PublicURL+RevocationPath {
		return domain.ErrInvalid
	}
	wss, err := endpoint(d.DeviceWSSURL, "wss")
	if err != nil || !strings.EqualFold(wss.Hostname(), public.Hostname()) || wss.Path != "/device" {
		return domain.ErrInvalid
	}
	return nil
}

func endpoint(value, scheme string) (*url.URL, error) {
	if len(value) > 4096 || strings.TrimSpace(value) != value {
		return nil, domain.ErrInvalid
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != scheme || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" {
		return nil, domain.ErrInvalid
	}
	return u, nil
}

func visible(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if character < 33 || character > 126 {
			return false
		}
	}
	return true
}

func validVersions(versions []int) bool {
	if len(versions) == 0 || len(versions) > 2 {
		return false
	}
	seen := make(map[int]bool, len(versions))
	for _, version := range versions {
		if seen[version] || (version != 1 && version != 2) {
			return false
		}
		seen[version] = true
	}
	return true
}

func validDeviceCA(value string) bool {
	if len(value) == 0 || len(value) > 32<<10 {
		return false
	}
	remaining := bytes.TrimSpace([]byte(value))
	count := 0
	for len(remaining) != 0 {
		block, rest, ok := certificateBlock(remaining)
		if !ok || count == 8 {
			return false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return false
		}
		count++
		remaining = bytes.TrimSpace(rest)
	}
	return count != 0
}

// Decode exactly the first block. pem.Decode alone skips malformed prefixes,
// which could otherwise publish accidental secret text with a later valid CA.
func certificateBlock(data []byte) (*pem.Block, []byte, bool) {
	const start, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	endAt := bytes.Index(data, []byte(end))
	if !bytes.HasPrefix(data, []byte(start)) || endAt < 0 {
		return nil, nil, false
	}
	chunk := data[:endAt+len(end)]
	block, rest := pem.Decode(chunk)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || bytes.Count(chunk, []byte("-----BEGIN ")) != 1 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, nil, false
	}
	return block, data[endAt+len(end):], true
}
