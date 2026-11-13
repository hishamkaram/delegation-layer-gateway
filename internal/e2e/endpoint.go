//go:build e2e

package main

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// The input owns the fixture's endpoint authority. The same immutable list
// controls certificate IP SANs and every helper HTTPS destination.
func fixtureIPs(values []string) ([]netip.Addr, error) {
	if len(values) == 0 {
		values = []string{"127.0.0.1"}
	}
	if len(values) > 16 {
		return nil, errors.New("fixture IP allowlist exceeds 16 addresses")
	}
	result := make([]netip.Addr, 0, len(values))
	seen := make(map[netip.Addr]bool, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4In6() || address.String() != value || (!address.IsLoopback() && !address.IsGlobalUnicast()) || seen[address] {
			return nil, errors.New("fixture allowlist requires unique canonical unicast IP literals")
		}
		seen[address] = true
		result = append(result, address)
	}
	return result, nil
}

func fixtureURL(value string) (*url.URL, error) {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || endpoint.Opaque != "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || strings.Contains(value, "#") || endpoint.RawPath != "" {
		return nil, errors.New("fixture endpoint requires a plain HTTPS URL without credentials, query or fragment")
	}
	return endpoint, nil
}

func fixtureEndpoint(value string, allowed []netip.Addr) (*url.URL, error) {
	endpoint, err := fixtureURL(value)
	if err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || address.Zone() != "" || address.String() != endpoint.Hostname() {
		return nil, errors.New("fixture endpoint requires a canonical IP host")
	}
	matched := false
	for _, candidate := range allowed {
		if address == candidate {
			matched = true
			break
		}
	}
	if !matched {
		return nil, errors.New("fixture endpoint IP is absent from the allowlist")
	}
	if port := endpoint.Port(); port != "" {
		number, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || number == 0 {
			return nil, errors.New("fixture endpoint port must be within 1..65535")
		}
	}
	if strings.HasSuffix(endpoint.Host, ":") {
		return nil, errors.New("fixture endpoint port is empty")
	}
	return endpoint, nil
}

// System trust validates a DNS endpoint, not Internet reachability. A single
// label is valid; the TLS verifier still owns trust and hostname authentication.
func systemEndpoint(value string) (*url.URL, error) {
	endpoint, err := fixtureURL(value)
	if err != nil {
		return nil, err
	}
	host := endpoint.Hostname()
	if !canonicalDNS(host) || endpoint.Path != "/mcp" {
		return nil, errors.New("fixture system endpoint requires canonical DNS and /mcp")
	}
	if port := endpoint.Port(); port != "" {
		number, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || number == 0 || strconv.FormatUint(number, 10) != port {
			return nil, errors.New("fixture system endpoint requires a canonical port")
		}
	}
	if endpoint.Host != host && endpoint.Host != host+":"+endpoint.Port() {
		return nil, errors.New("fixture system endpoint has a noncanonical authority")
	}
	if strings.HasSuffix(endpoint.Host, ":") {
		return nil, errors.New("fixture system endpoint port is empty")
	}
	return endpoint, nil
}

func canonicalDNS(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !canonicalDNSLabel(label) {
			return false
		}
	}
	return true
}

func canonicalDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

func callEndpoint(input callInput) (*url.URL, error) {
	switch input.TrustMode {
	case "", "fixture":
		addresses, err := fixtureIPs(input.AllowedIPs)
		if err != nil {
			return nil, err
		}
		endpoint, err := fixtureEndpoint(input.Endpoint, addresses)
		if err != nil {
			return nil, err
		}
		if endpoint.Path != "/mcp" {
			return nil, errors.New("fixture MCP endpoint path must be /mcp")
		}
		return endpoint, nil
	case "system":
		if input.CA != "" || input.AllowedIPs != nil {
			return nil, errors.New("fixture system trust cannot accept CA or IP overrides")
		}
		return systemEndpoint(input.Endpoint)
	default:
		return nil, errors.New("fixture trust mode is invalid")
	}
}
