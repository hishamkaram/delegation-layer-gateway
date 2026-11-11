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
