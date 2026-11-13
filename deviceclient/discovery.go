package deviceclient

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

type issuerEndpoints struct {
	Issuer string `json:"issuer"`
	Device string `json:"device_authorization_endpoint"`
	Token  string `json:"token_endpoint"`
}

func validDescriptor(d contract.Descriptor, gateway string) error {
	if d.Validate() != nil || d.PublicURL != gateway {
		return ErrDiscovery
	}
	if !slices.Contains(d.SupportedWireVersions, 2) {
		return ErrUnsupported
	}
	return nil
}

func discover(ctx context.Context, client *http.Client, gateway string) (contract.Descriptor, issuerEndpoints, error) {
	var d contract.Descriptor
	if err := requestJSON(ctx, client, http.MethodGet, gateway+contract.DescriptorPath, "", nil, &d, true); err != nil {
		return d, issuerEndpoints{}, err
	}
	if err := validDescriptor(d, gateway); err != nil {
		return d, issuerEndpoints{}, err
	}
	var resource struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := requestJSON(ctx, client, http.MethodGet, gateway+"/.well-known/oauth-protected-resource/mcp", "", nil, &resource, false); err != nil {
		return d, issuerEndpoints{}, err
	}
	if resource.Resource != d.Audience || len(resource.AuthorizationServers) != 1 || resource.AuthorizationServers[0] != d.Issuer {
		return d, issuerEndpoints{}, ErrDiscovery
	}
	return d, issuerEndpoints{}, nil
}

func discoverIssuer(ctx context.Context, client *http.Client, d contract.Descriptor) (issuerEndpoints, error) {
	var issuer issuerEndpoints
	if err := requestJSON(ctx, client, http.MethodGet, strings.TrimRight(d.Issuer, "/")+"/.well-known/openid-configuration", "", nil, &issuer, false); err != nil {
		return issuerEndpoints{}, err
	}
	if issuer == (issuerEndpoints{}) || !issuer.validFor(d) {
		return issuerEndpoints{}, ErrDiscovery
	}
	return issuer, nil
}

func (i issuerEndpoints) validFor(d contract.Descriptor) bool {
	return i == (issuerEndpoints{}) || (i.Issuer == d.Issuer && httpsEndpoint(i.Device) && httpsEndpoint(i.Token))
}

func (s *profileStore) withIssuer(ctx context.Context, client *http.Client, current profile) (profile, error) {
	issuer, err := discoverIssuer(ctx, client, current.Descriptor)
	if err != nil {
		return current, err
	}
	if current.Issuer != (issuerEndpoints{}) && current.Issuer != issuer {
		return current, ErrTrustChanged
	}
	if current.Issuer == issuer {
		return current, nil
	}
	current.Issuer = issuer
	if err = s.save(current); err != nil {
		return current, err
	}
	return current, nil
}
