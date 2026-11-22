package connector

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// These DTOs follow Native's public ProviderResponse/Description declaration.
// Compiled support is advisory metadata; it never filters execution intent.
type nativeProviderResponse struct {
	SchemaVersion int                         `json:"schema_version"`
	Providers     []nativeProviderDescription `json:"providers"`
	Error         string                      `json:"error,omitempty"`
}
type nativeProviderDescription struct {
	ID               string   `json:"id"`
	SupportedModes   []string `json:"supported_modes"`
	SupportedOptions []string `json:"supported_options"`
	RequiredOptions  []string `json:"required_options,omitempty"`
	Continuation     string   `json:"continuation"`
	Interaction      struct {
		SupportedModes []string `json:"supported_modes,omitempty"`
		Clarification  bool     `json:"clarification"`
		Steering       bool     `json:"steering"`
	} `json:"interaction"`
	ReadOnly struct {
		Supported   bool   `json:"supported"`
		Mechanism   string `json:"mechanism,omitempty"`
		Containment string `json:"containment,omitempty"`
	} `json:"read_only"`
	Runtime struct {
		VersionArgs   []string `json:"version_args,omitempty"`
		HelpArgs      []string `json:"help_args,omitempty"`
		RequiredFlags []string `json:"required_flags"`
	} `json:"runtime"`
}

func (a *Adapter) providerCatalog(ctx context.Context, r request, owner *controlOwner) ([]protocol.NativeProviderCapability, error) {
	call := invocation{command: "providers", args: []string{"providers", "--json"}, config: r.config, directory: owner.temporary}
	response, err := a.run(ctx, call)
	if err != nil {
		return nil, err
	}
	if response.exitCode != 0 || response.Error != "" {
		return nil, ErrEvidence
	}
	providers := make([]protocol.NativeProviderCapability, 0, len(response.providerCatalog))
	for _, description := range response.providerCatalog {
		providers = append(providers, protocol.NativeProviderCapability{Provider: description.ID, SupportedModes: description.SupportedModes, SupportedOptions: description.SupportedOptions, RequiredOptions: description.RequiredOptions, Continuation: description.Continuation, Authentication: "unknown"})
	}
	return providers, nil
}
