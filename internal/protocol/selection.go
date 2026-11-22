package protocol

import "time"

// SelectionRequest obtains Native context for one operation-owned project.
// It is read-only: no permanent connector pin or Gateway project is created.
type SelectionRequest struct {
	Selection FileSelection `json:"selection"`
}

func (r SelectionRequest) Validate() error {
	if r.Selection.Validate() != nil || r.Selection.RelativePathBase64 != "" {
		return ErrInvalid
	}
	return nil
}

type NativeProviderCapability struct {
	Provider         string   `json:"provider"`
	SupportedModes   []string `json:"supported_modes"`
	SupportedOptions []string `json:"supported_options"`
	RequiredOptions  []string `json:"required_options,omitempty"`
	Continuation     string   `json:"continuation"`
	Authentication   string   `json:"authentication"`
}

// SelectionObservation is advisory dated Native metadata. It never authorizes
// an execution option. The operation freezes its exact guards independently.
type SelectionObservation struct {
	Selection           FileSelection              `json:"selection"`
	Context             ContextBinding             `json:"context"`
	WorkspaceGuard      string                     `json:"workspace_guard,omitempty"`
	AdmissionOpen       bool                       `json:"admission_open"`
	AdmissionGeneration string                     `json:"admission_generation"`
	Features            []string                   `json:"features"`
	Providers           []NativeProviderCapability `json:"providers"`
	ObservedAt          time.Time                  `json:"observed_at"`
}

func (r SelectionObservation) ValidateFor(request SelectionRequest) error {
	if err := r.validateHeader(request); err != nil {
		return err
	}
	for _, feature := range r.Features {
		if !identifier(feature) {
			return ErrInvalid
		}
	}
	return validateNativeProviders(r.Providers)
}

func (r SelectionObservation) validateHeader(request SelectionRequest) error {
	if request.Validate() != nil || r.Selection != request.Selection || !guardToken(r.Context.Root) || !guardToken(r.Context.Project) || (r.AdmissionGeneration != "" && !identifier(r.AdmissionGeneration)) || r.ObservedAt.IsZero() || len(r.Features) > 100 || len(r.Providers) > 100 {
		return ErrInvalid
	}
	if r.AdmissionOpen && r.AdmissionGeneration == "" {
		return ErrInvalid
	}
	if r.WorkspaceGuard != "" && !guardToken(r.WorkspaceGuard) {
		return ErrInvalid
	}
	return nil
}

func validateNativeProviders(providers []NativeProviderCapability) error {
	seen := make(map[string]bool)
	for _, p := range providers {
		if p.validate() != nil || seen[p.Provider] {
			return ErrInvalid
		}
		seen[p.Provider] = true
	}
	return nil
}

func (p NativeProviderCapability) validate() error {
	if !identifier(p.Provider) || len(p.SupportedModes) > 32 || len(p.SupportedOptions) > 64 || len(p.RequiredOptions) > 64 || len(p.Continuation) > 128 {
		return ErrInvalid
	}
	for _, set := range [][]string{p.SupportedModes, p.SupportedOptions, p.RequiredOptions} {
		if err := validateSelectionTokens(set); err != nil {
			return err
		}
	}
	switch p.Authentication {
	case "unknown", "verified", "unavailable":
		return nil
	default:
		return ErrInvalid
	}
}

func validateSelectionTokens(values []string) error {
	for _, value := range values {
		if !selectionToken(value) {
			return ErrInvalid
		}
	}
	return nil
}
