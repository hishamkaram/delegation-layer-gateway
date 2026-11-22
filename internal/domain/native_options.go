package domain

import (
	"encoding/hex"
	"unicode/utf8"
)

// NativeOptions carries execution intent, not Gateway execution policy. Only
// Delegate decides whether a provider supports these values or their defaults.
// Version zero is absent; version one preserves omitted Native options.
type NativeOptions struct {
	Version              int        `json:"version"`
	Provider             ProviderID `json:"provider"`
	Model                Selection  `json:"model"`
	Effort               Selection  `json:"effort"`
	Permission           string     `json:"permission,omitempty"`
	Budget               string     `json:"budget,omitempty"`
	ReviewTarget         string     `json:"review_target,omitempty"`
	NativeTimeout        string     `json:"native_timeout,omitempty"`
	OutputSilenceTimeout string     `json:"output_silence_timeout,omitempty"`
}

func (o NativeOptions) Validate() error {
	if o.Version != 1 || Token(string(o.Provider)) != nil || o.Model.Validate() != nil || o.Effort.Validate() != nil {
		return ErrInvalid
	}
	for _, value := range []string{o.Permission, o.Budget, o.ReviewTarget, o.NativeTimeout, o.OutputSilenceTimeout} {
		if value != "" && optionValue(value) != nil {
			return ErrInvalid
		}
	}
	return nil
}

// OperationRoute is immutable operation-owned selection, never a project pin.
// Registry retains it after discarding request bodies. Context stores one-way
// Native guard commitments; no local context token enters this record.
type OperationRoute struct {
	Version        int
	RequestID      RequestID
	InputDigest    Digest
	ScopeID        string
	RelativePath   string
	WorkspaceGuard string
	Predecessor    OperationID
	InputFormat    InputFormat `json:",omitzero"`
}

func (r OperationRoute) Validate() error {
	if r.Version != 1 || TaskID(r.RequestID).Validate() != nil || r.InputDigest.Validate() != nil || Token(r.ScopeID) != nil {
		return ErrInvalid
	}
	if len(r.RelativePath) == 0 || len(r.RelativePath) > 4096 || !utf8.ValidString(r.RelativePath) {
		return ErrInvalid
	}
	if r.WorkspaceGuard != "" && ContextToken(r.WorkspaceGuard) != nil {
		return ErrInvalid
	}
	if r.Predecessor != "" && Token(string(r.Predecessor)) != nil {
		return ErrInvalid
	}
	if r.InputFormat != "" && r.InputFormat != DispatchInputV1 && r.InputFormat != ContinuationInputV1 {
		return ErrInvalid
	}
	return nil
}

func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }
