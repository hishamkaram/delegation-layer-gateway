// Package deviceclient connects an explicitly selected Delegate installation to
// a trusted Gateway. Delegate remains the task execution and outcome authority.
package deviceclient

import (
	"context"
	"io"
	"time"
)

// ConnectOptions contains caller-approved local choices. It never selects a
// Delegate state root, starts providers or installs a background service.
type ConnectOptions struct {
	GatewayURL            string
	ProfileDirectory      string
	DelegateExecutable    string
	DelegateRoot          string
	DelegateRootContext   string
	DeviceName            string
	PrivateCAFile         string
	Workspaces            []WorkspaceApproval
	Providers             []ProviderPolicy
	PresentChallenge      func(context.Context, Challenge) error
	EnrollmentTokenFile   string
	EnrollmentTokenReader io.Reader
	ReplaceExisting       bool
}

func (ConnectOptions) String() string     { return "device_connect_options" }
func (o ConnectOptions) GoString() string { return o.String() }

type WorkspaceApproval struct {
	Alias         string           `json:"alias"`
	Directory     string           `json:"directory"`
	NativeContext string           `json:"native_context"`
	Providers     []ProviderPolicy `json:"providers"`
}

func (WorkspaceApproval) String() string     { return "workspace_approval" }
func (a WorkspaceApproval) GoString() string { return a.String() }

// Workspace is a local UI view. Native identity tokens are retained privately.
// Disabled historical approvals remain in the lifetime profile bound of 100.
type Workspace struct {
	ID        string           `json:"id"`
	Alias     string           `json:"alias"`
	Directory string           `json:"directory"`
	Revision  uint64           `json:"revision"`
	Enabled   bool             `json:"enabled"`
	Providers []ProviderPolicy `json:"providers"`
}

// WorkspaceUpdate cannot retarget a directory or Native context. Nil Providers
// preserves the current policy; an explicit empty slice disables all providers.
type WorkspaceUpdate struct {
	Alias     string
	Providers []ProviderPolicy
}

type ProviderPolicy struct {
	Provider         string   `json:"provider"`
	Models           []string `json:"models"`
	Efforts          []string `json:"efforts"`
	Permissions      []string `json:"permissions"`
	MaxBudgetSeconds uint32   `json:"max_budget_seconds"`
	NativeModel      bool     `json:"native_model"`
	NativeEffort     bool     `json:"native_effort"`
}

// Challenge contains only the fields the caller may deliberately present.
// Its normal formatted representation redacts even the user-facing code.
type Challenge struct {
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresAt               time.Time
}

func (Challenge) String() string     { return "device_auth_challenge" }
func (c Challenge) GoString() string { return c.String() }

// ConnectionStatus is a dated local observation, not execution readiness or
// proof of remote revocation. IdentityInUse leaves credential state unknown.
type ConnectionStatus struct {
	GatewayID            string    `json:"gateway_id"`
	GatewayURL           string    `json:"gateway_url"`
	DeviceID             string    `json:"device_id,omitempty"`
	OwnerPrincipal       string    `json:"owner_principal,omitempty"`
	CredentialGeneration uint64    `json:"credential_generation,omitempty"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at,omitempty"`
	CredentialState      string    `json:"credential_state"`
	IdentityInUse        bool      `json:"identity_in_use"`
	ObservedAt           time.Time `json:"observed_at"`
}

// LocalContextInfo is explicit local-only input for Native context inspection.
// It contains no credentials. Its opaque Native token must never cross MCP/WSS.
type LocalContextInfo struct {
	DelegateExecutable  string           `json:"delegate_executable"`
	DelegateRoot        string           `json:"delegate_root"`
	DelegateRootContext string           `json:"-"`
	Providers           []ProviderPolicy `json:"providers"`
}

func (LocalContextInfo) String() string     { return "gateway_local_context" }
func (c LocalContextInfo) GoString() string { return c.String() }
