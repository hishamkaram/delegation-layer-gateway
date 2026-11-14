// Package connector adapts typed wire controls to the installed public Delegate
// CLI. Delegate alone owns admission, execution, cancellation and accepted data.
package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const (
	MaxStdoutBytes = 256 << 10
	MaxStderrBytes = 16 << 10
	// V2 local envelopes may contain two one-MiB opaque Native tokens. They
	// are normalized before the separate bounded wire frame is constructed.
	MaxWorkspaceStdoutBytes = 4 << 20
	DefaultControlTimeout   = 30 * time.Second
	MaxControlTimeout       = 300 * time.Second
)

var (
	ErrConfiguration = errors.New("connector_invalid_configuration")
	ErrPending       = errors.New("pending")
	ErrCapacity      = errors.New("resource_limit")
	ErrConflict      = errors.New("conflict")
	ErrEvidence      = errors.New("evidence_invalid")
)

// ProviderPolicy is the local authority, independent of Gateway grants.
type ProviderPolicy struct {
	Provider         string
	Models           []string
	Efforts          []string
	Permissions      []domain.Permission
	MaxBudgetSeconds uint32
	NativeModel      bool
	NativeEffort     bool
}
type (
	Project struct {
		Alias        string
		Root         string
		Directory    string
		RootToken    string
		ProjectToken string
		Providers    []ProviderPolicy
	}
	Config struct {
		Executable         string
		TemporaryDirectory string
		GatewayID          domain.GatewayID
		Projects           []Project
		// ProjectStore enables the opt-in workspace protocol. It is exclusive
		// with static Projects and remains the local policy/pin authority.
		ProjectStore   ProjectStore
		ControlTimeout time.Duration
	}
)

type configuration struct {
	Config
	generation uint64
	projects   map[string]Project
}

func checkedConfig(input Config) (*configuration, error) {
	if pathsErr := checkConfigPaths(input); pathsErr != nil {
		return nil, pathsErr
	}
	if input.ControlTimeout == 0 {
		input.ControlTimeout = DefaultControlTimeout
	}
	if input.ControlTimeout <= 0 || input.ControlTimeout > MaxControlTimeout {
		return nil, ErrConfiguration
	}
	result := &configuration{Config: input, projects: make(map[string]Project)}
	result.Projects = make([]Project, 0, len(input.Projects))
	for _, project := range input.Projects {
		if err := checkProject(project); err != nil {
			return nil, err
		}
		if _, exists := result.projects[project.Alias]; exists {
			return nil, ErrConfiguration
		}
		project.Providers = clonePolicies(project.Providers)
		result.projects[project.Alias] = project
		result.Projects = append(result.Projects, project)
	}
	return result, nil
}

func checkConfigPaths(input Config) error {
	if !filepath.IsAbs(input.Executable) || !filepath.IsAbs(input.TemporaryDirectory) || domain.Token(string(input.GatewayID)) != nil || !validProjectMode(input) {
		return ErrConfiguration
	}
	executable, err := os.Stat(input.Executable)
	if err != nil || !executable.Mode().IsRegular() || executable.Mode()&0o111 == 0 {
		return ErrConfiguration
	}
	if !existingDirectory(input.TemporaryDirectory) {
		return ErrConfiguration
	}

	return nil
}

func validProjectMode(input Config) bool {
	if input.ProjectStore != nil {
		return len(input.Projects) == 0
	}
	return len(input.Projects) > 0 && len(input.Projects) <= 100
}

func existingDirectory(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func checkProject(p Project) error {
	if pinsErr := checkProjectPins(p); pinsErr != nil {
		return pinsErr
	}
	seen := make(map[string]bool)
	for _, policy := range p.Providers {
		if seen[policy.Provider] {
			return ErrConfiguration
		}
		seen[policy.Provider] = true
		if policyErr := checkPolicy(policy); policyErr != nil {
			return policyErr
		}
	}
	return nil
}

func checkProjectPins(p Project) error {
	if !existingDirectory(p.Root) || !filepath.IsAbs(p.Directory) || filepath.Clean(p.Directory) != p.Directory || (protocol.ProjectCapability{Alias: p.Alias}).Validate() != nil || !digest(p.RootToken) {
		return ErrConfiguration
	}
	if len(p.ProjectToken) == 0 || len(p.ProjectToken) > 4096 || strings.ContainsAny(p.ProjectToken, "\x00\r\n") || len(p.Providers) > 100 {
		return ErrConfiguration
	}
	return nil
}

func checkPolicy(policy ProviderPolicy) error {
	ceiling := domain.DispatchCeiling{Providers: []domain.ProviderID{domain.ProviderID(policy.Provider)}, Permissions: policy.Permissions, MaxBudgetSeconds: policy.MaxBudgetSeconds}
	if ceiling.Validate() != nil || len(policy.Models) > 100 || len(policy.Efforts) > 100 {
		return ErrConfiguration
	}
	for _, values := range [][]string{policy.Models, policy.Efforts} {
		for _, value := range values {
			if (protocol.Selection{Kind: "explicit", Value: value}).Validate() != nil {
				return ErrConfiguration
			}
		}
	}
	return nil
}

func clonePolicies(input []ProviderPolicy) []ProviderPolicy {
	result := make([]ProviderPolicy, len(input))
	for i, p := range input {
		p.Models = append([]string(nil), p.Models...)
		p.Efforts = append([]string(nil), p.Efforts...)
		p.Permissions = append([]domain.Permission(nil), p.Permissions...)
		result[i] = p
	}
	return result
}

func (p Project) wireContext() protocol.ContextBinding {
	return protocol.ContextBinding{Root: protocol.WireContextGuard(p.RootToken), Project: protocol.WireContextGuard(p.ProjectToken)}
}
