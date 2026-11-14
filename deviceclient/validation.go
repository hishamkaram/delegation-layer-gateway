package deviceclient

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.RawPath != "" || len(raw) > 4096 || (u.Path != "" && u.Path != "/") {
		return "", ErrConfiguration
	}
	return "https://" + strings.ToLower(u.Host), nil
}

func httpsEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && u.RawPath == "" && len(raw) <= 4096
}

func localPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && utf8.ValidString(path) && !strings.ContainsAny(path, "\x00\r\n")
}

func checkedOptions(input ConnectOptions) (ConnectOptions, error) {
	gateway, err := origin(input.GatewayURL)
	if err != nil || !localPath(input.ProfileDirectory) || !localPath(input.DelegateExecutable) || !localPath(input.DelegateRoot) || !opaqueContext(input.DelegateRootContext) {
		return ConnectOptions{}, ErrConfiguration
	}
	file, err := os.Stat(input.DelegateExecutable)
	if err != nil || !file.Mode().IsRegular() || file.Mode().Perm()&0o111 == 0 {
		return ConnectOptions{}, ErrConfiguration
	}
	input.GatewayURL = gateway
	if !validEnrollmentOptions(input) {
		return ConnectOptions{}, ErrConfiguration
	}
	if !validWorkspaces(input.Workspaces, true) || !validProviders(input.Providers) {
		return ConnectOptions{}, ErrConfiguration
	}
	input.Workspaces = cloneApprovals(input.Workspaces)
	input.Providers = slices.Clone(input.Providers)
	for i := range input.Providers {
		input.Providers[i].Models = slices.Clone(input.Providers[i].Models)
		input.Providers[i].Efforts = slices.Clone(input.Providers[i].Efforts)
		input.Providers[i].Permissions = slices.Clone(input.Providers[i].Permissions)
	}
	return input, nil
}

func validProvider(p ProviderPolicy) bool {
	permissions := make([]domain.Permission, len(p.Permissions))
	for i, v := range p.Permissions {
		permissions[i] = domain.Permission(v)
	}
	ceiling := domain.DispatchCeiling{Providers: []domain.ProviderID{domain.ProviderID(p.Provider)}, Permissions: permissions, MaxBudgetSeconds: p.MaxBudgetSeconds}
	capability := protocol.ProviderCapability{Provider: p.Provider, Models: p.Models, Efforts: p.Efforts, Permissions: p.Permissions, MaxBudgetSeconds: p.MaxBudgetSeconds, Authentication: "unknown"}
	if ceiling.Validate() != nil || capability.Validate() != nil || !uniqueSelections(p.Models) || !uniqueSelections(p.Efforts) || !uniqueSelections(p.Permissions) {
		return false
	}

	return true
}

func validWorkspaces(workspaces []WorkspaceApproval, checkDisk bool) bool {
	if len(workspaces) > 100 {
		return false
	}
	seen := make(map[string]bool)
	for _, workspace := range workspaces {
		if !validWorkspaceApproval(workspace) || seen[workspace.Alias] {
			return false
		}
		seen[workspace.Alias] = true
		if checkDisk {
			info, err := os.Stat(workspace.Directory)
			if err != nil || !info.IsDir() {
				return false
			}
		}
	}
	return true
}

func validProviders(providers []ProviderPolicy) bool {
	if len(providers) > 100 {
		return false
	}
	seen := make(map[string]bool)
	for _, provider := range providers {
		if seen[provider.Provider] || !validProvider(provider) {
			return false
		}
		seen[provider.Provider] = true
	}
	return true
}

func validEnrollmentOptions(input ConnectOptions) bool {
	if input.PrivateCAFile != "" && !localPath(input.PrivateCAFile) {
		return false
	}
	if input.EnrollmentTokenFile != "" && (input.EnrollmentTokenReader != nil || !localPath(input.EnrollmentTokenFile)) {
		return false
	}
	return input.DeviceName == "" || validName(input.DeviceName)
}

func validName(name string) bool {
	return domain.ValidateDeviceName(name) == nil && strings.TrimSpace(name) == name
}

func uniqueSelections(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
