package deviceclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const maxNativeContextBytes = 1 << 20

type workspaceRecord struct {
	WorkspaceApproval
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
	Enabled  bool   `json:"enabled"`
}

func validWorkspaceApproval(a WorkspaceApproval) bool {
	return domain.Token(a.Alias) == nil && localPath(a.Directory) && opaqueContext(a.NativeContext) && validProviders(a.Providers)
}

func opaqueContext(value string) bool {
	return len(value) > 0 && len(value) <= maxNativeContextBytes && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validWorkspaceRecords(workspaces []workspaceRecord) bool {
	if len(workspaces) > protocol.MaxWorkspaces {
		return false
	}
	ids, names := make(map[string]bool), make(map[string]bool)
	for _, w := range workspaces {
		if !validWorkspaceApproval(w.WorkspaceApproval) || domain.TaskID(w.ID).Validate() != nil || strings.ToLower(w.ID) != w.ID || w.Revision == 0 || ids[w.ID] {
			return false
		}
		if w.Enabled {
			if names[w.Alias] {
				return false
			}
			names[w.Alias] = true
		}
		ids[w.ID] = true
	}
	return true
}

func clonePolicies(policies []ProviderPolicy) []ProviderPolicy {
	result := slices.Clone(policies)
	for i := range result {
		result[i].Models = slices.Clone(result[i].Models)
		result[i].Efforts = slices.Clone(result[i].Efforts)
		result[i].Permissions = slices.Clone(result[i].Permissions)
	}
	return result
}

func cloneApprovals(approvals []WorkspaceApproval) []WorkspaceApproval {
	result := slices.Clone(approvals)
	for i := range result {
		result[i].Providers = clonePolicies(result[i].Providers)
	}
	return result
}

func (w workspaceRecord) view() Workspace {
	return Workspace{ID: w.ID, Alias: w.Alias, Directory: w.Directory, Revision: w.Revision, Enabled: w.Enabled, Providers: clonePolicies(w.Providers)}
}

func approvalWithDefaults(a WorkspaceApproval, defaults []ProviderPolicy) WorkspaceApproval {
	if a.Providers == nil {
		a.Providers = defaults
	}
	a.Providers = clonePolicies(a.Providers)
	return a
}

func mintWorkspace(approval WorkspaceApproval, defaults []ProviderPolicy, random io.Reader) (workspaceRecord, error) {
	if !validWorkspaceApproval(approval) || random == nil {
		return workspaceRecord{}, ErrConfiguration
	}
	var id [16]byte
	if _, err := io.ReadFull(random, id[:]); err != nil {
		return workspaceRecord{}, failed(ErrPersistence, err)
	}
	return workspaceRecord{WorkspaceApproval: approvalWithDefaults(approval, defaults), ID: hex.EncodeToString(id[:]), Revision: 1, Enabled: true}, nil
}

func initialWorkspaces(approvals []WorkspaceApproval, defaults []ProviderPolicy, random io.Reader) ([]workspaceRecord, error) {
	records := make([]workspaceRecord, 0, len(approvals))
	for _, approval := range approvals {
		record, err := mintWorkspace(approval, defaults, random)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func sameApprovals(input []WorkspaceApproval, stored []workspaceRecord, defaults []ProviderPolicy) bool {
	if len(input) != len(stored) {
		return false
	}
	for i, approval := range input {
		if !stored[i].Enabled || !reflect.DeepEqual(approvalWithDefaults(approval, defaults), stored[i].WorkspaceApproval) {
			return false
		}
	}
	return true
}

// ListWorkspaces returns copied local UI values, including disabled history.
// It performs no Native inspection, directory scan, OAuth or network request.
func ListWorkspaces(ctx context.Context, profileDirectory string) (result []Workspace, resultErr error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, failed(ErrProfile, err)
	}
	store, err := openProfile(profileDirectory, false, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, failed(ErrProfile, closeErr))
		}
	}()
	if store.value == nil {
		return nil, ErrProfile
	}
	result = make([]Workspace, 0, len(store.value.Workspaces))
	for _, workspace := range store.value.Workspaces {
		result = append(result, workspace.view())
	}
	return result, nil
}

type workspaceMutation func(profile) (profile, Workspace, bool, error)

func changeWorkspace(ctx context.Context, directory string, revocation bool, change workspaceMutation) (workspace Workspace, resultErr error) {
	if ctx == nil {
		return workspace, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return workspace, failed(ErrProfile, err)
	}
	store, err := openProfile(directory, false, true)
	if err != nil {
		return workspace, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, failed(ErrPersistence, closeErr))
		}
	}()
	if store.value == nil {
		return workspace, ErrProfile
	}
	next, workspace, changed, err := change(*store.value)
	if err != nil || !changed {
		return workspace, err
	}
	if err = ctx.Err(); err != nil {
		return Workspace{}, failed(ErrPersistence, err)
	}
	if err = store.savePartition(next, revocation); err != nil {
		return Workspace{}, err
	}
	return workspace, nil
}

// AllowWorkspace explicitly approves one frozen directory/context. Repeating
// the same active approval reuses its ID; retargeting an alias is rejected.
func AllowWorkspace(ctx context.Context, directory string, approval WorkspaceApproval) (Workspace, error) {
	if !validWorkspaceApproval(approval) {
		return Workspace{}, ErrConfiguration
	}
	approval = cloneApprovals([]WorkspaceApproval{approval})[0]
	return changeWorkspace(ctx, directory, false, func(current profile) (profile, Workspace, bool, error) {
		normalized := approvalWithDefaults(approval, current.Providers)
		for _, existing := range current.Workspaces {
			if existing.Enabled && existing.Alias == approval.Alias {
				if reflect.DeepEqual(existing.WorkspaceApproval, normalized) {
					return current, existing.view(), false, nil
				}
				return current, Workspace{}, false, ErrConflict
			}
		}
		if len(current.Workspaces) >= protocol.MaxWorkspaces {
			return current, Workspace{}, false, ErrCapacity
		}
		record, err := mintWorkspace(approval, current.Providers, rand.Reader)
		if err != nil {
			return current, Workspace{}, false, err
		}
		current.Workspaces = append(slices.Clone(current.Workspaces), record)
		return current, record.view(), true, nil
	})
}

// UpdateWorkspace changes only one approval's alias or provider ceiling using
// its current revision. Directory and Native identity cannot be retargeted.
func UpdateWorkspace(ctx context.Context, directory, id string, expectedRevision uint64, update WorkspaceUpdate) (Workspace, error) {
	if expectedRevision == 0 || (update.Alias != "" && domain.Token(update.Alias) != nil) || !validProviders(update.Providers) {
		return Workspace{}, ErrConfiguration
	}
	update.Providers = clonePolicies(update.Providers)
	return changeWorkspace(ctx, directory, update.Providers != nil && len(update.Providers) == 0 && update.Alias == "", func(current profile) (profile, Workspace, bool, error) {
		return reviseWorkspace(current, id, expectedRevision, update, false)
	})
}

// RemoveWorkspace retains a disabled history entry and its stable ID. The 100
// workspace limit includes these entries; no history is silently evicted.
func RemoveWorkspace(ctx context.Context, directory, id string, expectedRevision uint64) (Workspace, error) {
	if expectedRevision == 0 {
		return Workspace{}, ErrConfiguration
	}
	return changeWorkspace(ctx, directory, true, func(current profile) (profile, Workspace, bool, error) {
		return reviseWorkspace(current, id, expectedRevision, WorkspaceUpdate{}, true)
	})
}

func reviseWorkspace(current profile, id string, revision uint64, update WorkspaceUpdate, remove bool) (profile, Workspace, bool, error) {
	index := slices.IndexFunc(current.Workspaces, func(w workspaceRecord) bool { return w.ID == id })
	if index < 0 {
		return current, Workspace{}, false, ErrConflict
	}
	existing := current.Workspaces[index]
	if existing.Revision != revision || !existing.Enabled {
		return current, Workspace{}, false, ErrConflict
	}
	next := existing
	if update.Alias != "" {
		next.Alias = update.Alias
	}
	if update.Providers != nil {
		next.Providers = clonePolicies(update.Providers)
	}
	next.Enabled = !remove
	if reflect.DeepEqual(existing, next) {
		return current, existing.view(), false, nil
	}
	if existing.Revision == ^uint64(0) {
		if !remove && (update.Providers == nil || len(update.Providers) != 0 || update.Alias != "") {
			return current, Workspace{}, false, ErrCapacity
		}
	} else {
		next.Revision++
	}
	current.Workspaces = slices.Clone(current.Workspaces)
	current.Workspaces[index] = next
	if !validWorkspaceRecords(current.Workspaces) {
		return current, Workspace{}, false, ErrConflict
	}
	return current, next.view(), true, nil
}

// Reject an unambiguously oversized aggregate before allocating encoded JSON.
// The final encoder checks the exact whole-bundle byte limit as well.

func (p profile) payloadBytesExceedBudget() bool {
	remaining := maxBaseProfileBytes
	for _, value := range profileStrings(p) {
		if !takeProfileBytes(value, &remaining) {
			return true
		}
	}
	if !takePolicyBytes(p.Providers, &remaining) {
		return true
	}
	for _, workspace := range p.Workspaces {
		if !takeProfileBytes(workspace.NativeContext, &remaining) || !takeProfileBytes(workspace.Directory, &remaining) || !takeProfileBytes(workspace.Alias, &remaining) || !takePolicyBytes(workspace.Providers, &remaining) {
			return true
		}
	}
	return false
}

func takeProfileBytes(value string, remaining *int) bool {
	if len(value) > *remaining {
		return false
	}
	*remaining -= len(value)
	return true
}

func takePolicyBytes(policies []ProviderPolicy, remaining *int) bool {
	for _, provider := range policies {
		if !takeProfileBytes(provider.Provider, remaining) {
			return false
		}
		for _, values := range [][]string{provider.Models, provider.Efforts, provider.Permissions} {
			for _, value := range values {
				if !takeProfileBytes(value, remaining) {
					return false
				}
			}
		}
	}
	return true
}

func profileStrings(p profile) []string {
	d := p.Descriptor
	result := []string{p.DelegateExecutable, p.DelegateRoot, p.DelegateRootContext, p.DeviceName, p.PrivateCAFile, p.Issuer.Issuer, p.Issuer.Device, p.Issuer.Token, d.GatewayID, d.PublicURL, d.Issuer, d.NativeClientID, d.Audience, d.EnrollmentURL, d.SelfEnrollmentURL, d.RevokeURL, d.DeviceWSSURL, d.DeviceCAPEM}
	return append(result, d.Capabilities...)
}
