package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	WorkspaceFeature   = "workspace-constrained-connector-v1"
	MaxWorkspaces      = 100
	MaxProjectPins     = 1024
	MaxProjectPinBytes = 4 << 20
)

// WorkspaceBinding identifies a locally approved directory. Its ID and guard
// never change; current policy revisions are separate dated observations.
type WorkspaceBinding struct {
	ID    string `json:"workspace_id"`
	Guard string `json:"guard"`
}

func (w WorkspaceBinding) Validate() error {
	if !identifier(w.ID) || !guardToken(w.Guard) {
		return ErrInvalid
	}
	return nil
}

type WorkspaceCapability struct {
	WorkspaceBinding
	Name           string `json:"name"`
	PolicyRevision uint64 `json:"policy_revision"`
}

// CapabilityReportV2 has a bounded workspace inventory and no project list.
// Resolved projects are queried individually; durable tombstones never enlarge
// HELLO or its periodic metadata refresh.
type CapabilityReportV2 struct {
	ObservedAt    time.Time             `json:"observed_at"`
	Root          *RootCapability       `json:"root,omitempty"`
	Workspaces    []WorkspaceCapability `json:"workspaces"`
	ProjectBudget *ProjectBudget        `json:"project_budget,omitempty"`
}

// ProjectBudget is a dated local capacity observation, never an admission
// reservation. Both durable record count and encoded bytes bound new pins.
type ProjectBudget struct {
	Limit     uint32 `json:"limit"`
	Used      uint32 `json:"used"`
	ByteLimit uint32 `json:"byte_limit"`
	BytesUsed uint32 `json:"bytes_used"`
}

func (b ProjectBudget) Validate() error {
	if b.Limit != MaxProjectPins || b.Used > b.Limit || b.ByteLimit != MaxProjectPinBytes || b.BytesUsed > b.ByteLimit {
		return ErrInvalid
	}
	return nil
}

func (r CapabilityReportV2) Validate() error {
	if r.ObservedAt.IsZero() || len(r.Workspaces) > MaxWorkspaces {
		return ErrInvalid
	}
	if r.ProjectBudget != nil && r.ProjectBudget.Validate() != nil {
		return ErrInvalid
	}
	if r.Root == nil {
		if len(r.Workspaces) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if r.Root.Validate() != nil || !slices.Contains(r.Root.Features, WorkspaceFeature) {
		return ErrInvalid
	}
	ids, names := make(map[string]bool), make(map[string]bool)
	for _, workspace := range r.Workspaces {
		if workspace.Validate() != nil || !identifier(workspace.Name) || workspace.PolicyRevision == 0 || ids[workspace.ID] || names[workspace.Name] {
			return ErrInvalid
		}
		ids[workspace.ID], names[workspace.Name] = true, true
	}
	return nil
}

// ResolveProjectRequest is a durable local pin request. Retrying RequestID must
// return its original binding, including after a directory or policy changes.
type ResolveProjectRequest struct {
	RequestID    string `json:"request_id"`
	WorkspaceID  string `json:"workspace_id"`
	RelativePath string `json:"relative_path"`
}

func (r ResolveProjectRequest) Validate() error {
	if !lowerHex(r.RequestID, 32) || !identifier(r.WorkspaceID) || !ValidRelativeProject(r.RelativePath) {
		return ErrInvalid
	}
	return nil
}

// ValidRelativeProject accepts an existing-directory selector, not an arbitrary
// filesystem path. Native independently checks actual ancestry and symlinks.
func ValidRelativeProject(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.Contains(value, "\\") || path.IsAbs(value) || path.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." || len(part) > 255 {
			return false
		}
		for _, char := range part {
			if unicode.IsControl(char) || char == ':' {
				return false
			}
		}
	}
	return true
}

// ResolvedProject is immutable replay identity, independent of live readiness
// and execution permission. Handle is the accepted resolution request ID.
type ResolvedProject struct {
	Handle    string           `json:"handle"`
	Workspace WorkspaceBinding `json:"workspace"`
	Context   ContextBinding   `json:"context"`
}

func (p ResolvedProject) Validate() error {
	if !lowerHex(p.Handle, 32) || p.Workspace.Validate() != nil || !guardToken(p.Context.Root) || !guardToken(p.Context.Project) {
		return ErrInvalid
	}
	return nil
}

// ProjectCapabilityV2 is a fresh targeted observation of a retained identity.
// CurrentPolicyRevision is a freshness hint, never part of task identity or a
// substitute for checking the actual current ceiling through CLI Start.
type ProjectCapabilityV2 struct {
	Project               ResolvedProject   `json:"project"`
	CurrentPolicyRevision uint64            `json:"current_policy_revision"`
	Capability            ProjectCapability `json:"capability"`
}

func (p ProjectCapabilityV2) Validate() error {
	if p.Project.Validate() != nil || p.CurrentPolicyRevision == 0 || p.Capability.Validate() != nil {
		return ErrInvalid
	}
	if p.Capability.Alias != p.Project.Handle || p.Capability.Context != p.Project.Context || !slices.Contains(p.Capability.Features, WorkspaceFeature) {
		return ErrInvalid
	}
	return nil
}

type ResolveProjectReply struct {
	RequestID          string          `json:"request_id"`
	RelativePathSHA256 string          `json:"relative_path_sha256"`
	Project            ResolvedProject `json:"project"`
}

func (r ResolveProjectReply) ValidateFor(request ResolveProjectRequest) error {
	digest := sha256.Sum256([]byte(request.RelativePath))
	if request.Validate() != nil || r.RequestID != request.RequestID || r.Project.Handle != request.RequestID || r.RelativePathSHA256 != hex.EncodeToString(digest[:]) || r.Project.Validate() != nil || r.Project.Workspace.ID != request.WorkspaceID {
		return ErrInvalid
	}
	return nil
}
