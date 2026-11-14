package connector

import (
	"context"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// WorkspacePolicy is a copied current approval. Store alone mutates revisions
// and ceilings; the adapter never caches it as execution authority.
type WorkspacePolicy struct {
	ID            string
	Alias         string
	Directory     string
	NativeContext string
	Revision      uint64
	Enabled       bool
	Providers     []ProviderPolicy
}

type WorkspaceSnapshot struct {
	RootDirectory string
	RootContext   string
	Workspaces    []WorkspacePolicy
	ProjectBudget protocol.ProjectBudget
}

// ProjectPin is immutable local context history. Its Project.Providers must be
// empty: current policy is obtained separately, including for resume. Local
// paths and opaque Native tokens never leave this consumer-owned boundary.
type ProjectPin struct {
	Request          protocol.ResolveProjectRequest
	Project          Project
	WorkspaceContext string
}

func (p ProjectPin) Validate() error {
	if p.Request.Validate() != nil || p.Project.Alias != p.Request.RequestID || len(p.Project.Providers) != 0 {
		return ErrEvidence
	}
	for _, directory := range []string{p.Project.Root, p.Project.Directory} {
		if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
			return ErrEvidence
		}
	}
	if !digest(p.Project.RootToken) || !validNativeProjectToken(p.Project.ProjectToken) || !validNativeProjectToken(p.WorkspaceContext) {
		return ErrEvidence
	}
	return nil
}

func validNativeProjectToken(value string) bool {
	return len(value) > 0 && len(value) <= 1<<20 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (p ProjectPin) WireIdentity() protocol.ResolvedProject {
	return protocol.ResolvedProject{Handle: p.Request.RequestID, Workspace: protocol.WorkspaceBinding{ID: p.Request.WorkspaceID, Guard: protocol.WireContextGuard(p.WorkspaceContext)}, Context: p.Project.wireContext()}
}

// ProjectStore is implemented by the single durable local profile owner.
// Reads observe committed rename snapshots without the policy lock. A replay
// success and every retained-pin lookup confirm directory durability before
// returning identity. No successful Start or targeted evidence uses a merely
// visible, uncertain rename.
type ProjectStore interface {
	Snapshot(context.Context) (WorkspaceSnapshot, error)
	LookupPin(context.Context, string) (ProjectPin, error)
	LookupResolution(context.Context, protocol.ResolveProjectRequest) (ProjectPin, bool, error)
	Lock(context.Context) (WorkspaceLease, error)
}

// WorkspaceLease owns the same exclusive file lock used by local edits.
// Start authorization reloads under this lease and keeps it through CLI Start,
// then releases it before Wait. Unlock errors do not release Wait ownership or
// permit replacement execution after a successful Start.
type WorkspaceLease interface {
	Snapshot() WorkspaceSnapshot
	CurrentWorkspace(string) (WorkspacePolicy, error)
	// CommitResolution checks replay first (same request returns its durable
	// winner; changed request conflicts). New commits require the current
	// enabled workspace/root guards, then count/byte capacity, then durable
	// publication before acknowledgement. Candidate paths never replace replay.
	CommitResolution(ProjectPin) (ProjectPin, error)
	Close() error
}
