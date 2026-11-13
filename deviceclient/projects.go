package deviceclient

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type projectRecord struct {
	Request        protocol.ResolveProjectRequest `json:"request"`
	Identity       protocol.ResolvedProject       `json:"identity"`
	Directory      string                         `json:"directory"`
	ProjectContext string                         `json:"project_context"`
}

func validProjectRecords(p profile) bool {
	if len(p.Pins) > protocol.MaxProjectPins {
		return false
	}
	if len(p.Pins) == 0 {
		return true
	}
	guards := make(map[string]string, len(p.Workspaces))
	for _, w := range p.Workspaces {
		guards[w.ID] = protocol.WireContextGuard(w.NativeContext)
	}
	root := protocol.WireContextGuard(p.DelegateRootContext)
	ids := make(map[string]bool, len(p.Pins))
	for _, record := range p.Pins {
		if ids[record.Request.RequestID] || !record.validFor(root, guards[record.Request.WorkspaceID]) {
			return false
		}
		ids[record.Request.RequestID] = true
	}
	// All records share the selected root. Validate its Native root-token shape
	// once, without rescanning a 1MiB workspace token for every retained pin.
	_, err := p.Pins[0].project(p)
	return err == nil
}

func (r projectRecord) validFor(root, workspace string) bool {
	if r.Request.Validate() != nil || r.Identity.Validate() != nil || r.Identity.Handle != r.Request.RequestID || r.Identity.Workspace.ID != r.Request.WorkspaceID {
		return false
	}
	return localPath(r.Directory) && opaqueContext(r.ProjectContext) && r.Identity.Context.Root == root && r.Identity.Workspace.Guard == workspace && r.Identity.Context.Project == protocol.WireContextGuard(r.ProjectContext)
}

func (r projectRecord) project(p profile) (connector.ProjectPin, error) {
	if r.Request.Validate() != nil || r.Identity.Validate() != nil || r.Identity.Handle != r.Request.RequestID || r.Identity.Workspace.ID != r.Request.WorkspaceID || !localPath(r.Directory) || !opaqueContext(r.ProjectContext) {
		return connector.ProjectPin{}, connector.ErrEvidence
	}
	workspace, ok := findWorkspace(p, r.Request.WorkspaceID)
	if !ok {
		return connector.ProjectPin{}, connector.ErrEvidence
	}
	pin := connector.ProjectPin{Request: r.Request, WorkspaceContext: workspace.NativeContext, Project: connector.Project{Alias: r.Request.RequestID, Root: p.DelegateRoot, Directory: r.Directory, RootToken: p.DelegateRootContext, ProjectToken: r.ProjectContext}}
	if pin.Validate() != nil || pin.WireIdentity() != r.Identity {
		return connector.ProjectPin{}, connector.ErrEvidence
	}
	return pin, nil
}

func findWorkspace(p profile, id string) (workspaceRecord, bool) {
	for _, workspace := range p.Workspaces {
		if workspace.ID == id {
			return workspace, true
		}
	}
	return workspaceRecord{}, false
}

func pinIndex(p profile, id string) int {
	return slices.IndexFunc(p.Pins, func(r projectRecord) bool { return r.Request.RequestID == id })
}

type profileProjects struct{ directory string }

func newProfileProjects(directory string) *profileProjects {
	return &profileProjects{directory: directory}
}

var _ connector.ProjectStore = (*profileProjects)(nil)

func (p *profileProjects) Snapshot(ctx context.Context) (snapshot connector.WorkspaceSnapshot, result error) {
	store, err := p.read(ctx)
	if err != nil {
		return snapshot, err
	}
	defer func() { result = errors.Join(result, projectError(store.Close())) }()
	return projectSnapshot(*store.value)
}

func (p *profileProjects) read(ctx context.Context) (*profileStore, error) {
	if ctx == nil {
		return nil, connector.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, projectError(err)
	}
	store, err := openProfile(p.directory, false, false)
	if err != nil {
		return nil, projectError(err)
	}
	if store.value == nil {
		return nil, projectError(errors.Join(ErrProfile, store.Close()))
	}
	return store, nil
}

func projectSnapshot(p profile) (connector.WorkspaceSnapshot, error) {
	encoded, err := encodedPins(p.Pins)
	if err != nil {
		return connector.WorkspaceSnapshot{}, projectError(err)
	}
	snapshot := connector.WorkspaceSnapshot{RootDirectory: p.DelegateRoot, RootContext: p.DelegateRootContext, ProjectBudget: protocol.ProjectBudget{Limit: protocol.MaxProjectPins, Used: uint32(len(p.Pins)), ByteLimit: protocol.MaxProjectPinBytes, BytesUsed: uint32(len(encoded))}}
	snapshot.Workspaces = make([]connector.WorkspacePolicy, 0, len(p.Workspaces))
	for _, record := range p.Workspaces {
		snapshot.Workspaces = append(snapshot.Workspaces, workspacePolicy(record))
	}
	return snapshot, nil
}

func workspacePolicy(w workspaceRecord) connector.WorkspacePolicy {
	providers := make([]connector.ProviderPolicy, 0, len(w.Providers))
	for _, p := range w.Providers {
		permissions := make([]domain.Permission, len(p.Permissions))
		for i, value := range p.Permissions {
			permissions[i] = domain.Permission(value)
		}
		providers = append(providers, connector.ProviderPolicy{Provider: p.Provider, Models: slices.Clone(p.Models), Efforts: slices.Clone(p.Efforts), Permissions: permissions, MaxBudgetSeconds: p.MaxBudgetSeconds, NativeModel: p.NativeModel, NativeEffort: p.NativeEffort})
	}
	return connector.WorkspacePolicy{ID: w.ID, Alias: w.Alias, Directory: w.Directory, NativeContext: w.NativeContext, Revision: w.Revision, Enabled: w.Enabled, Providers: providers}
}

func (p *profileProjects) LookupPin(ctx context.Context, id string) (pin connector.ProjectPin, result error) {
	store, err := p.read(ctx)
	if err != nil {
		return pin, err
	}
	defer func() { result = errors.Join(result, projectError(store.Close())) }()
	index := pinIndex(*store.value, id)
	if index < 0 {
		return pin, connector.ErrConflict
	}
	return store.confirmProject(store.value.Pins[index])
}

func (p *profileProjects) LookupResolution(ctx context.Context, request protocol.ResolveProjectRequest) (pin connector.ProjectPin, found bool, result error) {
	if request.Validate() != nil {
		return pin, false, connector.ErrEvidence
	}
	store, err := p.read(ctx)
	if err != nil {
		return pin, false, err
	}
	defer func() { result = errors.Join(result, projectError(store.Close())) }()
	index := pinIndex(*store.value, request.RequestID)
	if index < 0 {
		return pin, false, nil
	}
	if store.value.Pins[index].Request != request {
		return pin, false, connector.ErrConflict
	}
	pin, err = store.confirmProject(store.value.Pins[index])
	return pin, err == nil, err
}

func (s *profileStore) confirmProject(record projectRecord) (connector.ProjectPin, error) {
	if err := s.directory.Sync(); err != nil {
		return connector.ProjectPin{}, projectError(err)
	}
	return record.project(*s.value)
}

func (p *profileProjects) Lock(ctx context.Context) (connector.WorkspaceLease, error) {
	if ctx == nil {
		return nil, connector.ErrConfiguration
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, failed(connector.ErrCapacity, err)
		}
		store, err := openProfile(p.directory, false, true)
		if err == nil {
			if store.value == nil {
				return nil, projectError(errors.Join(ErrProfile, store.Close()))
			}
			if syncErr := store.directory.Sync(); syncErr != nil {
				return nil, projectError(errors.Join(syncErr, store.Close()))
			}
			snapshot, snapshotErr := projectSnapshot(*store.value)
			if snapshotErr != nil {
				return nil, errors.Join(snapshotErr, projectError(store.Close()))
			}
			return &profileWorkspaceLease{store: store, snapshot: snapshot}, nil
		}
		if !errors.Is(err, ErrBusy) {
			return nil, projectError(err)
		}
		select {
		case <-ctx.Done():
			return nil, failed(connector.ErrCapacity, ctx.Err())
		case <-ticker.C:
		}
	}
}

type profileWorkspaceLease struct {
	store    *profileStore
	snapshot connector.WorkspaceSnapshot
	closed   bool
	closeErr error
}

var _ connector.WorkspaceLease = (*profileWorkspaceLease)(nil)

func (l *profileWorkspaceLease) Snapshot() connector.WorkspaceSnapshot {
	if l.closed {
		return connector.WorkspaceSnapshot{}
	}
	snapshot := l.snapshot
	snapshot.Workspaces = make([]connector.WorkspacePolicy, 0, len(l.snapshot.Workspaces))
	for _, record := range l.store.value.Workspaces {
		snapshot.Workspaces = append(snapshot.Workspaces, workspacePolicy(record))
	}
	return snapshot
}

func (l *profileWorkspaceLease) CurrentWorkspace(id string) (connector.WorkspacePolicy, error) {
	if l.closed {
		return connector.WorkspacePolicy{}, connector.ErrEvidence
	}
	w, ok := findWorkspace(*l.store.value, id)
	if !ok {
		return connector.WorkspacePolicy{}, connector.ErrConflict
	}
	return workspacePolicy(w), nil
}

func (l *profileWorkspaceLease) CommitResolution(pin connector.ProjectPin) (connector.ProjectPin, error) {
	if l.closed {
		return connector.ProjectPin{}, connector.ErrEvidence
	}
	if pin.Request.Validate() != nil {
		return connector.ProjectPin{}, connector.ErrEvidence
	}
	current := *l.store.value
	replay, found, replayErr := l.replayResolution(pin.Request)
	if found || replayErr != nil {
		return replay, replayErr
	}

	if l.store.uncertain {
		return connector.ProjectPin{}, connector.ErrEvidence
	}
	if err := validateNewProjectPin(current, pin); err != nil {
		return connector.ProjectPin{}, err
	}

	record := projectRecord{Request: pin.Request, Identity: pin.WireIdentity(), Directory: pin.Project.Directory, ProjectContext: pin.Project.ProjectToken}
	current.Pins = append(slices.Clone(current.Pins), record)
	snapshot, snapshotErr := projectSnapshot(current)
	if snapshotErr != nil {
		return connector.ProjectPin{}, snapshotErr
	}
	if err := l.store.savePartition(current, true); err != nil {
		if pinIndex(*l.store.value, pin.Request.RequestID) >= 0 {
			l.snapshot = snapshot
		}
		return connector.ProjectPin{}, projectError(err)
	}
	l.snapshot = snapshot
	return record.project(current)
}

func validateNewProjectPin(current profile, pin connector.ProjectPin) error {
	if pin.Validate() != nil {
		return connector.ErrEvidence
	}
	workspace, ok := findWorkspace(current, pin.Request.WorkspaceID)
	if !ok || !workspace.Enabled {
		return connector.ErrConflict
	}
	if pin.WorkspaceContext != workspace.NativeContext || pin.Project.Root != current.DelegateRoot || pin.Project.RootToken != current.DelegateRootContext {
		return connector.ErrEvidence
	}
	if len(current.Pins) >= protocol.MaxProjectPins {
		return connector.ErrCapacity
	}
	return nil
}

func (l *profileWorkspaceLease) replayResolution(request protocol.ResolveProjectRequest) (connector.ProjectPin, bool, error) {
	current := *l.store.value
	index := pinIndex(current, request.RequestID)
	if index < 0 {
		return connector.ProjectPin{}, false, nil
	}
	record := current.Pins[index]
	if record.Request != request {
		return connector.ProjectPin{}, true, connector.ErrConflict
	}
	pin, confirmErr := l.store.confirmProject(record)
	if confirmErr != nil {
		return connector.ProjectPin{}, true, confirmErr
	}

	l.store.uncertain = false
	snapshot, err := projectSnapshot(current)
	if err != nil {
		return connector.ProjectPin{}, true, err
	}
	l.snapshot = snapshot
	return pin, true, nil
}

func (l *profileWorkspaceLease) Close() error {
	if l.closed {
		return l.closeErr
	}
	l.closed = true
	l.closeErr = projectError(l.store.Close())
	return l.closeErr
}

func projectError(err error) error {
	if err == nil {
		return nil
	}
	kind := connector.ErrEvidence
	switch {
	case errors.Is(err, connector.ErrEvidence):
		kind = connector.ErrEvidence
	case errors.Is(err, ErrCapacity):
		kind = connector.ErrCapacity
	case errors.Is(err, ErrConflict):
		kind = connector.ErrConflict
	case errors.Is(err, ErrProfile), errors.Is(err, ErrConfiguration):
		kind = connector.ErrConfiguration
	}
	return failed(kind, err)
}
