package connector

import (
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Adapter owns the dated native capability cache. Only validated observations
// from its current config generation mutate it; service reads immutable copies.
// The aggregate timestamp is the oldest retained per-project observation.
func (a *Adapter) observeProject(generation uint64, project protocol.ProjectCapability) {
	if project.Validate() != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.generation != generation {
		return
	}
	found := false
	for index, old := range a.report.Projects {
		if old.Alias == project.Alias {
			a.report.Projects[index] = project
			found = true
			break
		}
	}
	if !found {
		a.report.Projects = append(a.report.Projects, project)
	}
	if a.observed == nil {
		a.observed = make(map[string]time.Time)
	}
	a.observed[project.Alias] = a.now()
	a.report.ObservedAt = oldestObservation(a.observed)
	a.probed = len(a.report.Projects) == len(a.config.Projects)
	for _, entry := range a.report.Projects {
		a.probed = a.probed && entry.Ready
	}
}

func oldestObservation(observed map[string]time.Time) time.Time {
	var oldest time.Time
	for _, at := range observed {
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	return oldest
}

// Namespace transitions invalidate project execution claims, never their dated
// provider observations. Only a fresh full project inspection can restore Ready.
func (a *Adapter) invalidateRootReadiness(generation uint64, rootToken string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.generation != generation {
		return
	}
	for i, report := range a.report.Projects {
		project, ok := a.config.projects[report.Alias]
		if ok && project.RootToken == rootToken {
			a.report.Projects[i].Ready = false
			a.probed = false
		}
	}
}
