package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const (
	maxNativeModelFactsBytes = 512 << 10
	maxNativeModelRows       = 4096
)

// Native owns this bounded observation. Pagination carries its current facts,
// never a model allowlist or a persisted connector discovery cache.
type nativeModelCatalog struct {
	Status     string               `json:"status"`
	ReasonCode string               `json:"reason_code"`
	Complete   bool                 `json:"complete"`
	Source     string               `json:"source"`
	Models     []protocol.ModelFact `json:"models"`
	Efforts    []string             `json:"efforts"`
}

type nativeModelResponse struct {
	SchemaVersion int       `json:"schema_version"`
	Command       string    `json:"command"`
	Provider      string    `json:"provider"`
	ObservedAt    time.Time `json:"observed_at"`
	nativeModelCatalog
	Failure *cliFailure `json:"failure,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func (a *Adapter) discoverModels(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	root, err := a.verifiedRoot(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if !scopedModelsSupported(root.Features) {
		return protocol.Reply{Operation: r.command.Operation, Error: &protocol.Failure{Code: "delegate_upgrade_required", Stage: "models"}}
	}
	r, err = a.bindScopedProject(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	response, err := a.runModels(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if response.Failure != nil {
		return nativeFailureReply(r.command.Operation, response.Failure)
	}
	if response.Error != "" || response.models == nil || response.models.Provider != r.models.Provider {
		return failed(r.command.Operation, ErrEvidence)
	}
	catalog, err := canonicalModelCatalog(response.models.nativeModelCatalog, *r.models, response.models.ObservedAt)
	if err != nil || !validModelExit(response.exitCode, catalog.Status) {
		return failed(r.command.Operation, ErrEvidence)
	}
	page, err := r.modelPage(catalog, response.models.ObservedAt)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return protocol.Reply{Operation: r.command.Operation, Error: &protocol.Failure{Code: "catalog_changed", Stage: "models", Retryable: true}}
		}
		return failed(r.command.Operation, err)
	}
	return a.publishMetadata(ctx, r, page)
}

func scopedModelsSupported(features []string) bool {
	return slices.Contains(features, protocol.FeatureScopedModels) && slices.Contains(features, protocol.FeaturePathProject)
}

func (a *Adapter) runModels(ctx context.Context, r request, owner *controlOwner) (cliResponse, error) {
	workspace, err := owner.file("models-workspace.txt", []byte(r.scoped.scope.ExpectedWorkspace))
	if err != nil {
		return cliResponse{}, err
	}
	// Models has its own Native inspection lifetime and no control-timeout flag.
	call := invocation{command: "models", config: r.config, directory: owner.temporary, startGuard: r.scopedStartGuard, args: []string{"models", "--root", r.project.Root, "--provider", r.models.Provider, "--expected-root", r.project.RootToken, "--expected-workspace-file", workspace, "--relative-project", r.scoped.selection.RelativePath, "--json"}}
	return a.run(ctx, call)
}

func validModelExit(code int, status string) bool {
	switch status {
	case "available", "partial":
		return code == 0
	case "blocked", "unavailable":
		return code == 2
	case "failed":
		return code == 1
	default:
		return false
	}
}

func canonicalModelCatalog(catalog nativeModelCatalog, query protocol.ModelQuery, observed time.Time) (nativeModelCatalog, error) {
	if len(catalog.Models) > maxNativeModelRows || catalog.Models == nil || !distinctModelChoices(catalog.Efforts) || !validModelCatalogState(catalog) {
		return catalog, ErrEvidence
	}
	catalog.Models = slices.Clone(catalog.Models)
	catalog.Efforts = slices.Clone(catalog.Efforts)
	slices.Sort(catalog.Efforts)
	seen := make(map[string]bool, len(catalog.Models))
	for i, model := range catalog.Models {
		if seen[model.ID] || !distinctModelChoices(model.Efforts) || (model.DefaultEffort != "" && model.Efforts != nil && !slices.Contains(model.Efforts, model.DefaultEffort)) {
			return catalog, ErrEvidence
		}
		seen[model.ID] = true
		catalog.Models[i].Efforts = slices.Clone(model.Efforts)
		slices.Sort(catalog.Models[i].Efforts)
	}
	slices.SortFunc(catalog.Models, func(a, b protocol.ModelFact) int { return strings.Compare(a.ID, b.ID) })
	if _, err := protocol.Encode(catalog, maxNativeModelFactsBytes-1); err != nil {
		return catalog, ErrEvidence
	}
	// Reuse the wire text boundary in bounded pages, preserving Native's larger
	// full-catalog resource bound without adding another model-name validator.
	query.Limit = 100
	for next := 0; ; next += 100 {
		facts, eof := protocol.PageModelFacts(catalog.Models, next, 100)
		page := catalogPage(catalog, query.Provider, observed)
		page.Models, page.Version, page.EOF = facts, strings.Repeat("0", 64), true
		if page.ValidateFor(query) != nil {
			return catalog, ErrEvidence
		}
		if eof {
			break
		}
	}
	return catalog, nil
}

func validModelCatalogState(catalog nativeModelCatalog) bool {
	switch catalog.Status {
	case "available":
		return catalog.Complete && len(catalog.Models) != 0
	case "partial":
		return !catalog.Complete && len(catalog.Models) != 0
	case "blocked", "unavailable", "failed":
		return !catalog.Complete && len(catalog.Models) == 0
	default:
		return false
	}
}

func distinctModelChoices(choices []string) bool {
	if len(choices) > maxNativeModelRows {
		return false
	}
	seen := make(map[string]bool, len(choices))
	for _, choice := range choices {
		if seen[choice] {
			return false
		}
		seen[choice] = true
	}
	return true
}

func catalogPage(catalog nativeModelCatalog, provider string, observed time.Time) protocol.ModelPage {
	return protocol.ModelPage{Provider: provider, ObservedAt: observed, Status: catalog.Status, ReasonCode: catalog.ReasonCode, Source: catalog.Source, CatalogComplete: catalog.Complete, Efforts: catalog.Efforts}
}

func (r request) modelPage(catalog nativeModelCatalog, observed time.Time) (protocol.ModelPage, error) {
	page := catalogPage(catalog, r.models.Provider, observed)
	catalogBytes, err := protocol.Encode(catalog, maxNativeModelFactsBytes)
	if err != nil {
		return page, err
	}
	version := sha256.Sum256(catalogBytes)
	page.Version = hex.EncodeToString(version[:])
	bindingBytes, err := protocol.Encode(struct {
		Version        int    `json:"version"`
		Root           string `json:"root"`
		Scope          string `json:"scope"`
		Path           string `json:"path"`
		WorkspaceGuard string `json:"workspace_guard"`
		Provider       string `json:"provider"`
	}{1, r.command.Root, r.models.Selection.ScopeID, r.scoped.selection.RelativePath, protocol.WireContextGuard(r.scoped.scope.ExpectedWorkspace), r.models.Provider}, 16<<10)
	if err != nil {
		return page, err
	}
	binding := sha256.Sum256(bindingBytes)
	bindingDigest := hex.EncodeToString(binding[:])
	next := 0
	if r.models.Cursor != "" {
		cursor, cursorErr := protocol.DecodeModelCursor(r.models.Cursor, bindingDigest, page.Version)
		if cursorErr != nil || cursor.Next > len(catalog.Models) {
			return page, ErrConflict
		}
		next = cursor.Next
	}
	page.Models, page.EOF = protocol.PageModelFacts(catalog.Models, next, r.models.Limit)
	if !page.EOF {
		page.NextCursor, err = protocol.EncodeModelCursor(protocol.ModelCursor{Version: 1, BindingSHA256: bindingDigest, CatalogSHA256: page.Version, Next: next + len(page.Models)})
		if err != nil {
			return page, err
		}
	}
	if page.ValidateFor(*r.models) != nil {
		return page, ErrEvidence
	}
	return page, nil
}
