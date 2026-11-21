package mcpadapter

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type modelBackend struct {
	selectedMetadataBackend
	queries chan protocol.ModelQuery
	firstID string
}

func (b *modelBackend) ObserveModels(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.ModelQuery) (gateway.MetadataObservation[protocol.ModelPage], error) {
	value, err := b.ListModels(ctx, actor, device, request)
	return gateway.MetadataObservation[protocol.ModelPage]{Value: value, Source: testMetadataSource(device, protocol.ProviderModels)}, err
}

func (b *modelBackend) ListModels(_ context.Context, _ domain.Actor, _ domain.DeviceID, query protocol.ModelQuery) (protocol.ModelPage, error) {
	b.queries <- query
	start, count, cursor := 0, 100, strings.Repeat("m", 512)
	if query.Cursor != "" {
		start, count, cursor = 100, 45, ""
	}
	page := protocol.ModelPage{Provider: query.Provider, ObservedAt: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), Status: "available", ReasonCode: "models_available", Source: "native_cli", CatalogComplete: true, Version: strings.Repeat("a", 64), Models: []protocol.ModelFact{}, Efforts: []string{"low", "high"}, NextCursor: cursor, EOF: cursor == ""}
	for index := start; index < start+count; index++ {
		page.Models = append(page.Models, protocol.ModelFact{ID: fmt.Sprintf("native-model-%03d", index), Name: fmt.Sprintf("Native model %d", index), Efforts: []string{"low", "high"}, DefaultEffort: "high"})
	}
	if start == 0 && b.firstID != "" {
		page.Models[0].ID = b.firstID
	}
	return page, nil
}

func TestRegisteredModelsPreserveLongNativeIDsWithInteriorSpaces(t *testing.T) {
	id := "Native model with interior spaces " + strings.Repeat("m", 700)
	backend := &modelBackend{queries: make(chan protocol.ModelQuery, 1), firstID: id}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Workspaces = backend })
	backend.metadataRegistry = f.store
	device := ownedFilesystemDevice(t, f)
	input := ModelsInput{DeviceID: string(device), Selection: protocol.FileSelection{ScopeID: protocol.SharedTempScope, RelativePath: "."}, Provider: "codex:exec"}
	result := decodeResult[protocol.ModelPage](t, f.call(t, f.session(t, "dispatch"), "list_models", args(t, input)))
	if result.Error != nil || result.Data == nil || len(result.Data.Models) == 0 || result.Data.Models[0].ID != id {
		t.Fatalf("Native model metadata was filtered by MCP selection rules: %+v", result)
	}
}

func TestRegisteredModelsAreExplicitAdvisoryAndPaginatedBeyondOneHundred(t *testing.T) {
	backend := &modelBackend{selectedMetadataBackend: selectedMetadataBackend{requests: make(chan protocol.SelectionRequest, 1), providers: []protocol.NativeProviderCapability{{Provider: "codex:exec", SupportedModes: []string{"read-only"}, SupportedOptions: []string{"model"}, Continuation: "native-session", Authentication: "unknown"}}}, queries: make(chan protocol.ModelQuery, 4)}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Workspaces = backend })
	backend.metadataRegistry = f.store
	device := ownedFilesystemDevice(t, f)
	selection := protocol.FileSelection{ScopeID: protocol.SharedTempScope, RelativePath: "repo"}
	capabilities := decodeResult[Capabilities](t, f.call(t, f.session(t, "inventory"), "get_capabilities", args(t, CapabilitiesInput{DeviceID: string(device), Selection: &selection})))
	if capabilities.Error != nil || capabilities.Data == nil || len(backend.queries) != 0 {
		t.Fatal("get_capabilities probed models or failed")
	}
	input := ModelsInput{DeviceID: string(device), Selection: selection, Provider: "codex:exec", Limit: 100}
	expectError[protocol.ModelPage](t, f.call(t, f.session(t, "inventory"), "list_models", args(t, input)), "forbidden")
	if len(backend.queries) != 0 {
		t.Fatal("inventory-only token launched model discovery")
	}
	session := f.session(t, "alice")
	assertModelsCatalog(t, f)
	seen := []string{}
	for {
		result := decodeResult[protocol.ModelPage](t, f.call(t, session, "list_models", args(t, input)))
		if result.Error != nil || result.Data == nil {
			t.Fatalf("Native model page failed: %+v", result)
		}
		page := result.Data
		query := <-backend.queries
		if query != input.query() {
			t.Fatal("model selector/provider/cursor was changed")
		}
		for _, model := range page.Models {
			seen = append(seen, model.ID)
		}
		assertModelPageAdvice(t, *page)
		if page.EOF {
			break
		}
		input.Cursor = page.NextCursor
	}
	if len(seen) != 145 || seen[0] != "native-model-000" || seen[144] != "native-model-144" {
		t.Fatal("models beyond the first hundred were hidden or reordered")
	}
}

func assertModelsCatalog(t *testing.T, f *fixture) {
	t.Helper()
	listed, err := f.session(t, "alice").ListTools(t.Context(), nil)
	check(t, err)
	for _, tool := range listed.Tools {
		if tool.Name != "list_models" {
			continue
		}
		wire := sdkValue[toolWire](t, tool)
		assertClosed(t, wire.Input)
		assertClosed(t, wire.Output)
		assertToolHints(t, wire, toolExpectation{idempotent: true})
		assertToolOAuth(t, wire, []string{"task:dispatch"})
		if wire.Input.Properties["cursor"].MaxLength == nil || *wire.Input.Properties["cursor"].MaxLength != 2048 {
			t.Fatal("model cursor schema has the wrong wire bound")
		}
		return
	}
	t.Fatal("explicit model tool not registered")
}

func assertModelPageAdvice(t *testing.T, page protocol.ModelPage) {
	t.Helper()
	if page.Status != "available" || page.Source != "native_cli" || !page.CatalogComplete || len(page.Models) == 0 || page.Models[0].Name == "" || !reflect.DeepEqual(page.Models[0].Efforts, []string{"low", "high"}) || page.Models[0].DefaultEffort != "high" || !reflect.DeepEqual(page.Efforts, []string{"low", "high"}) {
		t.Fatal("Native model advice was flattened or replaced")
	}
}
