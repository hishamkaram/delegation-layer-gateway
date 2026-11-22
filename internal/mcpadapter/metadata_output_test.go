package mcpadapter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// The checker is an explicit consumer-boundary fake. Real transport, root and
// credential rechecks are independently covered by the workspace service tests.
type metadataOutputBackend struct {
	*filesystemBackend
	*modelBackend
	current  atomic.Uint64
	checks   atomic.Int32
	onCheck  func()
	registry Registry
}

type metadataEndpointGate struct {
	Registry
	armed    atomic.Bool
	calls    atomic.Int32
	skip     int32
	entered  chan struct{}
	released chan struct{}
	once     sync.Once
}

func (g *metadataEndpointGate) AuthorizeOwnedDevice(ctx context.Context, input domain.OwnedDeviceRequest) (domain.OwnedDeviceAuthorization, error) {
	value, err := g.Registry.AuthorizeOwnedDevice(ctx, input)
	if input.Scope == domain.InventoryRead && g.armed.Load() {
		if g.calls.Add(1) <= g.skip {
			return value, err
		}
		g.once.Do(func() { close(g.entered) })
		select {
		case <-g.released:
		case <-ctx.Done():
			return domain.OwnedDeviceAuthorization{}, ctx.Err()
		}
	}
	return value, err
}

func TestMetadataOutputRejectsGenerationChangeDuringEndpointScopeCheck(t *testing.T) {
	for _, tool := range []string{"get_capabilities", "list_workspaces"} {
		t.Run(tool, func(t *testing.T) {
			recorder := &handoffRecorder{entered: make(chan struct{}), unblock: make(chan struct{})}
			endpoint := &metadataEndpointGate{entered: make(chan struct{}), released: make(chan struct{})}
			if tool == "list_workspaces" {
				// Inventory input authority runs before the output source check.
				// Gate the latter's endpoint scope, where the split-check bug lived.
				endpoint.skip = 1
			}
			var recorderOnce, endpointOnce sync.Once
			releaseRecorder := func() { recorderOnce.Do(func() { close(recorder.unblock) }) }
			releaseEndpoint := func() { endpointOnce.Do(func() { close(endpoint.released) }) }
			backend := newMetadataOutputBackend("metadata-output-canary")
			f := newConfiguredFixture(t, 0, recorder, func(options *Options) {
				endpoint.Registry, options.Registry = options.Registry, endpoint
				options.Workspaces = backend
			})
			backend.registry = endpoint
			device := ownedFilesystemDevice(t, f)
			input := metadataOutputInput(t, tool, device, protocol.FileSelection{ScopeID: protocol.SharedTempScope})
			results := beginBoundaryToolCall(t, f, f.session(t, "alice"), tool, input)
			t.Cleanup(func() { releaseRecorder(); releaseEndpoint() })
			awaitBoundaryGate(t, recorder.entered, results)
			endpoint.armed.Store(true)
			releaseRecorder()
			awaitBoundaryGate(t, endpoint.entered, results)
			backend.current.Store(2)
			releaseEndpoint()
			result := <-results
			check(t, result.err)
			assertMetadataAbsent(t, result.result, "metadata-output-canary")
			expectError[json.RawMessage](t, result.result, "conflict")
		})
	}
}

func (b *metadataOutputBackend) CheckMetadataObservation(ctx context.Context, actor domain.Actor, source gateway.MetadataSource, additional domain.ScopeSet) error {
	b.checks.Add(1)
	if source.Validate() != nil {
		return domain.Reject(domain.EvidenceInvalid)
	}
	if err := checkTestMetadataScopes(ctx, b.registry, actor, source, additional); err != nil {
		return err
	}
	if source.Binding.Connection.Counter != b.current.Load() {
		return domain.Reject(domain.Conflict)
	}
	if b.onCheck != nil {
		b.onCheck()
	}
	return ctx.Err()
}

func (b *metadataOutputBackend) ObserveWorkspaces(_ context.Context, _ domain.Actor, device domain.DeviceID) (workspaces.InventoryObservation, error) {
	source := testMetadataSource(device, protocol.FilesystemScopes)
	return workspaces.InventoryObservation{Value: workspaces.Inventory{Device: device, Online: true, Scopes: []protocol.FilesystemScope{{ID: protocol.SharedTempScope, Kind: "shared_temp", Name: "metadata-output-canary"}}, Workspaces: []protocol.WorkspaceCapability{}}, Source: &source}, nil
}

func newMetadataOutputBackend(marker string) *metadataOutputBackend {
	backend := &metadataOutputBackend{
		filesystemBackend: &filesystemBackend{calls: make(chan filesystemCall, 1), read: func(context.Context, filesystemCall) (protocol.FilesystemResponse, error) {
			return fileResponse([]byte(marker), pointer(marker)), nil
		}},
		modelBackend: &modelBackend{selectedMetadataBackend: selectedMetadataBackend{requests: make(chan protocol.SelectionRequest, 1), providers: []protocol.NativeProviderCapability{{Provider: marker, Authentication: "unknown"}}}, queries: make(chan protocol.ModelQuery, 1), firstID: marker},
	}
	backend.current.Store(1)
	return backend
}

func TestMetadataOutputsRecheckOriginalSourceAfterRecorder(t *testing.T) {
	for _, tool := range []string{"read_file", "list_models", "get_capabilities", "list_workspaces"} {
		t.Run(tool, func(t *testing.T) { metadataOutputRevocation(t, tool) })
	}
}

func metadataOutputRevocation(t *testing.T, tool string) {
	t.Helper()
	const marker = "metadata-output-canary"
	gate := &handoffRecorder{entered: make(chan struct{}), unblock: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(gate.unblock) }) }
	backend := newMetadataOutputBackend(marker)
	f := newConfiguredFixture(t, 0, gate, func(options *Options) { options.Filesystem, options.Workspaces = backend, backend })
	backend.registry = f.store
	device := ownedFilesystemDevice(t, f)
	selection := protocol.FileSelection{ScopeID: protocol.SharedTempScope}
	input := metadataOutputInput(t, tool, device, selection)
	results := beginBoundaryToolCall(t, f, f.session(t, "alice"), tool, input)
	t.Cleanup(release)
	awaitBoundaryGate(t, gate.entered, results)
	if backend.checks.Load() == 0 {
		t.Fatal("successful metadata reached encoding without checking its source")
	}
	backend.current.Store(2)
	release()
	result := <-results
	check(t, result.err)
	assertMetadataAbsent(t, result.result, marker)
	expectError[json.RawMessage](t, result.result, "conflict")
	if backend.checks.Load() < 2 {
		t.Fatal("metadata source was not rechecked after the recorder")
	}
}

func TestMetadataOutputRechecksExpiryAfterFinalSourceCheck(t *testing.T) {
	const marker = "metadata-output-canary"
	gate := &handoffRecorder{entered: make(chan struct{}), unblock: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(gate.unblock) }) }
	var offset atomic.Int64
	var afterRecorder atomic.Bool
	var crossedExpiry atomic.Bool
	backend := newMetadataOutputBackend(marker)
	backend.onCheck = func() {
		if afterRecorder.Load() {
			offset.Store(int64(25 * time.Hour))
			crossedExpiry.Store(true)
		}
	}
	f := newConfiguredFixture(t, 0, gate, func(options *Options) {
		options.Filesystem = backend
		options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	})
	device := ownedFilesystemDevice(t, f)
	input := args(t, FileReadInput{DeviceID: string(device), ScopeID: protocol.SharedTempScope})
	results := beginBoundaryToolCall(t, f, f.session(t, "alice"), "read_file", input)
	t.Cleanup(release)
	awaitBoundaryGate(t, gate.entered, results)
	afterRecorder.Store(true)
	release()
	result := <-results
	check(t, result.err)
	if !crossedExpiry.Load() || backend.current.Load() != 1 {
		t.Fatal("fixture did not cross expiry from an otherwise valid final source check")
	}
	assertMetadataAbsent(t, result.result, marker)
	expectError[json.RawMessage](t, result.result, "unauthenticated")
	metadata := sdkValue[map[string]json.RawMessage](t, result.result.Meta)
	var challenges []string
	check(t, json.Unmarshal(metadata["mcp/www_authenticate"], &challenges))
	if len(challenges) != 1 || !strings.Contains(challenges[0], "invalid_token") {
		t.Fatal("expired output did not require token reacquisition")
	}
}

func TestMetadataOutputsRetainEndpointInventoryScopeAfterRecorder(t *testing.T) {
	for _, tool := range []string{"get_capabilities", "list_workspaces"} {
		t.Run(tool, func(t *testing.T) {
			const marker = "metadata-output-canary"
			gate := &handoffRecorder{entered: make(chan struct{}), unblock: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(gate.unblock) }) }
			backend := newMetadataOutputBackend(marker)
			f := newConfiguredFixture(t, 0, gate, func(options *Options) { options.Workspaces = backend })
			backend.registry = f.store
			device := ownedFilesystemDevice(t, f)
			input := metadataOutputInput(t, tool, device, protocol.FileSelection{ScopeID: protocol.SharedTempScope})
			results := beginBoundaryToolCall(t, f, f.session(t, "alice"), tool, input)
			t.Cleanup(release)
			awaitBoundaryGate(t, gate.entered, results)
			policy := domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, MaxDevices: 1}
			check(t, f.store.PutOwnerPolicy(t.Context(), f.alice.Principal, policy))
			for _, scope := range policy.Scopes {
				_, err := f.store.AuthorizeOwnedDevice(t.Context(), domain.OwnedDeviceRequest{Actor: f.alice, Device: device, Scope: scope})
				check(t, err)
			}
			release()
			result := <-results
			check(t, result.err)
			assertMetadataAbsent(t, result.result, marker)
			expectError[json.RawMessage](t, result.result, "not_found")
		})
	}
}

func TestWorkspaceOnlyFallbackRechecksInventoryScopeAfterRecorder(t *testing.T) {
	const marker = "metadata-output-canary"
	gate := &handoffRecorder{entered: make(chan struct{}), unblock: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(gate.unblock) }) }
	backend := &scopeInventoryBackend{scopes: []protocol.FilesystemScope{{ID: "workspace", Kind: "workspace", Name: marker}}, discoveryError: "resource_limit"}
	f := newConfiguredFixture(t, 0, gate, func(options *Options) { options.Workspaces = backend })
	device := ownedFilesystemDevice(t, f)
	results := beginBoundaryToolCall(t, f, f.session(t, "alice"), "list_workspaces", args(t, WorkspacesInput{DeviceID: string(device)}))
	t.Cleanup(release)
	awaitBoundaryGate(t, gate.entered, results)
	policy := domain.OwnerPolicy{Enabled: true, Scopes: domain.ScopeSet{domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}, MaxDevices: 1}
	check(t, f.store.PutOwnerPolicy(t.Context(), f.alice.Principal, policy))
	release()
	result := <-results
	check(t, result.err)
	assertMetadataAbsent(t, result.result, marker)
	expectError[json.RawMessage](t, result.result, "not_found")
}

type unstampedMetadataBackend struct{ *metadataOutputBackend }

func (b unstampedMetadataBackend) ObserveFilesystem(ctx context.Context, actor domain.Actor, device domain.DeviceID, operation protocol.Operation, request protocol.FilesystemRequest) (gateway.MetadataObservation[protocol.FilesystemResponse], error) {
	result, err := b.filesystemBackend.ObserveFilesystem(ctx, actor, device, operation, request)
	result.Source = gateway.MetadataSource{}
	return result, err
}

func (b unstampedMetadataBackend) ObserveModels(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.ModelQuery) (gateway.MetadataObservation[protocol.ModelPage], error) {
	result, err := b.modelBackend.ObserveModels(ctx, actor, device, request)
	result.Source = gateway.MetadataSource{}
	return result, err
}

func (b unstampedMetadataBackend) ObserveSelection(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.SelectionRequest) (gateway.MetadataObservation[protocol.SelectionObservation], error) {
	result, err := b.modelBackend.ObserveSelection(ctx, actor, device, request)
	result.Source = gateway.MetadataSource{}
	return result, err
}

func (b unstampedMetadataBackend) ObserveWorkspaces(ctx context.Context, actor domain.Actor, device domain.DeviceID) (workspaces.InventoryObservation, error) {
	result, err := b.metadataOutputBackend.ObserveWorkspaces(ctx, actor, device)
	result.Source = nil
	return result, err
}

func TestMetadataOutputsRequireOriginalSource(t *testing.T) {
	for _, tool := range []string{"read_file", "list_models", "get_capabilities", "list_workspaces"} {
		t.Run(tool, func(t *testing.T) {
			backend := unstampedMetadataBackend{newMetadataOutputBackend("metadata-output-canary")}
			f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Filesystem, options.Workspaces = backend, backend })
			device := ownedFilesystemDevice(t, f)
			input := metadataOutputInput(t, tool, device, protocol.FileSelection{ScopeID: protocol.SharedTempScope})
			result := f.call(t, f.session(t, "alice"), tool, input)
			assertMetadataAbsent(t, result, "metadata-output-canary")
			expectError[json.RawMessage](t, result, "evidence_invalid")
		})
	}
}

func metadataOutputInput(t *testing.T, tool string, device domain.DeviceID, selection protocol.FileSelection) json.RawMessage {
	t.Helper()
	switch tool {
	case "read_file":
		return args(t, FileReadInput{DeviceID: string(device), ScopeID: selection.ScopeID})
	case "list_models":
		return args(t, ModelsInput{DeviceID: string(device), Selection: selection, Provider: "provider"})
	case "get_capabilities":
		return args(t, CapabilitiesInput{DeviceID: string(device), Selection: &selection})
	case "list_workspaces":
		return args(t, WorkspacesInput{DeviceID: string(device)})
	default:
		t.Fatal("unknown metadata fixture tool")
		return nil
	}
}

func assertMetadataAbsent(t *testing.T, result *mcp.CallToolResult, marker string) {
	t.Helper()
	structured, err := json.Marshal(result.StructuredContent)
	check(t, err)
	for _, value := range []string{marker, base64.StdEncoding.EncodeToString([]byte(marker))} {
		if strings.Contains(string(structured), value) {
			t.Fatal("stale requested data escaped in structured output")
		}
		for _, content := range result.Content {
			text, ok := content.(*mcp.TextContent)
			if ok && strings.Contains(text.Text, value) {
				t.Fatal("stale requested data escaped in text output")
			}
		}
	}
}

func TestMetadataOutputStampsPreservePublicJSONAndSchemas(t *testing.T) {
	source := testMetadataSource("fixture-device", protocol.ReadFile)
	file := fileResponse([]byte{0, 0xff, 1}, nil)
	assertMetadataWire[filesystemOutput, protocol.FilesystemResponse](t, filesystemOutput{FilesystemResponse: file, source: source}, file)
	page := protocol.ModelPage{Provider: "provider", Models: []protocol.ModelFact{}, Efforts: []string{}}
	assertMetadataWire[modelsOutput, protocol.ModelPage](t, modelsOutput{ModelPage: page, source: source}, page)
	capabilities := Capabilities{DeviceID: "fixture-device", Providers: []Provider{}}
	stamped := capabilities
	stamped.metadataSource = &source
	assertMetadataWire[Capabilities, Capabilities](t, stamped, capabilities)
	inventory := WorkspaceInventory{DeviceID: "fixture-device", Workspaces: []protocol.WorkspaceCapability{}, Scopes: []protocol.FilesystemScope{}}
	stampedInventory := inventory
	stampedInventory.metadataSource = &source
	assertMetadataWire[WorkspaceInventory, WorkspaceInventory](t, stampedInventory, inventory)
}

func assertMetadataWire[Out, Wire any](t *testing.T, output Out, wire Wire) {
	t.Helper()
	got, err := json.Marshal(Envelope[Out]{Data: &output})
	check(t, err)
	want, err := json.Marshal(Envelope[Wire]{Data: &wire})
	check(t, err)
	if string(got) != string(want) {
		t.Fatal("private metadata source changed public JSON")
	}
	outputSchema, err := jsonschema.For[Envelope[Out]](nil)
	check(t, err)
	wireSchema, err := jsonschema.For[Envelope[Wire]](nil)
	check(t, err)
	if !reflect.DeepEqual(outputSchema, wireSchema) {
		t.Fatal("private metadata source changed public schema")
	}
}
