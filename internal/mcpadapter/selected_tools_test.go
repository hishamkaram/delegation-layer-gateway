package mcpadapter

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type selectedMetadataBackend struct {
	workspaceBackend
	requests  chan protocol.SelectionRequest
	providers []protocol.NativeProviderCapability
}

func (b *selectedMetadataBackend) ObserveSelection(ctx context.Context, actor domain.Actor, device domain.DeviceID, request protocol.SelectionRequest) (gateway.MetadataObservation[protocol.SelectionObservation], error) {
	value, err := b.InspectSelection(ctx, actor, device, request)
	return gateway.MetadataObservation[protocol.SelectionObservation]{Value: value, Source: testMetadataSource(device, protocol.SelectProject)}, err
}

func (b *selectedMetadataBackend) InspectSelection(_ context.Context, _ domain.Actor, _ domain.DeviceID, request protocol.SelectionRequest) (protocol.SelectionObservation, error) {
	b.requests <- request
	return protocol.SelectionObservation{Selection: request.Selection, Context: protocol.ContextBinding{Root: protocol.WireContextGuard("root"), Project: protocol.WireContextGuard("selected-directory")}, AdmissionOpen: true, AdmissionGeneration: "generation", Features: []string{protocol.FeatureNativeOptions, protocol.FeatureProjectHashGuard}, Providers: b.providers, ObservedAt: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}, nil
}

func TestSelectedCapabilitiesExposeAllNativeProviderAdviceWithoutExecutionCeilings(t *testing.T) {
	// These seven IDs match the Native production catalog. The reported fields
	// are independent fixture observations, not a Gateway execution allowlist.
	providers := []string{"antigravity:print", "codex:exec", "codex:review", "claude:print", "pi:json", "opencode:run", "ccr:print"}
	backend := &selectedMetadataBackend{requests: make(chan protocol.SelectionRequest, 4)}
	for _, id := range providers {
		backend.providers = append(backend.providers, protocol.NativeProviderCapability{Provider: id, SupportedModes: []string{"read-only", "future-native-mode"}, SupportedOptions: []string{"model", "effort", "review-target"}, RequiredOptions: []string{"review-target"}, Continuation: "native-session", Authentication: "unknown"})
	}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Workspaces = backend })
	backend.metadataRegistry = f.store
	device := ownedFilesystemDevice(t, f)
	selection := protocol.FileSelection{ScopeID: protocol.SharedTempScope, RelativePath: "repo:with\\name"}
	input := CapabilitiesInput{DeviceID: string(device), Selection: &selection}
	for _, token := range []string{"alice", "inventory"} {
		result := decodeResult[Capabilities](t, f.call(t, f.session(t, token), "get_capabilities", args(t, input)))
		if result.Error != nil || result.Data == nil || len(result.Data.Providers) != 7 || !reflect.DeepEqual(result.Data.Selection, &selection) {
			t.Fatalf("selected Native metadata lost: %+v", result)
		}
		for index, provider := range result.Data.Providers {
			assertNativeAdvice(t, provider, providers[index], token == "alice")
		}
		if (<-backend.requests).Selection != selection {
			t.Fatal("capabilities selection was retargeted")
		}
	}
}

func assertNativeAdvice(t *testing.T, provider Provider, id string, dispatch bool) {
	t.Helper()
	if provider.Provider != id || !reflect.DeepEqual(provider.SupportedModes, []string{"read-only", "future-native-mode"}) || !reflect.DeepEqual(provider.SupportedOptions, []string{"model", "effort", "review-target"}) || !reflect.DeepEqual(provider.RequiredOptions, []string{"review-target"}) || provider.Continuation != "native-session" || provider.MaxBudgetSeconds != 0 || provider.DispatchAllowed != dispatch {
		t.Fatalf("Native advice was filtered or gained Gateway policy: %+v", provider)
	}
}

type selectedPreparationBackend struct {
	Operations
	requests  chan gateway.SelectedPreparation
	failure   error
	after     func()
	operation string
}

func (b *selectedPreparationBackend) PrepareSelected(_ context.Context, _ domain.Actor, request gateway.SelectedPreparation) (domain.PreparedOperation, error) {
	b.requests <- request
	if b.after != nil {
		b.after()
	}
	operation := b.operation
	if operation == "" {
		operation = "prepared-operation"
	}
	return domain.PreparedOperation{Correlation: domain.Correlation{Operation: domain.OperationID(operation), Task: domain.TaskID(strings.Repeat("c", 32))}, ExpiresAt: time.Date(2026, 11, 21, 13, 0, 0, 0, time.UTC)}, b.failure
}

func selectedPreparationInput() PrepareInput {
	return PrepareInput{DeviceID: "device-one", RequestID: strings.Repeat("b", 32), Selection: &protocol.FileSelection{ScopeID: protocol.SharedTempScope, RelativePath: "new:repo"}, NativeOptions: &NativeOptionsInput{Provider: "codex:review"}, Brief: "requested Native task"}
}

func TestSelectedPreparationPreservesNativeOmissionsAndExplicitUnadvertisedOptions(t *testing.T) {
	backend := &selectedPreparationBackend{requests: make(chan gateway.SelectedPreparation, 4)}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { backend.Operations = options.Operations; options.Operations = backend })
	input := selectedPreparationInput()
	for _, explicit := range []bool{false, true} {
		if explicit {
			input.NativeOptions = &NativeOptionsInput{Provider: "future-native-provider", Model: pointer("not-in-cached-catalog"), Effort: pointer("future-effort"), Permission: "future-native-mode", Budget: "4h", ReviewTarget: "base:main", NativeTimeout: "3h", OutputSilenceTimeout: "2h"}
		}
		result := decodeResult[Prepared](t, f.call(t, f.session(t, "dispatch"), "prepare_dispatch", args(t, input)))
		if result.Error != nil || result.Data == nil || result.Data.OperationID != "prepared-operation" {
			t.Fatalf("Native options were vetoed by adapter policy: %+v", result)
		}
		request := <-backend.requests
		if string(request.RequestID) != input.RequestID || request.Selection != *input.Selection || request.Request.Brief != input.Brief {
			t.Fatal("selected preparation correlation or bytes changed")
		}
		if !reflect.DeepEqual(request.Request.Native, input.NativeOptions.options()) {
			t.Fatal("Native defaults or explicit choices were changed")
		}
		if !explicit && (request.Request.Native.Permission != "" || request.Request.Native.Budget != "" || request.Request.Native.Model.Kind != domain.NativeDefault || request.Request.Native.Effort.Kind != domain.NativeDefault) {
			t.Fatal("Gateway invented an omitted Native default")
		}
	}
}

func TestSelectedPreparationRejectsMixedLegacyFieldsIncludingExplicitZero(t *testing.T) {
	backend := &selectedPreparationBackend{requests: make(chan gateway.SelectedPreparation, 4)}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { backend.Operations = options.Operations; options.Operations = backend })
	session := f.session(t, "dispatch")
	input := selectedPreparationInput()
	for _, field := range []string{`"project_alias":"legacy"`, `"provider":""`, `"budget_seconds":0`, `"model":null`} {
		base := args(t, input)
		mixed := json.RawMessage(string(base[:len(base)-1]) + "," + field + "}")
		expectError[Prepared](t, f.call(t, session, "prepare_dispatch", mixed), "invalid_request")
	}
	if len(backend.requests) != 0 {
		t.Fatal("mixed selection modes reached preparation owner")
	}
}

func TestSelectedPreparationUncertaintyAndExpiryRetainTheSameRequestID(t *testing.T) {
	for _, boundary := range []string{"backend", "expiry"} {
		t.Run(boundary, func(t *testing.T) {
			var offset atomic.Int64
			backend := &selectedPreparationBackend{requests: make(chan gateway.SelectedPreparation, 1)}
			if boundary == "backend" {
				backend.failure = &gateway.RemoteError{Failure: protocol.Failure{Code: "admission_unknown", Retryable: true}}
			} else {
				backend.after = func() { offset.Store(int64(25 * time.Hour)) }
			}
			f := newConfiguredFixture(t, 0, nil, func(options *Options) {
				backend.Operations = options.Operations
				options.Operations = backend
				options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
			})
			input := selectedPreparationInput()
			result := decodeResult[Prepared](t, f.call(t, f.session(t, "dispatch"), "prepare_dispatch", args(t, input)))
			if result.Error == nil || result.Error.RequestID != input.RequestID || !result.Error.Retryable || result.Data != nil {
				t.Fatalf("uncertainty lost stable request identity: %+v", result)
			}
			if len(backend.requests) != 1 {
				t.Fatal("uncertain preparation was retried or never reached owner")
			}
		})
	}
}

func TestSelectedPreparationEncodingFailureRetainsRequestIdentity(t *testing.T) {
	backend := &selectedPreparationBackend{requests: make(chan gateway.SelectedPreparation, 1), operation: strings.Repeat(privateCanary, 1<<15)}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { backend.Operations = options.Operations; options.Operations = backend })
	input := selectedPreparationInput()
	result := f.call(t, f.session(t, "dispatch"), "prepare_dispatch", args(t, input))
	expectError[Prepared](t, result, "evidence_invalid")
	if decodeResult[Prepared](t, result).Error.RequestID != input.RequestID {
		t.Fatal("encoding failure discarded same-request recovery identity")
	}
	assertPublic(t, result)
}

func TestLegacyPreparationPreservesLongNativeLiteralSelections(t *testing.T) {
	f := newFixture(t, 1)
	input := prepareFixture("Native owns literal selection semantics")
	model := "Native model with interior spaces " + strings.Repeat("m", 700)
	effort := "Native effort with interior spaces " + strings.Repeat("e", 700)
	input.Model, input.Effort = &model, &effort
	result := decodeResult[Prepared](t, f.call(t, f.session(t, "dispatch"), "prepare_dispatch", args(t, input)))
	if result.Error != nil || result.Data == nil || result.Data.OperationID == "" {
		t.Fatalf("MCP imposed its own Native literal restriction: %+v", result)
	}
	if len(f.link.commands) != 0 {
		t.Fatal("literal preparation dispatched a task")
	}
}
