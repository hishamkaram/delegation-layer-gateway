package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// This consumer fixture proves MCP mapping and response gates, not Native
// continuation admission, provider session ownership or durable replay.
type continuationBackend struct {
	Operations
	requests  chan gateway.ContinuationPreparation
	actors    chan domain.Actor
	failure   error
	operation string
}

func (b *continuationBackend) PrepareContinuation(_ context.Context, actor domain.Actor, input gateway.ContinuationPreparation) (domain.PreparedOperation, error) {
	b.requests <- input
	if b.actors != nil {
		b.actors <- actor
	}
	operation := b.operation
	if operation == "" {
		operation = "successor-operation"
	}
	return domain.PreparedOperation{Correlation: domain.Correlation{Operation: domain.OperationID(operation), Task: domain.TaskID(strings.Repeat("c", 32))}, ExpiresAt: time.Date(2026, 11, 21, 13, 0, 0, 0, time.UTC)}, b.failure
}

func continuationArguments(extra string) json.RawMessage {
	return json.RawMessage(`{"device_id":"device-one","predecessor_operation_id":"saved-predecessor","request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"` + extra + `}`)
}

func TestContinuationToolAdvertisesClosedDispatchOnlyPreparation(t *testing.T) {
	f := newFixture(t, 0)
	session := f.session(t, "dispatch")
	listed, err := session.ListTools(t.Context(), nil)
	check(t, err)
	for _, tool := range listed.Tools {
		if tool.Name != "prepare_continuation" {
			continue
		}
		wire := sdkValue[toolWire](t, tool)
		assertClosed(t, wire.Input)
		assertClosed(t, wire.Output)
		assertToolHints(t, wire, toolExpectation{false, false, true, []string{"task:dispatch"}})
		assertToolOAuth(t, wire, []string{"task:dispatch"})
		for _, field := range []string{"device_id", "predecessor_operation_id", "request_id", "selection", "brief", "overrides"} {
			if _, ok := wire.Input.Properties[field]; !ok {
				t.Fatalf("continuation input omitted %s", field)
			}
		}
		if len(wire.Input.Properties) != 6 {
			t.Fatal("continuation input gained an unsupported execution or authority field")
		}
		if !strings.Contains(tool.Description, "dispatch_task") || !strings.Contains(session.InitializeResult().Instructions, "prepare_continuation") {
			t.Fatal("follow-up instructions omitted preparation and confirmation")
		}
		return
	}
	t.Fatal("prepare_continuation is absent from the public MCP catalog")
}

func TestContinuationPreparationForwardsInheritedAndExplicitIntentWithoutDispatch(t *testing.T) {
	backend := &continuationBackend{requests: make(chan gateway.ContinuationPreparation, 2), actors: make(chan domain.Actor, 2)}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { backend.Operations = options.Operations; options.Operations = backend })
	session := f.session(t, "dispatch")
	for _, explicit := range []bool{false, true} {
		extra := ""
		want := gateway.ContinuationPreparation{RequestID: domain.RequestID(strings.Repeat("b", 32)), Device: "device-one", Predecessor: "saved-predecessor", Overrides: domain.ContinuationOverrides{Version: 1}}
		if explicit {
			extra = `,"selection":{"scope_id":"automatic-temp","relative_path":"repo:with\\name"},"brief":"exact new\nbrief <>&","overrides":{"budget":"4h","model":"future model with spaces","effort":"future effort","output_silence_timeout":"0"}`
			want.Selection = &protocol.FileSelection{ScopeID: "automatic-temp", RelativePath: `repo:with\name`}
			want.Brief = pointer("exact new\nbrief <>&")
			want.Overrides = domain.ContinuationOverrides{Version: 1, Budget: "4h", Model: "future model with spaces", Effort: "future effort", OutputSilenceTimeout: "0"}
		}
		result := decodeResult[Prepared](t, f.call(t, session, "prepare_continuation", continuationArguments(extra)))
		if result.Error != nil || result.Data == nil || result.Data.OperationID != "successor-operation" || result.Data.TaskID != strings.Repeat("c", 32) || result.Data.ExpiresAt.IsZero() {
			t.Fatalf("continuation was not prepared: %+v", result)
		}
		if got := <-backend.requests; !reflect.DeepEqual(got, want) {
			t.Fatalf("continuation intent changed: got %+v, want %+v", got, want)
		}
		if actor := <-backend.actors; !reflect.DeepEqual(actor.Scopes, domain.ScopeSet{domain.TaskDispatch}) {
			t.Fatal("preparation acquired read authority")
		}
	}
	if len(f.link.commands) != 0 {
		t.Fatal("preparing a follow-up dispatched or read Native work")
	}
}

func TestContinuationPreparationRejectsMalformedOrForbiddenInputsBeforeOwner(t *testing.T) {
	backend := &continuationBackend{requests: make(chan gateway.ContinuationPreparation, 1)}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { backend.Operations = options.Operations; options.Operations = backend })
	session := f.session(t, "dispatch")
	invalid := []json.RawMessage{
		json.RawMessage(`{"predecessor_operation_id":"saved-predecessor","request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`),
		json.RawMessage(`{"device_id":"device-one","request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`),
		json.RawMessage(`{"device_id":"device-one","predecessor_operation_id":"saved-predecessor"}`),
		continuationArguments(`,"request_id":"new-request"`),
		json.RawMessage(strings.Replace(string(continuationArguments("")), `"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`, `"not-a-stable-request"`, 1)),
		json.RawMessage(strings.Replace(string(continuationArguments("")), `"saved-predecessor"`, `"not/a/handle"`, 1)),
		json.RawMessage(strings.Replace(string(continuationArguments("")), `"device-one"`, `"not:a:device"`, 1)),
		continuationArguments(`,"brief":""`),
		continuationArguments(`,"brief":null`),
		continuationArguments(`,"selection":null`),
		continuationArguments(`,"selection":{"scope_id":"automatic-temp","relative_path":"../escape"}`),
		continuationArguments(`,"selection":{"scope_id":"automatic-temp","relative_path_base64":"Lg"}`),
		continuationArguments(`,"overrides":null`),
		continuationArguments(`,"overrides":{"model":null}`),
		continuationArguments(`,"overrides":{"model":"nul\u0000model"}`),
	}
	for _, field := range []string{"provider", "permission", "cwd", "review_target", "native_timeout", "project_alias", "operation_id"} {
		invalid = append(invalid, continuationArguments(`,"`+field+`":"forbidden"`))
		invalid = append(invalid, continuationArguments(`,"overrides":{"`+field+`":""}`))
	}
	for _, input := range invalid {
		result := f.call(t, session, "prepare_continuation", input)
		envelope := decodeResult[Prepared](t, result)
		if envelope.Error == nil || envelope.Error.Code != "invalid_request" || envelope.Data != nil {
			t.Fatalf("invalid continuation input %s was accepted: %+v", input, envelope)
		}
		if envelope.Error.RequestID != "" {
			t.Fatal("invalid input acquired request recovery authority")
		}
	}
	if len(backend.requests) != 0 {
		t.Fatal("invalid continuation reached the preparation owner")
	}
}

func TestContinuationPreparationRequiresDispatchScopeWithoutReadingResults(t *testing.T) {
	backend := &continuationBackend{requests: make(chan gateway.ContinuationPreparation, 1)}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { backend.Operations = options.Operations; options.Operations = backend })
	for _, token := range []string{"inventory", "read"} {
		result := f.call(t, f.session(t, token), "prepare_continuation", continuationArguments(""))
		expectError[Prepared](t, result, "forbidden")
		wire := sdkValue[resultWire](t, result)
		if len(wire.Meta.Challenges) != 1 || !strings.Contains(wire.Meta.Challenges[0], `scope="task:dispatch"`) {
			t.Fatal("continuation scope challenge changed")
		}
	}
	if len(backend.requests) != 0 {
		t.Fatal("read-only token reached continuation preparation")
	}
}

type continuationFinalRecorder struct{ offset *atomic.Int64 }

func (r continuationFinalRecorder) Record(event observability.Event) {
	if event.Code == observability.MCPToolResponseReady {
		r.offset.Store(int64(25 * time.Hour))
	}
}

func TestContinuationPreparationUncertaintyRetainsIdentityAndNeverRetries(t *testing.T) {
	for _, boundary := range []string{"owner", "private-error", "final-expiry", "encoding"} {
		t.Run(boundary, func(t *testing.T) {
			backend := &continuationBackend{requests: make(chan gateway.ContinuationPreparation, 1)}
			var offset atomic.Int64
			var recorder Recorder
			wantCode := "admission_unknown"
			switch boundary {
			case "owner":
				backend.failure = &gateway.RemoteError{Failure: protocol.Failure{Code: wantCode, Retryable: true}}
			case "private-error":
				backend.failure = errors.New(privateCanary)
				wantCode = "internal_error"
			case "final-expiry":
				recorder = continuationFinalRecorder{&offset}
				wantCode = "unauthenticated"
			case "encoding":
				backend.operation = strings.Repeat(privateCanary, 1<<15)
				wantCode = "evidence_invalid"
			}
			f := newConfiguredFixture(t, 0, recorder, func(options *Options) {
				backend.Operations = options.Operations
				options.Operations = backend
				options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
			})
			result := f.call(t, f.session(t, "dispatch"), "prepare_continuation", continuationArguments(""))
			expectError[Prepared](t, result, wantCode)
			failure := decodeResult[Prepared](t, result).Error
			if failure.RequestID != strings.Repeat("b", 32) || len(backend.requests) != 1 {
				t.Fatal("uncertainty discarded the same-request identity or retried preparation")
			}
			if (boundary == "owner" || boundary == "final-expiry") && !failure.Retryable {
				t.Fatal("same-request recovery was forbidden after uncertainty")
			}
			if boundary == "final-expiry" {
				assertContinuationReacquisitionChallenge(t, sdkValue[resultWire](t, result))
			}
			assertPublic(t, result)
		})
	}
}

func assertContinuationReacquisitionChallenge(t *testing.T, wire resultWire) {
	t.Helper()
	if len(wire.Meta.Challenges) != 1 || !strings.Contains(wire.Meta.Challenges[0], `error="invalid_token"`) {
		t.Fatal("expired preparation omitted reacquisition challenge")
	}
}

func TestContinuationPreparationRepeatedRequestForwardsSameIdentity(t *testing.T) {
	backend := &continuationBackend{requests: make(chan gateway.ContinuationPreparation, 2)}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { backend.Operations = options.Operations; options.Operations = backend })
	session := f.session(t, "dispatch")
	input := continuationArguments(`,"overrides":{"output_silence_timeout":"0"}`)
	for range 2 {
		result := decodeResult[Prepared](t, f.call(t, session, "prepare_continuation", input))
		if result.Error != nil || result.Data == nil || result.Data.OperationID != "successor-operation" {
			t.Fatal("explicit same-request retry did not preserve its prepared handle")
		}
	}
	first, second := <-backend.requests, <-backend.requests
	if !reflect.DeepEqual(first, second) || first.RequestID != domain.RequestID(strings.Repeat("b", 32)) {
		t.Fatal("MCP replaced the stable continuation identity on retry")
	}
}

// Hiding the optional capability must fail explicitly, never downgrade to
// prepare_dispatch or launch a replacement task.
type withoutContinuation struct{ Operations }

func TestContinuationPreparationMissingCapabilityFailsExplicitly(t *testing.T) {
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Operations = withoutContinuation{options.Operations} })
	result := f.call(t, f.session(t, "dispatch"), "prepare_continuation", continuationArguments(""))
	expectError[Prepared](t, result, "unsupported_feature")
	if len(f.link.commands) != 0 {
		t.Fatal("unsupported continuation fell back to Native execution")
	}
}
