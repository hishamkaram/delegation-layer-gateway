package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type securityScheme struct {
	Type   string   `json:"type"`
	Scopes []string `json:"scopes"`
}

type toolHints struct {
	ReadOnly    bool
	Idempotent  bool
	Destructive bool
}

func register[In, Out any](a *Adapter, name, description string, scopes []domain.Scope, hints toolHints, handler func(context.Context, domain.Actor, In) (Out, error)) error {
	input, err := jsonschema.For[In](nil)
	if err != nil {
		return fmt.Errorf("build tool input: %w", err)
	}
	constrainInput(input)
	inValidator, err := input.Resolve(nil)
	if err != nil {
		return fmt.Errorf("resolve tool input: %w", err)
	}
	output, err := jsonschema.For[Envelope[Out]](nil)
	if err != nil {
		return fmt.Errorf("build tool output: %w", err)
	}
	output.OneOf = []*jsonschema.Schema{{Required: []string{"data"}, Not: &jsonschema.Schema{Required: []string{"error"}}}, {Required: []string{"error"}, Not: &jsonschema.Schema{Required: []string{"data"}}}}
	outValidator, err := output.Resolve(nil)
	if err != nil {
		return fmt.Errorf("resolve tool output: %w", err)
	}
	schemes := make([]securityScheme, 0, len(scopes))
	for _, scope := range scopes {
		schemes = append(schemes, securityScheme{Type: "oauth2", Scopes: []string{string(scope)}})
	}
	// SDK metadata is an extension map. Its values here are fixed typed OAuth
	// declarations, never user-controlled maps or authentication authority.
	tool := &mcp.Tool{Name: name, Description: description, InputSchema: input, OutputSchema: output, Meta: mcp.Meta{"securitySchemes": schemes}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: hints.ReadOnly, IdempotentHint: hints.Idempotent, DestructiveHint: &hints.Destructive}}
	a.server.AddTool(tool, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		started := time.Now()
		actor, failure, challenge := a.actor(request, scopes)
		if failure != nil {
			a.recordToolRejection(actor, name, failure.Code, time.Since(started))
			return recordedToolResult(a, actor, outValidator, Envelope[Out]{Error: failure}, challenge), nil
		}
		ctx, cancel := context.WithTimeout(ctx, a.options.Timeout)
		defer cancel()
		// The token is valid only through its verified expiry. Cancellation ends
		// observation; it never proves that a possibly sent task was not admitted.
		expires := request.Extra.TokenInfo.Expiration
		ctx, cancelExpiry := context.WithDeadline(ctx, expires)
		defer cancelExpiry()
		var args In
		raw := request.Params.Arguments
		if len(raw) == 0 {
			raw = json.RawMessage(`{}`)
		}
		if protocol.DecodeStrict(raw, &args, 1<<20) != nil || !validJSON(inValidator, raw) {
			a.recordToolRejection(actor, name, "invalid_request", time.Since(started))
			return recordedToolResult(a, actor, outValidator, Envelope[Out]{Error: &ToolError{Code: "invalid_request"}}, ""), nil
		}
		value, callErr := handler(ctx, actor, args)
		if failure, challenge = a.postHandlerFailure(ctx, expires, scopes); failure != nil {
			a.recordToolRejection(actor, name, failure.Code, time.Since(started))
			return recordedToolResult(a, actor, outValidator, Envelope[Out]{Error: retainInputFailure(args, failure)}, challenge), nil
		}
		if callErr != nil {
			a.recordInventoryFailure(actor, name, callErr)
			return recordedToolResult(a, actor, outValidator, Envelope[Out]{Error: inputFailure(args, callErr)}, ""), nil
		}
		result := recordedToolResult(a, actor, outValidator, Envelope[Out]{Data: &value}, "")
		// Encoding, schema validation and synchronous metadata sinks can take
		// time. Gate the complete text+structured result immediately before
		// handing it to the SDK; network delivery is outside this local gate.
		if failure, challenge = a.postHandlerFailure(ctx, expires, scopes); failure != nil {
			a.recordToolRejection(actor, name, failure.Code, time.Since(started))
			return recordedToolResult(a, actor, outValidator, Envelope[Out]{Error: retainInputFailure(args, failure)}, challenge), nil
		}
		return result, nil
	})
	return nil
}

func (a *Adapter) postHandlerFailure(ctx context.Context, expires time.Time, scopes []domain.Scope) (*ToolError, string) {
	if !a.options.Now().Before(expires) {
		// A completed handler may already have sent work. Reauthenticate and
		// resolve/retry its retained identity; this never authorizes replacement.
		return &ToolError{Code: "unauthenticated", Retryable: true}, a.challenge("invalid_token", "Access token expired; reauthenticate and resolve or retry the same retained identity", scopes)
	}
	if err := ctx.Err(); err != nil {
		return classify(err), ""
	}
	return nil, ""
}

// These inventory handlers return Registry/readiness decisions directly. Task
// controls have Gateway-owned observations and must not be recorded twice here.
func (a *Adapter) recordInventoryFailure(actor domain.Actor, name string, err error) {
	switch name {
	case "list_devices", "list_projects", "get_capabilities", "list_operations", "list_workspaces":
		if a.options.Recorder != nil && gateway.AuthorizationObservation(err) == routing.DeniedOrMissing {
			a.options.Recorder.Record(observability.Event{Code: observability.AuthorizationDenied, Principal: actor.Principal})
		}
	}
}

func (a *Adapter) recordToolRejection(actor domain.Actor, name, code string, elapsed time.Duration) {
	if a.options.Recorder == nil {
		return
	}
	event := observability.Event{Principal: actor.Principal}
	decision := routing.DeniedOrMissing
	switch code {
	case "forbidden":
		event.Code = observability.AuthorizationDenied
	case "unauthenticated":
		a.options.Recorder.Record(observability.Event{Code: observability.AuthenticationDenied})
		return
	case "invalid_request":
		event.Code = observability.ControlUnknown
		decision = routing.NotEvaluated // Destination/grant authorization never ran.
	default:
		return
	}
	class := observedToolClass(name)
	if class != "" && actor.Principal != "" {
		event.Control = routing.ControlMetadata{Class: class, Actor: routing.PrincipalActor, Authorization: decision, Recheck: routing.NotEvaluated, Transport: routing.NotAttempted, DurationNS: elapsed.Nanoseconds(), TransferSnapshot: routing.TransferSnapshot{WriteState: routing.WriteNotStarted}}
	} else if code == "invalid_request" {
		// Inventory schema failures use the validated tool-error category below.
		return
	}
	a.options.Recorder.Record(event)
}

func observedToolClass(name string) routing.ControlClass {
	switch name {
	case "resolve_project":
		return routing.ControlClass(protocol.ResolveProject)
	case "prepare_dispatch":
		return routing.PrepareClass
	case "dispatch_task":
		return routing.ControlClass(protocol.Admit)
	case "resolve_operation":
		return routing.ControlClass(protocol.Resolve)
	case "get_task_status":
		return routing.ControlClass(protocol.Status)
	case "recover_admission":
		return routing.ControlClass(protocol.ResumeExisting)
	case "collect_result":
		return routing.ControlClass(protocol.Collect)
	case "read_result_chunk":
		return routing.ControlClass(protocol.ResultChunk)
	case "cancel_task":
		return routing.ControlClass(protocol.Cancel)
	default:
		return ""
	}
}

// Ready means the final validated response was prepared, never that the peer
// received it or that an admitted Delegate task finished executing.
func recordedToolResult[Out any](a *Adapter, actor domain.Actor, schema *jsonschema.Resolved, envelope Envelope[Out], challenge string) *mcp.CallToolResult {
	result := toolResult(schema, envelope, challenge)
	if a.options.Recorder != nil {
		code := observability.MCPToolResponseReady
		if result.IsError {
			code = observability.MCPToolErrorReady
		}
		a.options.Recorder.Record(observability.Event{Code: code, Principal: actor.Principal})
	}
	return result
}

// JSON Schema requires an untyped JSON value. This value stays inside the
// validator boundary; all application inputs and outputs remain concrete DTOs.
func validJSON(schema *jsonschema.Resolved, data []byte) bool {
	var value any
	return json.Unmarshal(data, &value) == nil && schema.Validate(value) == nil
}

func toolResult[Out any](schema *jsonschema.Resolved, envelope Envelope[Out], challenge string) *mcp.CallToolResult {
	data, err := protocol.Encode(envelope, 1<<20)
	if err != nil || !validJSON(schema, data) {
		envelope = Envelope[Out]{Error: &ToolError{Code: "evidence_invalid"}}
		// The fallback contains only fixed primitive fields, so JSON encoding
		// cannot fail; retain the error path rather than ignoring that invariant.
		data, err = protocol.Encode(envelope, 1<<20)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: `{"error":{"code":"internal_error","retryable":false}}`}}}
		}
	}
	result := &mcp.CallToolResult{IsError: envelope.Error != nil, StructuredContent: json.RawMessage(data), Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}
	if challenge != "" {
		result.Meta = mcp.Meta{"mcp/www_authenticate": []string{challenge}}
	}
	return result
}

func classify(err error) *ToolError {
	cause := gateway.SoleError(err)
	if errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled) {
		return &ToolError{Code: "timeout", Retryable: true}
	}
	if errors.Is(cause, domain.ErrInvalid) || errors.Is(cause, protocol.ErrInvalid) {
		return &ToolError{Code: "invalid_request"}
	}
	if errors.Is(cause, protocol.ErrTooLarge) {
		return &ToolError{Code: "resource_limit", Retryable: false}
	}
	var failure *domain.Error
	if errors.As(cause, &failure) && failure != nil {
		return &ToolError{Code: string(failure.Code), Retryable: failure.Code == domain.Pending || failure.Code == domain.ResourceLimit}
	}
	var remote *gateway.RemoteError
	if errors.As(cause, &remote) && remote != nil && remote.Failure.Validate() == nil {
		return &ToolError{Code: remote.Failure.Code, Retryable: remote.Failure.Retryable}
	}
	return &ToolError{Code: "internal_error", Retryable: false}
}

// Only a checked consumer-owned input can retain its caller's request identity.
// Error graphs continue to describe causes, never correlation authority.
type retainedRequestInput interface{ retainedRequestID() string }

func inputFailure[In any](input In, err error) *ToolError {
	return retainInputFailure(input, classify(err))
}

func retainInputFailure[In any](input In, failure *ToolError) *ToolError {
	if retained, ok := any(input).(retainedRequestInput); ok {
		failure.RequestID = retained.retainedRequestID()
	}
	return failure
}

func constrainInput(schema *jsonschema.Schema) {
	for _, name := range []string{"device_id", "project_alias", "provider", "operation_id", "workspace_id"} {
		if property := schema.Properties[name]; property != nil {
			property.MinLength = pointer(1)
			property.MaxLength = pointer(128)
			property.Pattern = `^[A-Za-z0-9._:-]+$`
		}
	}
	for _, name := range []string{"model", "effort"} {
		if property := schema.Properties[name]; property != nil {
			property.MinLength = pointer(1)
			property.MaxLength = pointer(256)
		}
	}
	if property := schema.Properties["cursor"]; property != nil {
		property.MaxLength = pointer(128)
		property.Pattern = `^[A-Za-z0-9._:-]*$`
	}
	if property := schema.Properties["brief"]; property != nil {
		property.MinLength = pointer(1)
		property.MaxLength = pointer(256 << 10)
	}
	if property := schema.Properties["cancellation_id"]; property != nil {
		property.Pattern = `^[a-f0-9]{32}$`
	}
	if property := schema.Properties["request_id"]; property != nil {
		property.Pattern = `^[a-f0-9]{32}$`
		property.MinLength = pointer(32)
		property.MaxLength = pointer(32)
	}
	if property := schema.Properties["relative_path"]; property != nil {
		property.MinLength = pointer(1)
		property.MaxLength = pointer(4096)
	}
	if property := schema.Properties["permission"]; property != nil {
		property.Enum = []any{"read-only", "workspace-write", "danger-full-access"}
	}
	if property := schema.Properties["budget_seconds"]; property != nil {
		property.Minimum = pointer(1.0)
	}
	if property := schema.Properties["offset"]; property != nil {
		property.Minimum = pointer(0.0)
	}
	if property := schema.Properties["limit"]; property != nil {
		property.Minimum = pointer(1.0)
		maximum := 100.0
		if schema.Properties["offset"] != nil {
			maximum = 65536
		}
		property.Maximum = &maximum
	}
}

func pointer[T any](value T) *T { return &value }
