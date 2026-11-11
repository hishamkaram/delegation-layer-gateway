package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
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
		actor, failure, challenge := a.actor(request, scopes)
		if failure != nil {
			return recordedToolResult(a, actor, outValidator, Envelope[Out]{Error: failure}, challenge), nil
		}
		ctx, cancel := context.WithTimeout(ctx, a.options.Timeout)
		defer cancel()
		var args In
		raw := request.Params.Arguments
		if len(raw) == 0 {
			raw = json.RawMessage(`{}`)
		}
		if protocol.DecodeStrict(raw, &args, 1<<20) != nil || !validJSON(inValidator, raw) {
			return recordedToolResult(a, actor, outValidator, Envelope[Out]{Error: &ToolError{Code: "invalid_request"}}, ""), nil
		}
		value, callErr := handler(ctx, actor, args)
		if callErr != nil {
			return recordedToolResult(a, actor, outValidator, Envelope[Out]{Error: classify(callErr)}, ""), nil
		}
		return recordedToolResult(a, actor, outValidator, Envelope[Out]{Data: &value}, ""), nil
	})
	return nil
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
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return &ToolError{Code: "timeout", Retryable: true}
	}
	if errors.Is(err, domain.ErrInvalid) || errors.Is(err, protocol.ErrInvalid) {
		return &ToolError{Code: "invalid_request"}
	}
	if errors.Is(err, protocol.ErrTooLarge) {
		return &ToolError{Code: "resource_limit", Retryable: false}
	}
	var failure *domain.Error
	if errors.As(err, &failure) {
		return &ToolError{Code: string(failure.Code), Retryable: failure.Code == domain.Pending || failure.Code == domain.ResourceLimit}
	}
	var remote *gateway.RemoteError
	if errors.As(err, &remote) && remote.Failure.Validate() == nil {
		return &ToolError{Code: remote.Failure.Code, Retryable: remote.Failure.Retryable}
	}
	return &ToolError{Code: "internal_error", Retryable: false}
}

func constrainInput(schema *jsonschema.Schema) {
	for _, name := range []string{"device_id", "project_alias", "provider", "operation_id"} {
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
