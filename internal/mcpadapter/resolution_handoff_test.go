package mcpadapter

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
)

type expiryResolutionBackend struct {
	WorkspaceTools
	afterResolve func()
}

func (b expiryResolutionBackend) ResolveProject(ctx context.Context, actor domain.Actor, input workspaces.ResolveInput) (workspaces.Resolution, error) {
	result, err := b.WorkspaceTools.ResolveProject(ctx, actor, input)
	b.afterResolve()
	return result, err
}

func TestSDKResolutionExpiryRetainsIdentityAfterHandler(t *testing.T) {
	var offset atomic.Int64
	backend := &workspaceBackend{}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) {
		options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
		options.Workspaces = expiryResolutionBackend{WorkspaceTools: backend, afterResolve: func() { offset.Store(int64(25 * time.Hour)) }}
	})
	input := handoffResolutionInput()
	result := f.call(t, f.session(t, "dispatch"), "resolve_project", args(t, input))
	assertExpiredResolutionIdentity(t, result, input.RequestID)
	if backend.resolveCalls != 1 {
		t.Fatal("expiry fixture did not complete exactly one resolution")
	}
}

func TestSDKResolutionFinalHandoffRetainsIdentityAfterRecording(t *testing.T) {
	var offset atomic.Int64
	recorder := &handoffRecorder{entered: make(chan struct{}), unblock: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(recorder.unblock) }) }
	backend := &workspaceBackend{}
	f := newConfiguredFixture(t, 0, recorder, func(options *Options) {
		options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
		options.Workspaces = backend
	})
	input := handoffResolutionInput()
	results := beginBoundaryToolCall(t, f, f.session(t, "dispatch"), "resolve_project", args(t, input))
	t.Cleanup(release)
	awaitBoundaryGate(t, recorder.entered, results)
	offset.Store(int64(25 * time.Hour))
	release()
	result := <-results
	check(t, result.err)
	assertExpiredResolutionIdentity(t, result.result, input.RequestID)
	if backend.resolveCalls != 1 {
		t.Fatal("handoff failure repeated resolution")
	}
}

func TestSDKResolutionPreHandlerRejectionsDoNotGainIdentity(t *testing.T) {
	var offset atomic.Int64
	backend := &workspaceBackend{}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) {
		options.Workspaces = backend
		options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	})
	for _, test := range []struct{ token, code string }{{"inventory", "forbidden"}, {"dispatch", "unauthenticated"}} {
		session := f.session(t, test.token)
		if test.code == "unauthenticated" {
			offset.Store(int64(25 * time.Hour))
		}
		result := f.call(t, session, "resolve_project", args(t, handoffResolutionInput()))
		expectError[ResolvedProject](t, result, test.code)
		if decodeResult[ResolvedProject](t, result).Error.RequestID != "" {
			t.Fatal("pre-handler rejection gained an unvalidated input identity")
		}
	}
	if backend.resolveCalls != 0 {
		t.Fatal("pre-handler rejection reached resolution")
	}
}

func handoffResolutionInput() ResolveProjectInput {
	return ResolveProjectInput{DeviceID: "device-one", RequestID: strings.Repeat("e", 32), WorkspaceID: "code", RelativePath: "repo"}
}

func assertExpiredResolutionIdentity(t *testing.T, result *mcp.CallToolResult, requestID string) {
	t.Helper()
	expectError[ResolvedProject](t, result, "unauthenticated")
	failure := decodeResult[ResolvedProject](t, result).Error
	if failure.RequestID != requestID || !failure.Retryable {
		t.Fatal("post-handler expiry dropped same-request retry identity")
	}
	wire := sdkValue[resultWire](t, result)
	if len(wire.Meta.Challenges) != 1 || !strings.Contains(wire.Meta.Challenges[0], `error="invalid_token"`) {
		t.Fatal("retained identity changed the authentication challenge")
	}
	assertPublic(t, result)
}

func beginBoundaryToolCall(t *testing.T, f *fixture, session *mcp.ClientSession, name string, input json.RawMessage) <-chan probeResult {
	t.Helper()
	f.clock.advance()
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	results := make(chan probeResult, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: input})
		results <- probeResult{result: result, err: err}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("fixture MCP caller did not join")
		}
	})
	return results
}

func awaitBoundaryGate(t *testing.T, entered <-chan struct{}, results <-chan probeResult) {
	t.Helper()
	select {
	case <-entered:
	case result := <-results:
		t.Fatalf("tool returned before reaching its owner gate: %v", result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("tool did not reach its owner gate")
	}
}
