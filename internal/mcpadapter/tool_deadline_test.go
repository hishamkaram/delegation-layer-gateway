package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type deadlineAuthenticator struct {
	next    Authenticator
	expires atomic.Int64
}

func (a *deadlineAuthenticator) AuthenticateToken(ctx context.Context, raw string) (identity.VerifiedToken, error) {
	verified, err := a.next.AuthenticateToken(ctx, raw)
	if err != nil {
		return identity.VerifiedToken{}, err
	}
	verified.ExpiresAt = time.Unix(0, a.expires.Load())
	return verified, nil
}

type (
	deadlineProbeInput  struct{}
	deadlineProbeOutput struct {
		Value string `json:"value"`
	}
	deadlineObservation struct {
		deadline time.Time
		present  bool
	}
	probeResult struct {
		result *mcp.CallToolResult
		err    error
	}
)

func deadlineProbeFixture(t *testing.T, timeout time.Duration) (*fixture, *deadlineAuthenticator, <-chan deadlineObservation, <-chan struct{}) {
	t.Helper()
	authenticator := &deadlineAuthenticator{}
	authenticator.expires.Store(time.Now().Add(time.Hour).UnixNano())
	f := newConfiguredFixture(t, 0, nil, func(options *Options) {
		authenticator.next = options.Authenticator
		options.Authenticator = authenticator
		options.Now = time.Now
		options.Timeout = timeout
	})
	entered := make(chan deadlineObservation, 1)
	stopped := make(chan struct{})
	check(t, register(f.adapter, "deadline_probe", "Exercise a bounded fixture observer.", []domain.Scope{domain.TaskRead}, toolHints{ReadOnly: true}, func(ctx context.Context, _ domain.Actor, _ deadlineProbeInput) (deadlineProbeOutput, error) {
		defer close(stopped)
		deadline, present := ctx.Deadline()
		entered <- deadlineObservation{deadline: deadline, present: present}
		<-ctx.Done()
		// A misbehaving edge returning success after cancellation must not expose
		// that data. This fixture runs no provider or task.
		return deadlineProbeOutput{Value: privateCanary}, nil
	}))
	return f, authenticator, entered, stopped
}

func callDeadlineProbe(t *testing.T, session *mcp.ClientSession) (context.CancelFunc, <-chan probeResult) {
	t.Helper()
	return callFixtureProbe(t, session, "deadline_probe")
}

func callFixtureProbe(t *testing.T, session *mcp.ClientSession, name string) (context.CancelFunc, <-chan probeResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	results := make(chan probeResult, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: json.RawMessage(`{}`)})
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
	return cancel, results
}

func probeEntered(t *testing.T, entered <-chan deadlineObservation, results <-chan probeResult) deadlineObservation {
	t.Helper()
	select {
	case observation := <-entered:
		return observation
	case result := <-results:
		t.Fatalf("probe never entered handler: %v", result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not reach handler")
	}
	return deadlineObservation{}
}

func probeStopped(t *testing.T, stopped <-chan struct{}) {
	t.Helper()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture handler did not join")
	}
}

func TestSDKToolDeadlineIncludesVerifiedTokenExpiry(t *testing.T) {
	f, authenticator, entered, stopped := deadlineProbeFixture(t, 10*time.Second)
	session := f.session(t, "alice")
	expires := time.Now().Add(2 * time.Second)
	authenticator.expires.Store(expires.UnixNano())
	cancel, results := callDeadlineProbe(t, session)
	defer cancel()
	observation := probeEntered(t, entered, results)
	if !observation.present || !observation.deadline.Equal(expires) {
		t.Fatal("tool context did not use verified JWT expiry")
	}
	result := <-results
	check(t, result.err)
	probeStopped(t, stopped)
	expectError[deadlineProbeOutput](t, result.result, "unauthenticated")
	if !decodeResult[deadlineProbeOutput](t, result.result).Error.Retryable {
		t.Fatal("post-handler expiry lost same-identity retry semantics")
	}
	assertPublic(t, result.result)
}

func TestSDKToolConfiguredDeadlineWithholdsLateSuccess(t *testing.T) {
	f, _, entered, stopped := deadlineProbeFixture(t, 200*time.Millisecond)
	session := f.session(t, "alice")
	cancel, results := callDeadlineProbe(t, session)
	defer cancel()
	observation := probeEntered(t, entered, results)
	if !observation.present || observation.deadline.After(time.Now().Add(time.Second)) {
		t.Fatal("configured deadline was extended by token lifetime")
	}
	result := <-results
	check(t, result.err)
	probeStopped(t, stopped)
	expectError[deadlineProbeOutput](t, result.result, "timeout")
	assertPublic(t, result.result)
}

func TestSDKToolCallerCancellationStillReachesHandler(t *testing.T) {
	f, _, entered, stopped := deadlineProbeFixture(t, 10*time.Second)
	session := f.session(t, "alice")
	cancel, results := callDeadlineProbe(t, session)
	_ = probeEntered(t, entered, results)
	cancel()
	result := <-results
	if !errors.Is(result.err, context.Canceled) {
		t.Fatal("caller cancellation did not end the SDK call", result.err)
	}
	probeStopped(t, stopped)
}

func TestSDKToolRechecksExpiryBeforeSuccessResponse(t *testing.T) {
	var offset atomic.Int64
	f := newConfiguredFixture(t, 0, nil, func(options *Options) {
		options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	})
	check(t, register(f.adapter, "expiry_probe", "Exercise fixture response expiry.", []domain.Scope{domain.TaskRead}, toolHints{ReadOnly: true}, func(context.Context, domain.Actor, deadlineProbeInput) (deadlineProbeOutput, error) {
		offset.Store(int64(25 * time.Hour))
		return deadlineProbeOutput{Value: privateCanary}, nil
	}))
	result := f.call(t, f.session(t, "alice"), "expiry_probe", json.RawMessage(`{}`))
	expectError[deadlineProbeOutput](t, result, "unauthenticated")
	if !decodeResult[deadlineProbeOutput](t, result).Error.Retryable {
		t.Fatal("post-handler expiry forbade reauthentication and same-identity resolution")
	}
	assertPublic(t, result)
}

type handoffRecorder struct {
	entered chan struct{}
	unblock chan struct{}
	once    sync.Once
}

func (r *handoffRecorder) Record(event observability.Event) {
	if event.Code == observability.MCPToolResponseReady {
		r.once.Do(func() { close(r.entered) })
		<-r.unblock
	}
}

func TestSDKToolFinalHandoffRechecksExpiryAndCancellationAfterRecording(t *testing.T) {
	for _, mode := range []string{"expiry", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var offset atomic.Int64
			recorder := &handoffRecorder{entered: make(chan struct{}), unblock: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(recorder.unblock) }) }
			f := newConfiguredFixture(t, 0, recorder, func(options *Options) {
				options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
				options.Timeout = 2 * time.Second
			})
			contexts := make(chan context.Context, 1)
			check(t, register(f.adapter, "handoff_probe", "Exercise a fixture handoff gate.", []domain.Scope{domain.TaskRead}, toolHints{ReadOnly: true}, func(ctx context.Context, _ domain.Actor, _ deadlineProbeInput) (deadlineProbeOutput, error) {
				contexts <- ctx
				return deadlineProbeOutput{Value: privateCanary}, nil
			}))
			cancel, results := callFixtureProbe(t, f.session(t, "alice"), "handoff_probe")
			defer cancel()
			t.Cleanup(release)
			select {
			case <-recorder.entered:
			case result := <-results:
				t.Fatalf("handler failed before encoding/recording boundary: %v", result.err)
			case <-time.After(5 * time.Second):
				t.Fatal("metadata recording gate not reached")
			}
			ctx := <-contexts
			if mode == "expiry" {
				offset.Store(int64(25 * time.Hour))
			} else {
				<-ctx.Done()
			}
			release()
			result := <-results
			check(t, result.err)
			code := "unauthenticated"
			if mode == "deadline" {
				code = "timeout"
			}
			expectError[deadlineProbeOutput](t, result.result, code)
			assertPublic(t, result.result)
			if !decodeResult[deadlineProbeOutput](t, result.result).Error.Retryable {
				t.Fatal("post-handler observation failure lost same-identity retry semantics")
			}
		})
	}
}

func TestSDKToolPreHandlerExpiryRemainsNonRetryable(t *testing.T) {
	var offset atomic.Int64
	f := newConfiguredFixture(t, 0, nil, func(options *Options) {
		options.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	})
	var calls atomic.Int32
	check(t, register(f.adapter, "pre_expiry_probe", "Exercise fixture authentication.", []domain.Scope{domain.TaskRead}, toolHints{ReadOnly: true}, func(context.Context, domain.Actor, deadlineProbeInput) (deadlineProbeOutput, error) {
		calls.Add(1)
		return deadlineProbeOutput{Value: privateCanary}, nil
	}))
	session := f.session(t, "alice")
	offset.Store(int64(25 * time.Hour))
	result := f.call(t, session, "pre_expiry_probe", json.RawMessage(`{}`))
	expectError[deadlineProbeOutput](t, result, "unauthenticated")
	if decodeResult[deadlineProbeOutput](t, result).Error.Retryable || calls.Load() != 0 {
		t.Fatal("pre-handler expiry claimed a possible prior send")
	}
	assertPublic(t, result)
}
