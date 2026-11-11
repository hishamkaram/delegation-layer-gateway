//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDiscardDispatchResponseUsesRealHTTPSAndSDKWithoutRetry(t *testing.T) {
	for _, discard := range []bool{false, true} {
		t.Run(fmt.Sprint(discard), func(t *testing.T) {
			server := mcp.NewServer(&mcp.Implementation{Name: "discard-fixture", Version: "1"}, nil)
			var invoked atomic.Int32
			mcp.AddTool(server, &mcp.Tool{Name: "dispatch_task"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
				invoked.Add(1)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "accepted once"}}}, struct{}{}, nil
			})
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
			fixture, input := newMCPFixture(t, handler)
			input.Endpoint = fixture.URL + "/mcp"
			input.Tool = "dispatch_task"
			input.Arguments = json.RawMessage(`{}`)
			input.DiscardToolResponse = discard
			result, err := callMCP(t.Context(), input)
			if invoked.Load() != 1 {
				t.Fatal("tool invocation was dropped or repeated")
			}
			if discard {
				if result != nil || failureOutput(err) != `{"code":"fixture_response_discarded"}` {
					t.Fatalf("discard did not preserve a delivered call and joined session: result=%v err=%v", result, err)
				}
			} else if err != nil || result == nil || result.IsError {
				t.Fatalf("default dispatch response was discarded: %v", err)
			}
		})
	}
}

func TestDiscardFlagRejectsOtherToolsAndMetadataBeforeCredentials(t *testing.T) {
	for _, tool := range []string{"", "prepare_dispatch", "resolve_operation", "cancel_task"} {
		if _, err := callMCP(t.Context(), callInput{Endpoint: "https://gateway.example/mcp", TrustMode: "system", Tool: tool, DiscardToolResponse: true}); err == nil || err.Error() != "fixture response discard requires dispatch_task" {
			t.Fatal("invalid discard tool reached credential access")
		}
	}
	if _, err := readMetadata(t.Context(), callInput{Endpoint: "https://gateway.example/mcp", TrustMode: "system", DiscardToolResponse: true}); err == nil || err.Error() != "fixture metadata requires tokenless system trust input" {
		t.Fatal("metadata accepted a response-discard flag")
	}
}

func TestDiscardClassificationPreservesOriginalBody(t *testing.T) {
	const data = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dispatch_task","arguments":{}}}`
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://gateway.example/mcp", bytes.NewReader([]byte(data)))
	fixtureOK(t, err)
	var sent int
	transport := discardResponseTransport{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent++
		body, readErr := io.ReadAll(r.Body)
		fixtureOK(t, readErr)
		fixtureOK(t, r.Body.Close())
		if string(body) != data {
			t.Fatal("classification consumed or changed the sent request")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}
	response, roundErr := transport.RoundTrip(request)
	if response != nil {
		fixtureOK(t, response.Body.Close())
	}
	if response != nil || !errors.Is(roundErr, errDiscardedToolResponse) || sent != 1 {
		t.Fatal("matching response was not discarded after one unchanged send")
	}
}

func TestDiscardClassificationFailuresCloseOriginalWithoutSending(t *testing.T) {
	for name, setup := range map[string]func(*http.Request){
		"no-getbody": func(r *http.Request) { r.GetBody = nil },
		"getbody-error": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) { return nil, io.ErrUnexpectedEOF }
		},
		"nil-copy": func(r *http.Request) { r.GetBody = func() (io.ReadCloser, error) { return nil, nil } },
		"copy-read-error": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) { return &countedBody{reader: failedBodyReader{}}, nil }
		},
		"copy-close-error": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) {
				return &countedBody{reader: strings.NewReader(`{}`), closeErr: io.ErrClosedPipe}, nil
			}
		},
		"malformed": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(`{`)), nil }
		},
		"not-jsonrpc": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(`{}`)), nil }
		},
		"oversized": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1))), nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			original := &countedBody{reader: strings.NewReader("untouched"), closeErr: io.ErrClosedPipe}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://gateway.example/mcp", original)
			fixtureOK(t, err)
			setup(request)
			sent := false
			transport := discardResponseTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
				sent = true
				return nil, errors.New("unexpected send")
			})}
			response, roundErr := transport.RoundTrip(request)
			if response != nil {
				fixtureOK(t, response.Body.Close())
			}
			if sent || response != nil || roundErr == nil || !original.closed || original.read != 0 || !errors.Is(roundErr, io.ErrClosedPipe) {
				t.Fatal("classification error sent work, consumed the original body, or lost cleanup")
			}
		})
	}
}

func TestDiscardPassesInitializationGetDeleteAndNon200(t *testing.T) {
	for _, row := range []struct {
		method, body string
		status       int
	}{
		{http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, 200},
		{http.MethodGet, "", 200},
		{http.MethodDelete, "", 200},
		{http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dispatch_task"}}`, 503},
	} {
		request, err := http.NewRequestWithContext(t.Context(), row.method, "https://gateway.example/mcp", strings.NewReader(row.body))
		fixtureOK(t, err)
		transport := discardResponseTransport{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Body != nil {
				fixtureOK(t, r.Body.Close())
			}
			return &http.Response{StatusCode: row.status, Body: io.NopCloser(strings.NewReader("unchanged"))}, nil
		})}
		response, roundErr := transport.RoundTrip(request)
		fixtureOK(t, roundErr)
		data, readErr := io.ReadAll(response.Body)
		fixtureOK(t, readErr)
		fixtureOK(t, response.Body.Close())
		if response.StatusCode != row.status || string(data) != "unchanged" {
			t.Fatal("nonmatching HTTP response changed")
		}
	}
}

func TestDiscardCleanupFailureCannotBecomeExpectedLoss(t *testing.T) {
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://gateway.example/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dispatch_task"}}`))
	fixtureOK(t, err)
	body := &countedBody{reader: strings.NewReader("complete"), closeErr: io.ErrClosedPipe}
	transport := discardResponseTransport{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		fixtureOK(t, r.Body.Close())
		return &http.Response{StatusCode: 200, Body: body}, nil
	})}
	response, roundErr := transport.RoundTrip(request)
	if response != nil {
		fixtureOK(t, response.Body.Close())
	}
	if !body.closed || !errors.Is(roundErr, io.ErrClosedPipe) || errors.Is(roundErr, errDiscardedToolResponse) || failureOutput(finishMCPCall(roundErr, nil)) != `{"code":"fixture_failed"}` {
		t.Fatal("retained-body failure became intentional-loss evidence")
	}
	wrapped := fmt.Errorf("SDK: %w", errDiscardedToolResponse)
	joined := finishMCPCall(wrapped, io.ErrClosedPipe)
	if failureOutput(joined) != `{"code":"fixture_failed"}` || !errors.Is(joined, errDiscardedToolResponse) || !errors.Is(joined, io.ErrClosedPipe) {
		t.Fatal("session cleanup failure was hidden by the wire sentinel")
	}
	for _, altered := range []error{errors.Join(errExpectedResponseLoss, io.ErrClosedPipe), fmt.Errorf("cleanup: %w", errExpectedResponseLoss)} {
		if failureOutput(altered) != `{"code":"fixture_failed"}` {
			t.Fatal("joined or wrapped loss marker passed exact failure classification")
		}
	}
}

func TestDiscardCopyFailuresCloseBothBodiesAndPreserveEachError(t *testing.T) {
	copyCloseErr := errors.New("copy-close-failed")
	for _, row := range []struct {
		name    string
		reader  io.Reader
		getErr  error
		wantErr error
	}{
		{"copy-returned-with-error", strings.NewReader("unused"), io.ErrUnexpectedEOF, io.ErrUnexpectedEOF},
		{"copy-read-failed", failedBodyReader{}, nil, io.ErrUnexpectedEOF},
		{"copy-close-failed", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dispatch_task"}}`), nil, copyCloseErr},
	} {
		t.Run(row.name, func(t *testing.T) {
			original := &countedBody{reader: strings.NewReader("unchanged"), closeErr: io.ErrClosedPipe}
			copied := &countedBody{reader: row.reader, closeErr: copyCloseErr}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://gateway.example/mcp", original)
			fixtureOK(t, err)
			request.GetBody = func() (io.ReadCloser, error) { return copied, row.getErr }
			transport := discardResponseTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Error("copy failure reached the network")
				return nil, errors.New("unexpected send")
			})}
			response, roundErr := transport.RoundTrip(request)
			if response != nil {
				fixtureOK(t, response.Body.Close())
			}
			if !original.closed || original.read != 0 || !copied.closed || !errors.Is(roundErr, row.wantErr) || !errors.Is(roundErr, copyCloseErr) || !errors.Is(roundErr, io.ErrClosedPipe) {
				t.Fatal("copy failure lost independent body ownership or concrete errors")
			}
		})
	}
}

func TestDiscardMissingRequestOrOriginalBodyNeverSends(t *testing.T) {
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://gateway.example/mcp", strings.NewReader(`{}`))
	fixtureOK(t, err)
	fixtureOK(t, request.Body.Close())
	request.Body = nil
	for _, candidate := range []*http.Request{nil, request} {
		transport := discardResponseTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Error("missing original body reached the wire")
			return nil, errors.New("unexpected send")
		})}
		response, roundErr := transport.RoundTrip(candidate)
		if response != nil {
			fixtureOK(t, response.Body.Close())
		}
		if response != nil || roundErr == nil || failureOutput(roundErr) != `{"code":"fixture_failed"}` {
			t.Fatal("missing request body was accepted or classified as expected loss")
		}
	}
}

func TestDiscardWireCloseFailureIsNotExpectedResponseLoss(t *testing.T) {
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://gateway.example/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dispatch_task"}}`))
	fixtureOK(t, err)
	wire := &countedBody{reader: strings.NewReader("complete response"), closeErr: io.ErrClosedPipe}
	transport := discardResponseTransport{base: boundedTransport{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		fixtureOK(t, r.Body.Close())
		return &http.Response{StatusCode: 200, Body: wire}, nil
	})}}
	response, roundErr := transport.RoundTrip(request)
	if response != nil {
		fixtureOK(t, response.Body.Close())
	}
	if response != nil || !wire.closed || wire.read != len("complete response") || !errors.Is(roundErr, io.ErrClosedPipe) || errors.Is(roundErr, errDiscardedToolResponse) || failureOutput(finishMCPCall(roundErr, nil)) != `{"code":"fixture_failed"}` {
		t.Fatal("wire body close failure was mistaken for expected response loss")
	}
}
