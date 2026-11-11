package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
)

func TestAdminMalformedOversizedAndRedirectResponsesAreRedacted(t *testing.T) {
	for _, mode := range []string{"unknown", "oversize", "redirect", "empty", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			parent := t.TempDir()
			socket := filepath.Join(parent, "admin.sock")
			var calls atomic.Int64
			startAdminResponseServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				malformedAdminResponse(w, mode)
			}))
			input := writePrivate(t, filepath.Join(parent, "input.json"), adminapi.RegisterDeviceInput{DeviceID: "device", Name: "Workstation"})
			code, out, diagnostic := command(t, "admin", "--socket", socket, "--action", "register-device", "--input-file", input)
			if code != 1 || out != "" || strings.Contains(diagnostic, "private-canary") || calls.Load() != 1 {
				t.Fatalf("unsafe response handling: %d %s %s calls%d", code, out, diagnostic, calls.Load())
			}
		})
	}
}

func TestOutputPreparationFailureCausesNoMutation(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	socket := filepath.Join(parent, "admin.sock")

	var calls atomic.Int64
	startAdminResponseServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if encodeErr := json.NewEncoder(w).Encode(adminapi.Mutation{Committed: true}); encodeErr != nil {
			return
		}
	}))
	input := writePrivate(t, filepath.Join(parent, "input.json"), adminapi.RegisterDeviceInput{DeviceID: "device", Name: "Workstation"})
	existing := filepath.Join(parent, "existing.json")
	require(t, os.WriteFile(existing, []byte("foreign-private-canary"), 0o600))
	code, out, diagnostic := command(t, "admin", "--socket", socket, "--action", "register-device", "--input-file", input, "--output-file", existing)
	if code != 2 || out != "" || strings.Contains(diagnostic, "private-canary") || calls.Load() != 0 {
		t.Fatal("mutation began before output ownership")
	}
	after, err := os.ReadFile(existing)
	require(t, err)
	if !bytes.Equal(after, []byte("foreign-private-canary")) {
		t.Fatal("foreign output modified")
	}
}

func TestCanceledUnixAwaitAndCommittedFailureStayExplicit(t *testing.T) {
	response := &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"code":"disconnect_unconfirmed","committed":true}`))}
	defer func() { require(t, response.Body.Close()) }()
	_, err := readAdminResponse(response)
	var failure *commandError
	if !errors.As(err, &failure) || failure.exit != 3 || failure.code != "admin_mutation_committed_cleanup_unconfirmed" {
		t.Fatal("durable mutation rolled back in CLI report")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = unixRequest(ctx, filepath.Join(t.TempDir(), "missing.sock"), http.MethodPost, "/v1/devices", []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatal("Unix transport lost caller cancellation")
	}
}

func TestLostEnrollmentResponseNeverReplaysOrPrintsCredential(t *testing.T) {
	parent := t.TempDir()
	require(t, os.Chmod(parent, 0o700))
	socket := filepath.Join(parent, "admin.sock")

	var calls atomic.Int64
	var closed atomic.Bool
	startAdminResponseServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("HTTP1 hijacker unavailable")
			return
		}
		connection, _, hijackErr := hijacker.Hijack()
		if hijackErr != nil {
			t.Error(hijackErr)
			return
		}
		closed.Store(true)
		if closeErr := connection.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}))
	input := writePrivate(t, filepath.Join(parent, "input.json"), adminapi.EnrollmentInput{DeviceID: "device", Mode: "regular", Generation: 1})
	output := filepath.Join(parent, "token.json")
	code, out, diagnostic := command(t, "admin", "--socket", socket, "--action", "issue-enrollment-token", "--input-file", input, "--output-file", output)
	if code != 3 || out != "" || !strings.Contains(diagnostic, "credential_delivery_unconfirmed") || calls.Load() != 1 || !closed.Load() {
		t.Fatalf("lost response guessed or replayed: %d %s %s", code, out, diagnostic)
	}
	data, err := os.ReadFile(output)
	require(t, err)
	if len(data) != 0 {
		t.Fatal("unknown credential fabricated into output")
	}
}

func startAdminResponseServer(t *testing.T, socket string, handler http.Handler) {
	t.Helper()
	listener, err := net.Listen("unix", socket)
	require(t, err)
	server := &http.Server{Handler: handler}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		require(t, server.Close())
		if serveErr := <-done; !errors.Is(serveErr, http.ErrServerClosed) {
			t.Error(serveErr)
		}
	})
}

func malformedAdminResponse(w http.ResponseWriter, mode string) {
	w.Header().Set("Content-Type", "application/json")
	var body string
	switch mode {
	case "unknown":
		body = `{"device_id":"device","name":"Workstation","private-canary":true}`
	case "oversize":
		body = strings.Repeat("private-canary", maxAdminResponse)
	case "redirect":
		w.Header().Set("Location", "http://unix/private-canary")
		w.WriteHeader(307)
		body = `{"code":"private-canary","committed":false}`
	case "empty":
		body = `{}`
	case "plaintext":
		w.Header().Set("Content-Type", "text/plain")
		body = `{"device_id":"device","name":"Workstation"}`
	}
	if _, writeErr := io.WriteString(w, body); writeErr != nil {
		return
	}
}
