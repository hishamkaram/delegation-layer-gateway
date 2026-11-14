package deviceclient

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestExpectedShutdownRequiresQualifiedServeAndCleanClose(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	runtime, err := OpenRuntime(t.Context(), f.options.ProfileDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := runtime.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	serveErr := runtime.Serve(ctx)
	closeErr := runtime.Close()
	if !errors.Is(serveErr, context.Canceled) || !IsExpectedShutdown(serveErr, closeErr) {
		t.Fatal("clean joined interruption did not qualify for expected shutdown", serveErr, closeErr)
	}
	fault := errors.New("independent identity close failure")
	for _, test := range []struct {
		name         string
		serve, close error
	}{
		{name: "close-fault", serve: serveErr, close: fault},
		{name: "mixed-close-cancel", serve: serveErr, close: errors.Join(context.Canceled, fault)},
		{name: "mixed-serve", serve: errors.Join(serveErr, fault)},
		{name: "single-join", serve: errors.Join(serveErr, nil)},
		{name: "ordinary-wrapper", serve: fmt.Errorf("observer: %w", serveErr)},
		{name: "raw-cancel", serve: context.Canceled},
		{name: "unqualified-transport", serve: failed(ErrTransport, context.Canceled)},
		{name: "nil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if IsExpectedShutdown(test.serve, test.close) {
				t.Fatal("unqualified or mixed shutdown failure became success")
			}
		})
	}
}
