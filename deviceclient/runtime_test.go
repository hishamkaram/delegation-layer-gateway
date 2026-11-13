package deviceclient

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRuntimeOpenRetainsIdentityWithoutNetworkAndCloseReleases(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	f.server.Close()
	runtime, err := OpenRuntime(t.Context(), f.options.ProfileDirectory)
	if err != nil {
		t.Fatal("OpenRuntime required network or Native CLI", err)
	}
	t.Cleanup(func() {
		if closeErr := runtime.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	inactive, err := RuntimeInactive(t.Context(), f.options.ProfileDirectory)
	if err != nil || inactive {
		t.Fatal("OpenRuntime did not own identity", err)
	}
	if _, err = OpenRuntime(t.Context(), f.options.ProfileDirectory); !errors.Is(err, ErrBusy) {
		t.Fatal("two runtime owners acquired identity", err)
	}
	roots, err := runtime.configuration.Roots()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(f.descriptor.DeviceCAPEM))
	if block == nil {
		t.Fatal("CA fixture")
	}
	deviceCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = deviceCA.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now()}); err == nil {
		t.Fatal("downloaded device CA became server trust")
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
	inactive, err = RuntimeInactive(t.Context(), f.options.ProfileDirectory)
	if err != nil || !inactive {
		t.Fatal("identity lease leaked without Serve", err)
	}
	if err = runtime.Serve(t.Context()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatal("closed runtime started", err)
	}
}

func TestRuntimeCloseAndCancelledServeRace(t *testing.T) {
	f := connectedWorkspaceProfile(t)
	for range 12 {
		runtime, err := OpenRuntime(t.Context(), f.options.ProfileDirectory)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		start := make(chan struct{})
		var group sync.WaitGroup
		var serveErr, closeErr error
		group.Go(func() { <-start; serveErr = runtime.Serve(ctx) })
		group.Go(func() { <-start; closeErr = runtime.Close() })
		close(start)
		group.Wait()
		if closeErr != nil || (!errors.Is(serveErr, context.Canceled) && !errors.Is(serveErr, ErrRuntimeClosed)) {
			t.Fatal("Close/Serve race lost ownership", serveErr, closeErr)
		}
		if err = runtime.Serve(t.Context()); !errors.Is(err, ErrRuntimeClosed) {
			t.Fatal("runtime restarted after close", err)
		}
	}
}

func TestRuntimeCloseJoinsStartedNativeCLIWithoutReleasingIdentity(t *testing.T) {
	t.Setenv("GATEWAY_SDK_NATIVE_FIXTURE", "1")
	f := newGatewayFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f.options.DelegateExecutable = executable
	if _, err = Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(f.options.DelegateRoot, "sdk-native-block"), []byte("block"))
	runtime, err := OpenRuntime(t.Context(), f.options.ProfileDirectory)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	closeDone := make(chan error, 1)
	serveJoined, closeJoined := false, false
	closeLaunched := false
	t.Cleanup(func() {
		if releaseErr := os.WriteFile(filepath.Join(f.options.DelegateRoot, "sdk-native-release"), []byte("release"), 0o600); releaseErr != nil {
			t.Error(releaseErr)
		}
		if closeErr := runtime.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		if !serveJoined {
			<-serveDone
		}
		if closeLaunched && !closeJoined {
			<-closeDone
		}
	})
	go func() { serveDone <- runtime.Serve(t.Context()) }()
	waitRuntimeCondition(t, func() bool {
		_, statErr := os.Stat(filepath.Join(f.options.DelegateRoot, "sdk-native-started"))
		return statErr == nil
	})
	closeLaunched = true
	go func() { closeDone <- runtime.Close() }()
	waitRuntimeCondition(t, func() bool { runtime.mu.Lock(); defer runtime.mu.Unlock(); return runtime.closing })
	select {
	case closeErr := <-closeDone:
		closeJoined = true
		t.Fatal("Close returned before accepted CLI joined", closeErr)
	case <-time.After(80 * time.Millisecond):
	}
	inactive, err := RuntimeInactive(t.Context(), f.options.ProfileDirectory)
	if err != nil || inactive {
		t.Fatal("Close released identity before CLI join", err)
	}
	writePrivate(t, filepath.Join(f.options.DelegateRoot, "sdk-native-release"), []byte("release"))
	serveErr := <-serveDone
	serveJoined = true
	closeErr := <-closeDone
	closeJoined = true
	assertRuntimeJoined(t, f.options.ProfileDirectory, serveErr, closeErr)
}

func assertRuntimeJoined(t *testing.T, directory string, serveErr, closeErr error) {
	t.Helper()
	if !errors.Is(serveErr, context.Canceled) {
		t.Fatal("fixture did not complete the real runtime drain path", serveErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	inactive, err := RuntimeInactive(t.Context(), directory)
	if err != nil || !inactive {
		t.Fatal("joined runtime retained identity", err)
	}
}

func waitRuntimeCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("runtime owner gate not reached")
		case <-ticker.C:
		}
	}
}
