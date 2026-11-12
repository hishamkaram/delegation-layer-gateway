package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/httpguard"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
)

type rejectionTestGate struct {
	entered chan struct{}
	release chan struct{}
	enter   sync.Once
	open    sync.Once
}

func newRejectionTestGate() *rejectionTestGate {
	return &rejectionTestGate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *rejectionTestGate) hold() {
	g.enter.Do(func() { close(g.entered) })
	<-g.release
}

func (g *rejectionTestGate) unblock() { g.open.Do(func() { close(g.release) }) }

type boundaryRejectionResponse struct {
	reason httpguard.Rejection
	status int
}

// This fixture owns only local goroutines, the real temporary Audit, and one
// Guard slot. It does not run a TLS server or claim a live HTTP/2 attack proof.
type boundaryRejectionFixture struct {
	runtime   *Runtime
	handler   http.Handler
	auditGate *rejectionTestGate
	admitted  *rejectionTestGate
	owners    sync.WaitGroup
	entered   chan httpguard.Rejection
	responses chan boundaryRejectionResponse
	seedDone  chan error
	nextCalls atomic.Int32
}

func newBoundaryRejectionFixture(t *testing.T) *boundaryRejectionFixture {
	t.Helper()
	f := &boundaryRejectionFixture{
		runtime: &Runtime{}, auditGate: newRejectionTestGate(), admitted: newRejectionTestGate(),
		entered: make(chan httpguard.Rejection, 6), responses: make(chan boundaryRejectionResponse, 6), seedDone: make(chan error, 1),
	}
	directory := t.TempDir()
	require(t, os.Chmod(directory, 0o700))
	audit, err := observability.Open(directory, func() time.Time {
		// Audit.Record invokes now only after acquiring the actual Audit mutex.
		f.auditGate.hold()
		return time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	})
	require(t, err)
	t.Cleanup(func() {
		// Release audit first: a failed assertion must not strand the original
		// rejected handlers on its mutex. Close Audit only after every owner joins.
		f.auditGate.unblock()
		f.admitted.unblock()
		f.owners.Wait()
		if closeErr := audit.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	f.runtime.recorder, err = observability.NewRecorder(audit, &f.runtime.metrics)
	require(t, err)
	guard, err := httpguard.New(httpguard.Options{
		PublicOrigin: "https://gateway.example", ConcurrentRequests: 1, Timeout: time.Minute, MaxBodyBytes: 1024,
		Rejected: func(reason httpguard.Rejection) {
			f.entered <- reason
			f.runtime.observeHTTPRejection(reason)
		},
	})
	require(t, err)
	f.handler = guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.nextCalls.Add(1)
		f.admitted.hold()
		w.WriteHeader(http.StatusNoContent)
	}))
	f.owners.Go(func() { f.seedDone <- audit.Record(observability.Event{Code: observability.ShutdownStarted}) })
	f.owners.Go(func() { f.handler.ServeHTTP(httptest.NewRecorder(), boundaryRejectionRequest(false)) })
	return f
}

func boundaryRejectionRequest(originRejected bool) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://gateway.example/mcp", nil)
	request.TLS = &tls.ConnectionState{}
	if originRejected {
		request.Header.Set("Origin", "https://untrusted.example")
	}
	return request
}

func waitRejectionTestGate(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("controlled owner did not enter its gate")
	}
}

func (f *boundaryRejectionFixture) reject(origin bool) {
	reason := httpguard.CapacityRejected
	if origin {
		reason = httpguard.OriginRejected
	}
	f.owners.Go(func() {
		out := httptest.NewRecorder()
		f.handler.ServeHTTP(out, boundaryRejectionRequest(origin))
		f.responses <- boundaryRejectionResponse{reason: reason, status: out.Code}
	})
}

func (f *boundaryRejectionFixture) awaitRejectionEntries(t *testing.T) {
	t.Helper()
	counts := map[httpguard.Rejection]int{}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for range 6 {
		select {
		case reason := <-f.entered:
			counts[reason]++
		case <-deadline.C:
			t.Fatal("rejected requests did not enter the actual observation callback")
		}
	}
	if len(counts) != 2 || counts[httpguard.OriginRejected] != 3 || counts[httpguard.CapacityRejected] != 3 {
		t.Fatal("controlled requests did not exercise both pre-admission rejection categories")
	}
}

func (f *boundaryRejectionFixture) assertResponsesBeforeAuditRelease(t *testing.T) {
	t.Helper()
	// This is a finite deadlock-observation watchdog, not a throughput or latency
	// contract. The audit owner remains held for the entire response observation.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for completed := 0; completed < 6; completed++ {
		select {
		case response := <-f.responses:
			want := http.StatusServiceUnavailable
			if response.reason == httpguard.OriginRejected {
				want = http.StatusForbidden
			}
			if response.status != want {
				t.Fatalf("boundary rejection status %d, want %d", response.status, want)
			}
		case <-deadline.C:
			t.Fatalf("pre-admission rejection waited on held audit owner: returned %d of 6", completed)
		}
	}
}

func (f *boundaryRejectionFixture) assertCountersAndHealth(t *testing.T) {
	t.Helper()
	metrics := httptest.NewRecorder()
	f.runtime.metrics.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "http://unix/metrics", nil))
	for _, expected := range []string{
		"gateway_boundary_rejections_total{reason=\"origin\"} 3\n",
		"gateway_boundary_rejections_total{reason=\"capacity\"} 3\n",
		"gateway_events_total{event=\"authorization_denied\"} 0\n",
		"gateway_events_total{event=\"resource_denied\"} 0\n",
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatal("fixed boundary rejection counter differs from actual rejected requests")
		}
	}
	if health := f.runtime.recorder.Health(); !health.AuditHealthy || health.AuditFailures != 0 || health.MetricFailures != 0 {
		t.Fatal("count-only boundary observation invented a failed audit attempt")
	}
}

func TestPreAdmissionRejectionsDoNotWaitOnAuditOwner(t *testing.T) {
	f := newBoundaryRejectionFixture(t)
	waitRejectionTestGate(t, f.auditGate.entered)
	waitRejectionTestGate(t, f.admitted.entered)
	for range 3 {
		f.reject(true)
		f.reject(false)
	}
	f.awaitRejectionEntries(t)
	f.assertResponsesBeforeAuditRelease(t)
	f.assertCountersAndHealth(t)
	if f.nextCalls.Load() != 1 {
		t.Fatal("rejected request bypassed the one admitted-handler slot")
	}
	f.auditGate.unblock()
	if err := <-f.seedDone; err != nil {
		t.Fatal("original held audit write failed after its gate opened")
	}
}
