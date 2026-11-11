package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func privateDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAuditDurabilityPrivacyAndLease(t *testing.T) {
	dir := privateDirectory(t)
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	a, err := Open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, openErr := Open(dir, func() time.Time { return now }); openErr == nil {
		if closeErr := duplicate.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("two directory owners")
	}
	event := Event{Code: OperationPrepared, Device: "device1", Operation: "operation1"}
	if err = a.Record(event); err != nil {
		t.Fatal(err)
	}
	if err = a.Record(Event{Code: Code("private prompt canary")}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unclosed event accepted: %v", err)
	}
	if err = a.Record(Event{Code: ControlUnknown, Device: "secret/path"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("path metadata accepted")
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	assertPersistedEvent(t, dir, event, now)
	b, err := Open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	if err = a.Record(event); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed owner wrote record")
	}
}

func TestAuditRetentionAndTotalBound(t *testing.T) {
	dir := privateDirectory(t)
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for i := range 10 {
		file, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("audit-20261109-%02d.jsonl", i)), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err = file.Truncate(SegmentBytes); err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(dir, "audit-20261103-00.jsonl")
	if err := os.WriteFile(old, []byte("expired\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	if err = a.Record(Event{Code: ShutdownStarted}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired segment retained")
	}
	if _, err = os.Stat(filepath.Join(dir, "audit-20261109-00.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oldest full segment retained past total limit")
	}
	segments, err := a.segments()
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, segment := range segments {
		total += segment.size
	}
	if total > MaxAuditBytes {
		t.Fatalf("total %d", total)
	}
}

func TestAuditRejectsSymlinksAndUnsafeStorage(t *testing.T) {
	now := func() time.Time { return time.Now() }
	dir := privateDirectory(t)
	outside := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(outside, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "audit-20261110-00.jsonl")); err != nil {
		t.Fatal(err)
	}
	if owner, err := Open(dir, now); err == nil {
		if closeErr := owner.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("symlink accepted")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "do not touch" {
		t.Fatal("foreign data changed")
	}
	unsafe := privateDirectory(t)
	if err := os.Chmod(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if owner, err := Open(unsafe, now); err == nil {
		if closeErr := owner.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("public directory accepted")
	}
}

func TestConcurrentAuditAndFixedMetrics(t *testing.T) {
	a, err := Open(privateDirectory(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	var metrics Metrics
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 10 {
				if recordErr := a.Record(Event{Code: ControlCompleted}); recordErr != nil {
					t.Error(recordErr)
				}
				if metricErr := metrics.Record(ControlCompleted); metricErr != nil {
					t.Error(metricErr)
				}
			}
		})
	}
	workers.Wait()
	if err = metrics.Record(Code("secret_canary")); err == nil {
		t.Fatal("unbounded label accepted")
	}
	metrics.AuditFailed()
	out := httptest.NewRecorder()
	metrics.ServeHTTP(out, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(out.Body.String(), "gateway_events_total{event=\"control_completed\"} 80\n") || !strings.Contains(out.Body.String(), "gateway_audit_failures_total 1\n") || strings.Contains(out.Body.String(), "canary") {
		t.Fatal(out.Body.String())
	}
}

func assertPersistedEvent(t *testing.T, dir string, event Event, now time.Time) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "audit-20261110-00.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("canary")) || bytes.Count(data, []byte("\n")) != 1 {
		t.Fatalf("unexpected persisted records: %q", data)
	}
	var decoded record
	if err = json.Unmarshal(data, &decoded); err != nil || decoded.Event != event || !decoded.At.Equal(now) {
		t.Fatalf("record: %+v %v", decoded, err)
	}
	info, err := os.Stat(filepath.Join(dir, "audit-20261110-00.jsonl"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("audit permissions")
	}
}
