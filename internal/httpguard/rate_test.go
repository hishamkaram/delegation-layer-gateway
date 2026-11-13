package httpguard

import (
	"sync"
	"testing"
	"time"
)

func TestBoundedRatesDoNotResetActiveIdentity(t *testing.T) {
	now := time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)
	limits, err := NewRateLimits(1, 2, 1, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, second, third := limits.Allow("one"), limits.Allow("one"), limits.Allow("one")
	if !first || !second || third {
		t.Fatal("burst was not enforced")
	}
	if limits.Allow("two") || limits.Allow("one") {
		t.Fatal("capacity pressure reset a live bucket")
	}
	now = now.Add(time.Second)
	if !limits.Allow("one") || limits.Allow("one") {
		t.Fatal("refill bound changed")
	}
	now = now.Add(time.Minute)
	if !limits.Allow("two") {
		t.Fatal("idle identity was not evicted")
	}
}

func TestRateConcurrentCallersShareOneBurst(t *testing.T) {
	now := time.Now()
	limits, err := NewRateLimits(1, 20, 100, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan bool, 100)
	var callers sync.WaitGroup
	for range 100 {
		callers.Go(func() { results <- limits.Allow("same") })
	}
	callers.Wait()
	close(results)
	accepted := 0
	for result := range results {
		if result {
			accepted++
		}
	}
	if accepted != 20 {
		t.Fatalf("concurrent burst=%d, want20", accepted)
	}
}
