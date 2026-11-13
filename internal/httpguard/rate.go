package httpguard

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimits owns a bounded set of independently rate-limited identities.
// Idle eviction is explicit; active buckets are never silently reset on pressure.
type RateLimits struct {
	mu      sync.Mutex
	entries map[string]*bucket
	limit   rate.Limit
	burst   int
	maximum int
	idle    time.Duration
	now     func() time.Time
}
type bucket struct {
	limiter *rate.Limiter
	seen    time.Time
}

func NewRateLimits(perSecond, burst, maximum int, idle time.Duration, now func() time.Time) (*RateLimits, error) {
	if perSecond < 1 || burst < 1 || maximum < 1 || maximum > 65536 || idle <= 0 || now == nil {
		return nil, ErrInvalid
	}
	return &RateLimits{entries: make(map[string]*bucket), limit: rate.Limit(perSecond), burst: burst, maximum: maximum, idle: idle, now: now}, nil
}

func (l *RateLimits) Allow(identity string) bool {
	if identity == "" || len(identity) > 256 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, ok := l.entries[identity]
	if !ok {
		if len(l.entries) >= l.maximum {
			l.evictIdle(now)
		}
		if len(l.entries) >= l.maximum {
			return false
		}
		entry = &bucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[identity] = entry
	}
	entry.seen = now
	return entry.limiter.AllowN(now, 1)
}

func (l *RateLimits) evictIdle(now time.Time) {
	for key, entry := range l.entries {
		if now.Sub(entry.seen) >= l.idle {
			delete(l.entries, key)
		}
	}
}
