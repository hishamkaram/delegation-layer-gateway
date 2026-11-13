// Package httpguard owns bounded public HTTP admission. TLS socket ownership and
// token verification remain with server composition and the identity adapter.
package httpguard

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid HTTP guard configuration")

type Rejection string

const (
	OriginRejected   Rejection = "origin_rejected"
	CapacityRejected Rejection = "capacity_rejected"
)

type Options struct {
	// Rejected runs outside admission. It must be nonblocking and perform no I/O.
	Rejected           func(Rejection)
	PublicOrigin       string
	ConcurrentRequests int
	Timeout            time.Duration
	MaxBodyBytes       int64
}

// Guard owns the only active-request semaphore, released after the handler
// returns rather than when its client disconnects or its deadline expires.
type Guard struct {
	rejected func(Rejection)
	origin   *url.URL
	active   chan struct{}
	timeout  time.Duration
	maxBody  int64
}

func New(options Options) (*Guard, error) {
	origin, err := url.Parse(options.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return nil, ErrInvalid
	}
	if options.ConcurrentRequests < 1 || options.ConcurrentRequests > 128 || options.Timeout <= 0 || options.MaxBodyBytes < 1 || options.MaxBodyBytes > 1<<20 {
		return nil, ErrInvalid
	}
	return &Guard{origin: origin, active: make(chan struct{}, options.ConcurrentRequests), timeout: options.Timeout, maxBody: options.MaxBodyBytes, rejected: options.Rejected}, nil
}

func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || !strings.EqualFold(request.Host, g.origin.Host) || !g.allowedOrigin(request.Header.Values("Origin")) {
			g.observeRejection(OriginRejected)
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		select {
		case g.active <- struct{}{}:
			defer func() { <-g.active }()
		default:
			g.observeRejection(CapacityRejected)
			writer.Header().Set("Retry-After", "1")
			http.Error(writer, "resource_limit", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), g.timeout)
		defer cancel()
		request = request.WithContext(ctx)
		request.Body = http.MaxBytesReader(writer, request.Body, g.maxBody)
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func (g *Guard) observeRejection(reason Rejection) {
	// Rejection must remain fast even when admitted request storage is stalled.
	if g.rejected != nil {
		g.rejected(reason)
	}
}

func (g *Guard) allowedOrigin(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	origin, err := url.Parse(values[0])
	return err == nil && origin.Scheme == g.origin.Scheme && strings.EqualFold(origin.Host, g.origin.Host) && origin.Path == "" && origin.User == nil && origin.RawQuery == "" && origin.Fragment == ""
}
