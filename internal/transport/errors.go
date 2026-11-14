// Package transport owns bounded wire sessions, never Delegate task state.
package transport

import "errors"

var (
	ErrNoSession = errors.New("device_offline_no_session")
	ErrNotReady  = errors.New("device_not_ready")
	ErrOffline   = errors.New("device_offline")
	ErrProtocol  = errors.New("protocol_error")
	ErrCapacity  = errors.New("resource_limit")
	ErrConflict  = errors.New("conflict")
	ErrExpired   = errors.New("expired")
	ErrForbidden = errors.New("forbidden")
)

// Error formats only a fixed classification; native details are caller-only.
type Error struct {
	kind  error
	cause error
}

func (e *Error) Error() string { return e.kind.Error() }
func (e *Error) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}
func fail(kind, errorCause error) error { return &Error{kind: kind, cause: errorCause} }

// NewError preserves a transport classification and a non-public cause.
func NewError(kind, cause error) error {
	for _, known := range []error{ErrNoSession, ErrNotReady, ErrOffline, ErrProtocol, ErrCapacity, ErrConflict, ErrExpired, ErrForbidden} {
		if errors.Is(kind, known) {
			return fail(known, cause)
		}
	}
	return fail(ErrProtocol, errors.Join(kind, cause))
}
