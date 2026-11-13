package deviceruntime

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
)

// IsExpectedCancellation recognizes only cancellation leaves and this owner's
// connection/renewal labels over such causes. Independent cleanup, storage,
// configuration and opaque wrapper errors remain failures. It proves no task
// closure; the caller must separately join its owners and close identity.
func IsExpectedCancellation(err error) bool {
	if labeled, ok := err.(interface{ cancellationCause() (error, bool) }); ok {
		cause, eligible := labeled.cancellationCause()
		return eligible && IsExpectedCancellation(cause)
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !IsExpectedCancellation(cause) {
				return false
			}
		}
		return true
	}
	return plainMarker(err, context.Canceled, context.DeadlineExceeded)
}

// Only the producer can distinguish its fixed observation label from an
// independent error. Never strip labels inferred through errors.As or Is.
func (e failure) cancellationCause() (error, bool) {
	return e.cause, plainMarker(e.kind, ErrConnection, ErrRenewal)
}

// Cancellation changes the observation label, never whether a close/worker
// diagnostic survives. The original graph remains intact during shutdown.
func connectionFailure(err error, stopped bool) error {
	if err == nil || stopped {
		return err
	}
	return failed(ErrConnection, err)
}

func onlyPending(err error) bool {
	for {
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok {
			return plainMarker(err, connector.ErrPending)
		}
		causes := joined.Unwrap()
		if len(causes) != 1 {
			return false
		}
		err = causes[0]
	}
}

func plainMarker(err error, markers ...error) bool {
	_, wrapped := err.(interface{ Unwrap() error })
	_, joined := err.(interface{ Unwrap() []error })
	_, projected := err.(interface{ Is(error) bool })
	if wrapped || joined || projected {
		return false
	}
	for _, marker := range markers {
		if errors.Is(err, marker) {
			return true
		}
	}
	return false
}
