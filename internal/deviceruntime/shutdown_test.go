package deviceruntime

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
)

func TestExpectedCancellationRejectsIndependentFaults(t *testing.T) {
	fault := errors.New("independent shutdown fault")
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "cancel", err: context.Canceled, want: true},
		{name: "deadline", err: context.DeadlineExceeded, want: true},
		{name: "cancellation-joins", err: errors.Join(context.Canceled, context.DeadlineExceeded), want: true},
		{name: "connection-label", err: failed(ErrConnection, context.Canceled), want: true},
		{name: "renewal-label", err: failed(ErrRenewal, errors.Join(context.Canceled, nil)), want: true},
		{name: "configuration-label", err: failed(ErrConfiguration, context.Canceled)},
		{name: "cleanup", err: errors.Join(context.Canceled, ErrCleanup)},
		{name: "mixed-fault", err: errors.Join(context.Canceled, fault)},
		{name: "labeled-mixed-fault", err: failed(ErrConnection, errors.Join(context.Canceled, fault))},
		{name: "mixed-label", err: failed(errors.Join(ErrConnection, fault), context.Canceled)},
		{name: "bare-label", err: errors.Join(context.Canceled, ErrConnection)},
		{name: "ordinary-wrapper", err: fmt.Errorf("observer: %w", context.Canceled)},
		{name: "nil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := IsExpectedCancellation(test.err); got != test.want {
				t.Fatal("cancellation qualification changed an independent cause", got, test.want)
			}
		})
	}
}

func TestConnectionCancellationPreservesCloseAndWorkerFaults(t *testing.T) {
	fault := errors.New("close failed after cancellation")
	for _, marker := range []error{context.Canceled, connector.ErrPending} {
		original := errors.Join(marker, fault)
		forwarded := connectionFailure(original, true)
		if !errors.Is(forwarded, original) || !errors.Is(forwarded, fault) || IsExpectedCancellation(forwarded) {
			t.Fatal("cancellation suppressed a connection diagnostic")
		}
	}
}

func TestConnectionWorkerJoinsIgnoreOnlyPureExpectedEnds(t *testing.T) {
	fault := errors.New("worker cleanup failure")
	for _, test := range []struct {
		name      string
		attached  error
		renewed   error
		wantFault bool
	}{
		{name: "normal", attached: connector.ErrPending, renewed: context.Canceled},
		{name: "sole-joins", attached: errors.Join(connector.ErrPending, nil), renewed: failed(ErrRenewal, context.Canceled)},
		{name: "mixed-intake", attached: errors.Join(connector.ErrPending, fault), renewed: context.Canceled, wantFault: true},
		{name: "mixed-intake-cancel", attached: errors.Join(context.Canceled, fault), renewed: context.Canceled, wantFault: true},
		{name: "mixed-renewal", attached: connector.ErrPending, renewed: errors.Join(context.Canceled, fault), wantFault: true},
		{name: "labeled-mixed-renewal", attached: connector.ErrPending, renewed: failed(ErrRenewal, errors.Join(context.Canceled, fault)), wantFault: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			attached := make(chan error, 1)
			renewed := make(chan error, 1)
			attached <- test.attached
			renewed <- test.renewed
			actual := joinConnectionWorkers(attached, renewed, false, false)
			if test.wantFault {
				if !errors.Is(actual, fault) || IsExpectedCancellation(actual) {
					t.Fatal("joining an interrupted worker suppressed an independent fault")
				}
			} else if actual != nil {
				t.Fatal("normal worker end became a cleanup fault", actual)
			}
		})
	}
}
