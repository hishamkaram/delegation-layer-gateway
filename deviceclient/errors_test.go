package deviceclient

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
)

func TestIsBusyRequiresOnlyKnownContentionCauses(t *testing.T) {
	fault := errors.New("private cleanup failure")
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"public-marker", ErrBusy, true},
		{"wrapped-marker", fmt.Errorf("operation: %w", ErrBusy), true},
		{"profile-lease", failed(ErrBusy, instance.ErrBusy), true},
		{"identity-lease", failed(ErrBusy, errors.Join(deviceidentity.ErrBusy, instance.ErrBusy)), true},
		{"private-marker-alone", instance.ErrBusy, false},
		{"unrelated-fault", fault, false},
		{"profile-close-fault", failed(ErrBusy, errors.Join(instance.ErrBusy, fault)), false},
		{"identity-close-fault", failed(ErrBusy, errors.Join(deviceidentity.ErrBusy, instance.ErrBusy, fault)), false},
		{"outer-cleanup-fault", errors.Join(failed(ErrBusy, instance.ErrBusy), fault), false},
		{"other-sdk-kind", errors.Join(ErrBusy, ErrPersistence), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := IsBusy(test.err); got != test.want {
				t.Fatalf("busy=%t, want %t", got, test.want)
			}
		})
	}
}

func TestIdentityBusyObservationDoesNotHideCleanupFailure(t *testing.T) {
	busy := errors.Join(deviceidentity.ErrBusy, instance.ErrBusy)
	if !identityBusyOnly(busy) {
		t.Fatal("known identity contention became a failure")
	}
	if identityBusyOnly(errors.Join(busy, errors.New("private close failure"))) {
		t.Fatal("identity observation hid cleanup failure")
	}
	if identityBusyOnly(ErrBusy) {
		t.Fatal("SDK profile contention became identity contention")
	}
}
