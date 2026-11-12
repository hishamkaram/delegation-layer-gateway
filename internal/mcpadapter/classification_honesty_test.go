package mcpadapter

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type projectedClassificationError struct {
	policy *domain.Error
	remote *gateway.RemoteError
}

func (projectedClassificationError) Error() string { return privateCanary }

func (e projectedClassificationError) As(target any) bool {
	switch value := target.(type) {
	case **domain.Error:
		*value = e.policy
		return e.policy != nil
	case **gateway.RemoteError:
		*value = e.remote
		return e.remote != nil
	default:
		return false
	}
}

func TestClassifyKnownFailuresRequiresSoleCause(t *testing.T) {
	policy := &domain.Error{Code: domain.NotFound}
	remote := &gateway.RemoteError{Failure: protocol.Failure{Code: "device_offline", Retryable: true}}
	storage := errors.New(privateCanary)
	var nilPolicy *domain.Error
	var nilRemote *gateway.RemoteError
	for _, test := range []struct {
		name string
		err  error
		want ToolError
	}{
		{name: "policy", err: policy, want: ToolError{Code: "not_found"}},
		{name: "pending-policy", err: domain.Reject(domain.Pending), want: ToolError{Code: "pending", Retryable: true}},
		{name: "single-join-policy", err: errors.Join(policy, nil), want: ToolError{Code: "not_found"}},
		{name: "remote", err: remote, want: ToolError{Code: "device_offline", Retryable: true}},
		{name: "single-join-remote", err: errors.Join(remote, nil), want: ToolError{Code: "device_offline", Retryable: true}},
		{name: "mixed-policy-storage", err: errors.Join(policy, storage), want: ToolError{Code: "internal_error"}},
		{name: "mixed-remote-storage", err: errors.Join(remote, storage), want: ToolError{Code: "internal_error"}},
		{name: "wrapped-policy", err: fmt.Errorf("%s: %w", privateCanary, policy), want: ToolError{Code: "internal_error"}},
		{name: "wrapped-remote", err: fmt.Errorf("%s: %w", privateCanary, remote), want: ToolError{Code: "internal_error"}},
		{name: "custom-policy-projection", err: projectedClassificationError{policy: policy}, want: ToolError{Code: "internal_error"}},
		{name: "custom-remote-projection", err: projectedClassificationError{remote: remote}, want: ToolError{Code: "internal_error"}},
		{name: "nil-policy", err: nilPolicy, want: ToolError{Code: "internal_error"}},
		{name: "nil-remote", err: nilRemote, want: ToolError{Code: "internal_error"}},
		{name: "timeout-priority", err: errors.Join(policy, context.DeadlineExceeded), want: ToolError{Code: "timeout", Retryable: true}},
		{name: "canceled-priority", err: errors.Join(remote, context.Canceled), want: ToolError{Code: "timeout", Retryable: true}},
		{name: "invalid-priority", err: errors.Join(policy, domain.ErrInvalid), want: ToolError{Code: "invalid_request"}},
		{name: "oversize-priority", err: errors.Join(remote, protocol.ErrTooLarge), want: ToolError{Code: "resource_limit"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Fatal("public classification panicked on a typed nil error")
				}
			}()
			got := classify(test.err)
			if got == nil || *got != test.want {
				t.Fatalf("public classification=%+v, want %+v", got, test.want)
			}
		})
	}
}
