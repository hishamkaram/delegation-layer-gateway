package mcpadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestSentinelClassificationsRequireSoleCause(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want ToolError
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: ToolError{Code: "timeout", Retryable: true}},
		{name: "canceled", err: context.Canceled, want: ToolError{Code: "timeout", Retryable: true}},
		{name: "domain-invalid", err: domain.ErrInvalid, want: ToolError{Code: "invalid_request"}},
		{name: "protocol-invalid", err: protocol.ErrInvalid, want: ToolError{Code: "invalid_request"}},
		{name: "oversize", err: protocol.ErrTooLarge, want: ToolError{Code: "resource_limit"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, single := range []error{test.err, errors.Join(test.err, nil)} {
				if got := classify(single); *got != test.want {
					t.Fatalf("sole sentinel classified %+v, want %+v", got, test.want)
				}
			}
			for _, uncertain := range []error{errors.Join(test.err, errors.New(privateCanary)), fmt.Errorf("%s: %w", privateCanary, test.err)} {
				if got := classify(uncertain); *got != (ToolError{Code: "internal_error"}) {
					t.Fatalf("uncertain cause inferred known failure: %+v", got)
				}
			}
		})
	}
}

func TestSDKResolutionMixedSentinelsHideStorageDetailsAndRetainIdentity(t *testing.T) {
	backend := &workspaceBackend{}
	f := newConfiguredFixture(t, 0, nil, func(options *Options) { options.Workspaces = backend })
	session := f.session(t, "dispatch")
	input := ResolveProjectInput{DeviceID: "device-one", RequestID: strings.Repeat("e", 32), WorkspaceID: "code", RelativePath: "repo"}
	for _, sentinel := range []error{context.DeadlineExceeded, context.Canceled, domain.ErrInvalid, protocol.ErrInvalid, protocol.ErrTooLarge} {
		backend.failure = errors.Join(sentinel, errors.New(privateCanary))
		result := f.call(t, session, "resolve_project", args(t, input))
		expectError[ResolvedProject](t, result, "internal_error")
		failure := decodeResult[ResolvedProject](t, result).Error
		if failure.RequestID != input.RequestID || failure.Retryable {
			t.Fatal("mixed cause changed retained identity or inferred retry safety")
		}
		assertPublic(t, result)
	}
}
