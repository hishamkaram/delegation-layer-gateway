package wirelink

import (
	"errors"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func TestProtectedOversizePreservesPermanentSizeClassification(t *testing.T) {
	for _, cause := range []error{protocol.ErrTooLarge, transport.NewError(transport.ErrProtocol, protocol.ErrTooLarge)} {
		if err := publicError(cause); !errors.Is(err, protocol.ErrTooLarge) {
			t.Fatalf("permanent size error lost its public classification: %v", err)
		}
	}
	var remote *gateway.RemoteError
	if err := publicError(transport.ErrCapacity); !errors.As(err, &remote) || remote.Failure.Code != "resource_limit" || !remote.Failure.Retryable {
		t.Fatalf("ordinary queue pressure lost retryability: %v", err)
	}
}
