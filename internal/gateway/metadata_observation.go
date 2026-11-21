package gateway

import (
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// MetadataSource identifies the exact observation source. It is immutable
// evidence for a current-authority recheck, never a grant or a cached decision.
type MetadataSource struct {
	Binding   domain.OwnedRootBinding
	Operation protocol.Operation
}

func (s MetadataSource) Validate() error {
	if s.Binding.Validate() != nil || s.Operation.ValidateVersion(protocol.WireVersion2) != nil {
		return domain.ErrInvalid
	}
	return nil
}

// MetadataObservation carries a typed value and its original source across
// service boundaries. Consumers retain Source until their final output gate.
type MetadataObservation[T any] struct {
	Value  T
	Source MetadataSource
}
