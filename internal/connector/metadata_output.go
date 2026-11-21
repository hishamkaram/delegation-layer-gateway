package connector

import (
	"context"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// The profile owner serializes approval changes; Adapter owns replacement of
// that owner through config generations. Both must still match at publication.
// Profile -> Adapter lock order matches CLI Start. No callback or Wait runs
// under Adapter.mu, and Native controls have already joined before this call.
func (a *Adapter) publishMetadata(ctx context.Context, r request, value any) protocol.Reply {
	reply := bodyReply(r.command.Operation, value)
	if reply.Error != nil {
		return reply
	}
	if a.Generation() != r.config.generation {
		return failed(r.command.Operation, ErrConflict)
	}
	release, err := r.metadataOutputGuard(ctx)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	a.mu.RLock()
	// This check is the output linearization point. The profile lease still
	// excludes revocation; Reload cannot replace its owner during this check.
	current := a.config.generation == r.config.generation
	a.mu.RUnlock()
	closeErr := release()
	if !current {
		return failed(r.command.Operation, errors.Join(ErrConflict, closeErr))
	}
	if closeErr != nil {
		return failed(r.command.Operation, closeErr)
	}
	return reply
}

func (r request) metadataOutputGuard(ctx context.Context) (func() error, error) {
	if r.filesystem != nil {
		return r.filesystemStartGuard(ctx)
	}
	if r.scoped != nil {
		return r.scopedStartGuard(ctx)
	}
	return nil, ErrEvidence
}
