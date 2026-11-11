package registry

import (
	"database/sql"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func TestRoutingPermitPagesKeepStableMetadataCursorDuringRelease(t *testing.T) {
	f := newFixture(t)
	// A restored image may retain controls above normal admission bounds. This
	// fixture inserts their metadata only and starts no CLI or provider process.
	_, err := transaction(t.Context(), f.store, func(tx *sql.Tx) (struct{}, error) {
		for number := 1; number <= 101; number++ {
			if err := insertRoutingPermit(t.Context(), tx, routingRequest(t, f, protocol.ContextInspect, number)); err != nil {
				return struct{}{}, err
			}
		}
		return struct{}{}, nil
	})
	requireOK(t, err)
	first, err := f.store.ListRoutingPermits(t.Context(), routing.PermitPageRequest{Limit: 100})
	page := must(t, first, err)
	if len(page.Items) != 100 || page.Next == nil || page.Next.Request != page.Items[99].Call.RequestID {
		t.Fatal("permit cursor did not identify the final returned item")
	}
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE routing_permits SET state='settled' WHERE request=?", page.Items[0].Call.RequestID)
	requireOK(t, err)
	second, err := f.store.ListRoutingPermits(t.Context(), routing.PermitPageRequest{Limit: 100, After: page.Next})
	tail := must(t, second, err)
	if len(tail.Items) != 1 || tail.Next != nil {
		t.Fatal("release before the cursor skipped or duplicated pending permits")
	}
	for _, prior := range page.Items {
		if prior.Call == tail.Items[0].Call {
			t.Fatal("sentinel permit was repeated on the next page")
		}
	}
	f.store.admin = nil
	_, err = f.store.ListRoutingPermits(t.Context(), routing.PermitPageRequest{Limit: 100})
	requireCode(t, err, domain.Forbidden)
}
