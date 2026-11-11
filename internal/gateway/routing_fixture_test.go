package gateway

import (
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (f *dispatchFixture) reconcileRouting(t *testing.T) {
	t.Helper()
	generation := f.link.snapshot.Connection
	report := protocol.ControlInventory{PolicyVersion: 1, ProcessBoot: f.link.snapshot.ProcessBoot, BarrierID: strings.Repeat("a", 32), Generation: protocol.Generation{BootEpoch: string(generation.BootEpoch), Counter: generation.Counter}, Complete: true}
	status, err := f.store.ReconcileRouting(t.Context(), f.link.snapshot.Credential, report, f.now)
	if !dispatchMust(t, status, err).Ready {
		t.Fatal("fixture routing handshake blocked")
	}
}
