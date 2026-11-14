package devicehub

import (
	"errors"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestWireV2RequiresOwnedCredentialAuthorityAtConstruction(t *testing.T) {
	f := newFixture(t, Settings{})
	_, err := NewHub(t.Context(), Config{GatewayID: "gateway-one", BootEpoch: "other-boot", EnableWireV2: true}, f.store, f.clock.now)
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("v2 constructor accepted a store without required ownership authority", err)
	}
}
