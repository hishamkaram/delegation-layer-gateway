package adminapi

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestAdministrativeSummaryBoundAndDetailedReceiptPrecision(t *testing.T) {
	key := TaskKey{DeviceID: strings.Repeat("d", 128), RootGuard: "ctx1_" + strings.Repeat("a", 64), TaskID: strings.Repeat("b", 32)}
	when := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	summary := AdministrativeTaskSummary{Key: key, Attributed: true, OperationID: strings.Repeat("o", 128), Delivery: domain.Resolved, CancellationID: strings.Repeat("c", 32), SpecSHA256: strings.Repeat("e", 64), ObservationKind: domain.Terminal, ObservedAt: &when}
	if summary.Validate() != nil {
		t.Fatal("maximum summary fixture invalid")
	}
	page := AdministrativeTaskPage{Items: make([]AdministrativeTaskSummary, maxAdministrativePageItems), Next: &key}
	for i := range page.Items {
		page.Items[i] = summary
	}
	encoded, err := json.Marshal(page)
	if err != nil || len(encoded) > MaxResponseBytes {
		t.Fatal("bounded summary page exceeds CLI response limit")
	}
	detail := AdministrativeTask{Key: key, Attributed: true, OriginalProjectAlias: strings.Repeat("p", 128), ProjectGuard: "ctx1_" + strings.Repeat("f", 64), Origin: protocol.Origin{GatewayID: strings.Repeat("g", 128), AdmissionGeneration: strings.Repeat("n", 128), OperationID: summary.OperationID, PrincipalRef: strings.Repeat("u", 128), RequestSHA256: strings.Repeat("1", 64)}, SpecSHA256: summary.SpecSHA256, Delivery: domain.PossibleSend, Reserved: true, Receipt: &TaskReceipt{BriefSHA256: strings.Repeat("2", 64), Provider: strings.Repeat("v", 128), Permission: domain.ReadOnly, BudgetNanoseconds: math.MaxInt64, Model: protocol.Selection{Kind: "explicit", Value: strings.Repeat("<", 256)}, Effort: protocol.Selection{Kind: "explicit", Value: strings.Repeat("<", 256)}}}
	if detail.Validate() != nil {
		t.Fatal("maximum detail fixture invalid")
	}
	encoded, err = json.Marshal(detail)
	if err != nil || len(encoded) > MaxResponseBytes {
		t.Fatal("detailed task exceeds response limit")
	}
	var decoded AdministrativeTask
	if json.Unmarshal(encoded, &decoded) != nil || decoded.Receipt == nil || decoded.Receipt.BudgetNanoseconds != math.MaxInt64 {
		t.Fatal("native historical budget rounded in administrative output")
	}
}

func TestOversizedMetadataFailsWithoutChangingCursor(t *testing.T) {
	cursor := &RecoveryCursor{DeviceID: "device", RootGuard: "ctx1_" + strings.Repeat("a", 64)}
	page := RecoveryProgress{Next: cursor, Destinations: []RecoveryDestination{{Generation: strings.Repeat("x", MaxResponseBytes+1)}}}
	got, err := boundedMetadata(page)
	var classified *domain.Error
	if !errors.As(err, &classified) || classified.Code != domain.ResourceLimit || got.Next != cursor {
		t.Fatal("oversized metadata truncated a page or changed its cursor")
	}
}
