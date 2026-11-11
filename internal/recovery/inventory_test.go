package recovery

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestInventoryMappingPreservesPrecisionAndHonestEvidence(t *testing.T) {
	report, plan, transmission := inventoryFixture()
	now := time.Unix(100, 0)
	page, err := inventoryPage(report, plan, "", "gateway", transmission, now)
	if err != nil {
		t.Fatal(err)
	}
	requireInventoryEnvelope(t, page, transmission)
	requireExistingInventoryReceipt(t, page.Entries[0], now)
	refused := page.Entries[1]
	if refused.Existing != nil || refused.Refusal == nil || refused.Refusal.Origin != nil || refused.Refusal.Task != domain.TaskID(strings.Repeat("b", 32)) {
		t.Fatal("unattributed refusal fabricated receipt or origin")
	}
}

func requireInventoryEnvelope(t *testing.T, page domain.ImportedInventoryPage, transmission domain.Transmission) {
	t.Helper()
	if len(page.Entries) != 2 || page.Credential != transmission.Credential || page.Connection != transmission.Connection || page.CompletenessReceipt == nil || page.NextCursor != "" {
		t.Fatal("canonical page or authenticated connection changed")
	}
}

func requireExistingInventoryReceipt(t *testing.T, entry domain.ImportedInventoryEntry, now time.Time) {
	t.Helper()
	existing := entry.Existing
	if existing == nil || entry.Refusal != nil || existing.Receipt.Options.BudgetNanoseconds != math.MaxInt64 || existing.Receipt.Options.Effort != (domain.Selection{Kind: domain.Explicit, Value: "high"}) {
		t.Fatal("native receipt precision or selection changed")
	}
	if existing.Observation.Kind != domain.Existing || existing.Observation.ObservedAt != now || existing.Observation.Closure != nil || existing.Observation.Result != nil {
		t.Fatal("inventory presence fabricated an outcome or closure")
	}
}

func TestInventoryMappingRejectsForeignAndMalformedEvidence(t *testing.T) {
	for _, test := range []string{"root", "gateway", "device", "connection", "receipt-spec", "unbound-completeness"} {
		t.Run(test, func(t *testing.T) {
			report, plan, transmission := inventoryFixture()
			switch test {
			case "root":
				plan.Destination.Root = domain.RootGuard(protocol.WireContextGuard("another-root"))
			case "gateway":
				report.Entries[0].Origin.GatewayID = "foreign"
			case "device":
				transmission.Credential.Device = "another-device"
			case "connection":
				transmission.Connection.Counter = 0
			case "receipt-spec":
				report.Entries[0].Receipt.Task.SpecSHA256 = strings.Repeat("f", 64)
			case "unbound-completeness":
				report.Complete = false
			}
			if _, err := inventoryPage(report, plan, "", "gateway", transmission, time.Unix(100, 0)); err == nil {
				t.Fatal("invalid evidence yielded an applicable page")
			}
		})
	}
}

func inventoryFixture() (protocol.OriginInventoryReport, domain.BarrierPlan, domain.Transmission) {
	root := protocol.WireContextGuard("root")
	origin := protocol.Origin{GatewayID: "gateway", AdmissionGeneration: "historical", OperationID: "operation", PrincipalRef: "principal", RequestSHA256: strings.Repeat("1", 64)}
	receipt := &protocol.InventoryReceipt{Task: protocol.TaskBinding{TaskID: strings.Repeat("a", 32), Context: protocol.ContextBinding{Root: root, Project: protocol.WireContextGuard("project")}, Origin: origin, SpecSHA256: strings.Repeat("2", 64)}, BriefSHA256: strings.Repeat("3", 64), ExecutionOptions: protocol.InventoryExecutionOptions{Provider: "provider", Permission: "read-only", BudgetNanoseconds: math.MaxInt64, Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "explicit", Value: "high"}}}
	report := protocol.OriginInventoryReport{Entries: []protocol.OriginInventoryEntry{
		{TaskID: receipt.Task.TaskID, Resolution: "existing", Origin: &origin, SpecSHA256: receipt.Task.SpecSHA256, BriefSHA256: receipt.BriefSHA256, Receipt: receipt},
		{TaskID: strings.Repeat("b", 32), Resolution: "permanently_refused"},
	}, Complete: true, MembershipSHA256: strings.Repeat("4", 64), CompletenessReceipt: strings.Repeat("5", 64)}
	plan := domain.BarrierPlan{Destination: domain.RecoveryDestination{Recovery: "restore", Device: "device", Root: domain.RootGuard(root)}, Generation: "current"}
	transmission := domain.Transmission{Credential: domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 1}, Connection: domain.ConnectionGeneration{BootEpoch: "boot", Counter: 1}}
	return report, plan, transmission
}
