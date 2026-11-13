package connector

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func inventoryRequestFixture() request {
	project := Project{RootToken: strings.Repeat("a", 64), ProjectToken: "query-project-token"}
	return request{project: project, config: &configuration{GatewayID: "gateway-one"}, command: protocol.Command{Operation: protocol.OriginInventory}, inventory: &protocol.OriginInventoryRequest{GatewayID: "gateway-one", Generation: "restore-generation", Limit: 100, ExpectedRoot: project.wireContext().Root}}
}

func localInventoryEntry(id, project string) inventoryEntry {
	origin := protocol.Origin{GatewayID: "gateway-one", AdmissionGeneration: "generation-old", OperationID: "operation-one", PrincipalRef: "principal-one", RequestSHA256: strings.Repeat("b", 64)}
	receipt := &cliReceipt{RootToken: strings.Repeat("a", 64), ProjectToken: project, TaskID: strings.Repeat(id, 32), Origin: origin, SpecSHA256: strings.Repeat("c", 64), BriefSHA256: strings.Repeat("d", 64), ExecutionOptions: executionOptions{Provider: "codex", Permission: "read-only", BudgetNanoseconds: 1_000_000_001, Model: protocol.Selection{Kind: "native_default"}, Effort: protocol.Selection{Kind: "explicit", Value: "high"}}}
	return inventoryEntry{TaskID: receipt.TaskID, Resolution: "existing", Origin: &origin, SpecSHA256: receipt.SpecSHA256, BriefSHA256: receipt.BriefSHA256, Receipt: receipt}
}

func localInventory(entries ...inventoryEntry) *cliInventory {
	return &cliInventory{Entries: entries, Complete: true, MembershipSHA256: strings.Repeat("e", 64), CompletenessReceipt: strings.Repeat("f", 64)}
}

func TestInventoryNormalizesEachFrozenProjectWithoutQueryAttributionOrLeaks(t *testing.T) {
	r := inventoryRequestFixture()
	oldPath := "/private/canary/removed-project"
	oldToken := base64.RawURLEncoding.EncodeToString([]byte(oldPath))
	otherToken := "different-frozen-project-token"
	local := localInventory(localInventoryEntry("1", oldToken), localInventoryEntry("2", otherToken))
	response := cliResponse{Connector: &cliConnector{ContractVersion: 1, Features: []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}, RootToken: r.project.RootToken, Inventory: local}}
	reply := r.translateOrigin(response)
	if reply.Error != nil {
		t.Fatal("canonical multiproject inventory rejected")
	}
	var wire protocol.OriginInventoryReport
	if protocol.DecodeStrict(reply.Body, &wire, protocol.MaxFrameBytes) != nil || wire.ValidateFor(*r.inventory) != nil || len(wire.Entries) != 2 {
		t.Fatal("normalized inventory is not a valid public DTO")
	}
	for index, token := range []string{oldToken, otherToken} {
		receipt := wire.Entries[index].Receipt
		if receipt.Task.Context.Project != protocol.WireContextGuard(token) || receipt.Task.Context.Project == r.project.wireContext().Project || receipt.ExecutionOptions.BudgetNanoseconds != 1_000_000_001 {
			t.Fatal("historical frozen context or nanosecond budget changed")
		}
	}
	for _, secret := range []string{r.project.RootToken, r.project.ProjectToken, oldPath, oldToken, otherToken, "root_token", "project_token"} {
		if strings.Contains(string(reply.Body), secret) {
			t.Fatal("local CLI token/path escaped in wire inventory")
		}
	}
	// Inspect the direct normalized value, before a JSON round trip could hide
	// accidental pointer sharing with decoded local evidence.
	direct, normalizeErr := r.normalizeInventory(local)
	if normalizeErr != nil {
		t.Fatal(normalizeErr)
	}
	local.Entries[0].Origin.OperationID = "mutated-local"
	if direct.Entries[0].Origin.OperationID != "operation-one" {
		t.Fatal("wire inventory aliases mutable local origin")
	}
}

func TestInventoryRejectsMissingConflictingOrForeignCanonicalReceipt(t *testing.T) {
	for name, mutate := range map[string]func(*inventoryEntry){
		"missing":         func(e *inventoryEntry) { e.Receipt = nil },
		"task":            func(e *inventoryEntry) { e.Receipt.TaskID = strings.Repeat("2", 32) },
		"origin":          func(e *inventoryEntry) { e.Receipt.Origin.OperationID = "other" },
		"gateway":         func(e *inventoryEntry) { e.Origin.GatewayID = "foreign"; e.Receipt.Origin.GatewayID = "foreign" },
		"spec":            func(e *inventoryEntry) { e.Receipt.SpecSHA256 = strings.Repeat("f", 64) },
		"brief":           func(e *inventoryEntry) { e.Receipt.BriefSHA256 = strings.Repeat("f", 64) },
		"root":            func(e *inventoryEntry) { e.Receipt.RootToken = strings.Repeat("f", 64) },
		"empty-project":   func(e *inventoryEntry) { e.Receipt.ProjectToken = "" },
		"invalid-project": func(e *inventoryEntry) { e.Receipt.ProjectToken = "private\npath" },
		"invalid-options": func(e *inventoryEntry) { e.Receipt.ExecutionOptions.Model.Kind = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			r := inventoryRequestFixture()
			entry := localInventoryEntry("1", "historical-project")
			mutate(&entry)
			if _, normalizeErr := r.normalizeInventory(localInventory(entry)); normalizeErr == nil {
				t.Fatal("conflicting canonical inventory accepted")
			}
		})
	}
	r := inventoryRequestFixture()
	entry := localInventoryEntry("1", "historical-project")
	if _, normalizeErr := r.normalizeInventory(localInventory(entry, entry)); normalizeErr == nil {
		t.Fatal("duplicate task identity accepted")
	}
}

func TestInventoryRefusalsDoNotInventProjectOrRequireExistingReceipt(t *testing.T) {
	r := inventoryRequestFixture()
	refusal := inventoryEntry{TaskID: strings.Repeat("1", 32), Resolution: "permanently_refused"}
	withOrigin := localInventoryEntry("2", "unused").Origin
	wire, normalizeErr := r.normalizeInventory(localInventory(refusal, inventoryEntry{TaskID: strings.Repeat("2", 32), Resolution: "permanently_refused", Origin: withOrigin}))
	if normalizeErr != nil || len(wire.Entries) != 2 || wire.Entries[0].Receipt != nil || wire.Entries[0].Origin != nil || wire.Entries[1].Receipt != nil {
		t.Fatal("refusal acquired fabricated context or receipt")
	}
	refusal.Receipt = localInventoryEntry("1", "unused").Receipt
	if _, invalidErr := r.normalizeInventory(localInventory(refusal)); invalidErr == nil {
		t.Fatal("refusal claimed canonical existing receipt")
	}
}

func TestDecodePublicInventoryReceiptStrictlyBeforeNormalization(t *testing.T) {
	r := inventoryRequestFixture()
	entry := localInventoryEntry("1", "frozen-project")
	// Field names follow inspected Delegate taskdir.OriginInventoryEntry and
	// ConnectorReceipt; this explicit public envelope also catches DTO drift.
	fixture := `{"schema_version":1,"command":"origin","admission":"unknown","liveness":"unknown","publication":"unknown","connector":{"contract_version":1,"features":["namespace-admission-v1","namespace-mutation-lease-v1"],"root_token":"` + r.project.RootToken + `","inventory":{"entries":[{"task_id":"` + entry.TaskID + `","resolution":"existing","origin":ORIGIN,"spec_sha256":"` + entry.SpecSHA256 + `","brief_sha256":"` + entry.BriefSHA256 + `","receipt":RECEIPT}],"complete":true,"membership_sha256":"` + strings.Repeat("e", 64) + `","completeness_receipt":"` + strings.Repeat("f", 64) + `"}}}`
	origin, originErr := json.Marshal(entry.Origin)
	if originErr != nil {
		t.Fatal(originErr)
	}
	receipt, receiptErr := json.Marshal(entry.Receipt)
	if receiptErr != nil {
		t.Fatal(receiptErr)
	}
	fixture = strings.ReplaceAll(strings.ReplaceAll(fixture, "ORIGIN", string(origin)), "RECEIPT", string(receipt))
	decoded, decodeErr := decodeResponse([]byte(fixture), "origin", MaxStdoutBytes)
	if decodeErr != nil || r.translateOrigin(decoded).Error != nil {
		t.Fatal("inspected public entry receipt failed strict decoding")
	}
	for _, invalid := range []string{
		strings.Replace(fixture, `"budget_nanoseconds":1000000001`, `"budget_nanoseconds":1000000001,"budget_nanoseconds":1`, 1),
		strings.Replace(fixture, `"execution_options":`, `"local_path":"canary","execution_options":`, 1),
	} {
		if _, invalidErr := decodeResponse([]byte(invalid), "origin", MaxStdoutBytes); invalidErr == nil {
			t.Fatal("duplicate or unknown local receipt field accepted")
		}
	}
}
