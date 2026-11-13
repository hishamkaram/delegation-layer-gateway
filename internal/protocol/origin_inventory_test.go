package protocol

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func inventoryExample() (OriginInventoryReport, OriginInventoryRequest) {
	task := taskBinding()
	origin := task.Origin
	receipt := &InventoryReceipt{Task: task, BriefSHA256: strings.Repeat("d", 64), ExecutionOptions: InventoryExecutionOptions{Provider: "codex", Permission: "read-only", BudgetNanoseconds: 1_000_000_001, Model: Selection{Kind: "native_default"}, Effort: Selection{Kind: "explicit", Value: "high"}}}
	entry := OriginInventoryEntry{TaskID: task.TaskID, Resolution: "existing", Origin: &origin, SpecSHA256: task.SpecSHA256, BriefSHA256: receipt.BriefSHA256, Receipt: receipt}
	return OriginInventoryReport{Entries: []OriginInventoryEntry{entry}, Complete: true, MembershipSHA256: strings.Repeat("e", 64), CompletenessReceipt: strings.Repeat("f", 64)}, OriginInventoryRequest{GatewayID: origin.GatewayID, Generation: "restore-generation", Limit: 100, ExpectedRoot: task.Context.Root}
}

func TestOriginInventoryStrictWireAndExactNanoseconds(t *testing.T) {
	inventory, request := inventoryExample()
	inventory.Entries[0].Receipt.ExecutionOptions.BudgetNanoseconds = math.MaxInt64
	encoded, encodeErr := Encode(inventory, MaxFrameBytes)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	var decoded OriginInventoryReport
	if DecodeStrict(encoded, &decoded, MaxFrameBytes) != nil || decoded.ValidateFor(request) != nil || decoded.Entries[0].Receipt.ExecutionOptions.BudgetNanoseconds != math.MaxInt64 {
		t.Fatal("wire inventory lost exact historical nanoseconds")
	}
	for _, invalid := range [][]byte{
		bytes.Replace(encoded, []byte(`"task_id":`), []byte(`"project_token":"private-path","task_id":`), 1),
		bytes.Replace(encoded, []byte(`"resolution":"existing"`), []byte(`"resolution":"existing","resolution":"existing"`), 1),
		bytes.Replace(encoded, []byte(`"budget_nanoseconds":9223372036854775807`), []byte(`"budget_nanoseconds":9223372036854775808`), 1),
	} {
		var rejected OriginInventoryReport
		if DecodeStrict(invalid, &rejected, MaxFrameBytes) == nil {
			t.Fatal("unknown/local metadata, duplicate field or overflowing budget accepted")
		}
	}
}

func TestOriginInventoryRejectsConflictingAttributionAndPagination(t *testing.T) {
	for name, mutate := range map[string]func(*OriginInventoryReport, *OriginInventoryRequest){
		"missing-receipt": func(i *OriginInventoryReport, _ *OriginInventoryRequest) { i.Entries[0].Receipt = nil },
		"task-id": func(i *OriginInventoryReport, _ *OriginInventoryRequest) {
			i.Entries[0].Receipt.Task.TaskID = strings.Repeat("1", 32)
		},
		"origin": func(i *OriginInventoryReport, _ *OriginInventoryRequest) {
			i.Entries[0].Receipt.Task.Origin.OperationID = "other"
		},
		"spec": func(i *OriginInventoryReport, _ *OriginInventoryRequest) {
			i.Entries[0].SpecSHA256 = strings.Repeat("1", 64)
		},
		"brief": func(i *OriginInventoryReport, _ *OriginInventoryRequest) {
			i.Entries[0].BriefSHA256 = strings.Repeat("1", 64)
		},
		"duplicate-task":  func(i *OriginInventoryReport, _ *OriginInventoryRequest) { i.Entries = append(i.Entries, i.Entries[0]) },
		"complete-cursor": func(i *OriginInventoryReport, _ *OriginInventoryRequest) { i.NextCursor = i.Entries[0].TaskID },
		"incomplete-proof": func(i *OriginInventoryReport, _ *OriginInventoryRequest) {
			i.Complete = false
			i.NextCursor = i.Entries[0].TaskID
		},
		"missing-membership": func(i *OriginInventoryReport, _ *OriginInventoryRequest) { i.MembershipSHA256 = "" },
		"request-cursor":     func(i *OriginInventoryReport, r *OriginInventoryRequest) { r.Cursor = i.Entries[0].TaskID },
		"request-gateway":    func(_ *OriginInventoryReport, r *OriginInventoryRequest) { r.GatewayID = "other" },
		"request-root": func(_ *OriginInventoryReport, r *OriginInventoryRequest) {
			r.ExpectedRoot = WireContextGuard("other root")
		},
		"page-over-limit": func(i *OriginInventoryReport, r *OriginInventoryRequest) {
			r.Limit = 1
			i.Entries = append(i.Entries, OriginInventoryEntry{TaskID: strings.Repeat("b", 32), Resolution: "permanently_refused"})
		},
		"request-limit": func(_ *OriginInventoryReport, r *OriginInventoryRequest) { r.Limit = 0 },
		"invalid-permission": func(i *OriginInventoryReport, _ *OriginInventoryRequest) {
			i.Entries[0].Receipt.ExecutionOptions.Permission = "unknown"
		},
		"nonpositive-budget": func(i *OriginInventoryReport, _ *OriginInventoryRequest) {
			i.Entries[0].Receipt.ExecutionOptions.BudgetNanoseconds = 0
		},
		"local-context": func(i *OriginInventoryReport, _ *OriginInventoryRequest) {
			i.Entries[0].Receipt.Task.Context.Project = "/private/project"
		},
	} {
		t.Run(name, func(t *testing.T) {
			inventory, request := inventoryExample()
			mutate(&inventory, &request)
			if inventory.ValidateFor(request) == nil {
				t.Fatal("conflicting inventory evidence accepted")
			}
		})
	}
}

func TestOriginInventoryRefusalHasNoInventedContextAndPartialPageAdvances(t *testing.T) {
	inventory, request := inventoryExample()
	refusal := OriginInventoryEntry{TaskID: strings.Repeat("b", 32), Resolution: "permanently_refused"}
	inventory.Entries = append(inventory.Entries, refusal)
	inventory.Complete = false
	inventory.CompletenessReceipt = ""
	inventory.NextCursor = refusal.TaskID
	if inventory.ValidateFor(request) != nil {
		t.Fatal("unattributed refusal or valid advancing partial page rejected")
	}
	inventory.Entries[1].Receipt = inventory.Entries[0].Receipt
	if inventory.ValidateFor(request) == nil {
		t.Fatal("refusal claimed an existing-task receipt")
	}
	inventory.Entries = nil
	inventory.NextCursor = ""
	if inventory.ValidateFor(request) == nil {
		t.Fatal("incomplete empty inventory accepted")
	}
}
