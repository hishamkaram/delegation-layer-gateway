package connector

import (
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestUnlimitedReceiptSupportsAdmissionAndExistingControls(t *testing.T) {
	f, _, admission := compactAdmissionFixture(t, "unlimited")
	f.state.Features = append(f.state.Features, protocol.FeatureExecutionBudget)
	f.state.Budget, f.state.BudgetUnlimited = 0, true
	f.writeState()
	command := protocol.Command{Operation: protocol.Admit, Project: admission.Task.Origin.OperationID, Body: encoded(t, admission)}
	if reply := f.adapter.Execute(t.Context(), command); reply.Error != nil {
		t.Fatal("unlimited admission receipt rejected", reply.Error.Code)
	}
	task := admission.Task
	task.SpecSHA256 = strings.Repeat("c", 64)
	for _, operation := range []protocol.Operation{protocol.Resolve, protocol.Status, protocol.ResumeExisting, protocol.Cancel} {
		t.Run(string(operation), func(t *testing.T) {
			body := encoded(t, protocol.TaskControl{Task: task})
			if operation == protocol.Cancel {
				body = encoded(t, protocol.Cancellation{Task: task, CancellationID: strings.Repeat("2", 32)})
			}
			reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: operation, Project: task.Origin.OperationID, Body: body})
			if reply.Error != nil {
				t.Fatal("unlimited receipt blocked existing task control", reply.Error.Code)
			}
		})
	}
	assertUnlimitedDispatchCalls(t, f, 1)
}

func TestUnlimitedContinuationUsesNativeZeroBudgetReceipt(t *testing.T) {
	f, _, value := compactContinuationFixture(t, false, "")
	value.Overrides.Budget = "unlimited"
	recommitContinuation(t, &value)
	f.state.Features = append(f.state.Features, protocol.FeatureExecutionBudget)
	f.state.Budget, f.state.BudgetUnlimited = 0, true
	f.writeState()
	reply := f.adapter.Execute(t.Context(), protocol.Command{Operation: protocol.Continue, Project: value.Task.Origin.OperationID, Body: encoded(t, value)})
	if reply.Error != nil {
		t.Fatal("unlimited successor receipt rejected", reply.Error.Code)
	}
	continued := 0
	for _, call := range f.calls() {
		if call.Command != "continue" {
			continue
		}
		continued++
		flags, _, _, _ := helperArguments(call.Args)
		if flags["budget"] != "unlimited" {
			t.Fatal("continuation changed the explicit budget")
		}
	}
	if continued != 1 {
		t.Fatalf("continuation launches: %d", continued)
	}
}

func TestUnlimitedInventoryRequiresExplicitConsistentNativeBudget(t *testing.T) {
	f, _, admission := compactAdmissionFixture(t, "unlimited")
	for _, test := range []struct {
		name      string
		compact   bool
		unlimited bool
		nanos     int64
		valid     bool
	}{
		{name: "unlimited", compact: true, unlimited: true, valid: true},
		{name: "finite", compact: true, nanos: 1, valid: true},
		{name: "missing-marker", compact: true},
		{name: "contradictory-marker", compact: true, unlimited: true, nanos: 1},
		{name: "negative-duration", compact: true, nanos: -1},
		{name: "legacy-unlimited", unlimited: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := inventoryRequestFixture()
			entry := localInventoryEntry("1", f.config.Projects[0].ProjectToken)
			if test.compact {
				origin := admission.Task.Origin
				entry.Origin, entry.Receipt.Origin = &origin, origin
			}
			entry.Receipt.ExecutionOptions.BudgetNanoseconds = test.nanos
			entry.Receipt.ExecutionOptions.BudgetUnlimited = test.unlimited
			wire, err := r.normalizeInventory(localInventory(entry))
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, got %v", test.valid, err)
			}
			if test.valid && wire.Entries[0].Receipt.ExecutionOptions != (protocol.InventoryExecutionOptions{}) {
				t.Fatal("compact inventory copied observed options into request authority")
			}
		})
	}
}
