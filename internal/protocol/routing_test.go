package protocol

import (
	"strings"
	"testing"
)

func routingCall() ControlCall {
	return ControlCall{Generation: Generation{BootEpoch: "oldboot", Counter: 1}, RequestID: "g:1", OperationID: "operation", Operation: Status, RequestSHA256: strings.Repeat("a", 64)}
}

func TestRoutingInventoryRejectsIncompleteAmbiguousAndCurrentGenerationClaims(t *testing.T) {
	valid := ControlInventory{PolicyVersion: 1, ProcessBoot: strings.Repeat("b", 32), BarrierID: strings.Repeat("c", 32), Generation: Generation{BootEpoch: "newboot", Counter: 2}, Complete: true, Active: []ControlCall{routingCall()}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*ControlInventory)
	}{
		{"incomplete", func(v *ControlInventory) { v.Complete = false }},
		{"wrong policy", func(v *ControlInventory) { v.PolicyVersion = 2 }},
		{"current generation", func(v *ControlInventory) { v.Active[0].Generation = v.Generation }},
		{"duplicate key different hash", func(v *ControlInventory) {
			duplicate := v.Active[0]
			duplicate.RequestSHA256 = strings.Repeat("d", 64)
			v.Active = append(v.Active, duplicate)
		}},
		{"too many", func(v *ControlInventory) { v.Active = make([]ControlCall, 7) }},
		{"wrong namespace", func(v *ControlInventory) { v.Active[0].RequestID = "d:1" }},
		{"noncanonical id", func(v *ControlInventory) { v.Active[0].RequestID = "g:01" }},
		{"noncanonical digest", func(v *ControlInventory) { v.Active[0].RequestSHA256 = strings.Repeat("A", 64) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			value.Active = append([]ControlCall(nil), valid.Active...)
			test.change(&value)
			if value.Validate() == nil {
				t.Fatal("invalid routing inventory accepted")
			}
		})
	}
}

func TestEveryTaskControlConsumesScanCapacity(t *testing.T) {
	for _, operation := range []Operation{Admit, Resolve, ResumeExisting, FenceAbsent, Status, Collect, ResultChunk, Cancel} {
		if !operation.ScanConsumer() {
			t.Fatalf("unaccounted whole-payload consumer %s", operation)
		}
	}
	for _, operation := range []Operation{ContextInspect, OriginBarrier, OriginInventory, OriginReopen} {
		if operation.ScanConsumer() {
			t.Fatalf("metadata operation misclassified %s", operation)
		}
	}
	for _, operation := range []Operation{Admit, Resolve, ResumeExisting, Status, Collect, ResultChunk, ContextInspect, OriginBarrier, OriginInventory, OriginReopen} {
		if operation.ProtectedControl() {
			t.Fatalf("ordinary operation borrowed cancellation reserve: %s", operation)
		}
	}
	if !Cancel.ProtectedControl() || !FenceAbsent.ProtectedControl() {
		t.Fatal("cancellation reserve unavailable")
	}
}

func TestControlCompletionIsRoutingEvidenceOnly(t *testing.T) {
	for _, disposition := range []ControlDisposition{ControlNotClaimed, ControlPending, ControlSettled} {
		value := ControlCompletion{ProcessBoot: strings.Repeat("b", 32), Call: routingCall(), Disposition: disposition}
		if value.Validate() != nil {
			t.Fatal("valid completion denied")
		}
	}
	value := ControlCompletion{ProcessBoot: strings.Repeat("b", 32), Call: routingCall(), Disposition: "task_finished"}
	if value.Validate() == nil {
		t.Fatal("task outcome used as CLI cleanup proof")
	}
}

func TestRoutingAcknowledgementAndResponseKeepCleanupSeparate(t *testing.T) {
	ack := ControlInventoryAck{CredentialMode: "regular", PolicyVersion: 1, ProcessBoot: strings.Repeat("a", 32), BarrierID: strings.Repeat("b", 32), Generation: Generation{BootEpoch: "boot", Counter: 1}, Ready: false, Reason: "process_changed"}
	if ack.Validate() != nil {
		t.Fatal("blocked authenticated peer cannot receive ack")
	}
	ack.Ready = true
	if ack.Validate() == nil {
		t.Fatal("contradictory readiness accepted")
	}
	ack.Reason = ""
	if ack.Validate() != nil {
		t.Fatal("ready ack rejected")
	}
	response := ControlResponse{Completion: ControlCompletion{ProcessBoot: strings.Repeat("a", 32), Call: routingCall(), Disposition: ControlNotClaimed}, Reply: Reply{Operation: Status, Body: []byte(`{"admission":"admitted"}`)}}
	if response.Validate() == nil {
		t.Fatal("not-claimed response pretended a successful CLI observation")
	}
	response.Reply.Body = nil
	response.Reply.Error = &Failure{Code: "resource_limit", Retryable: true}
	if response.Validate() != nil {
		t.Fatal("definitive busy refusal rejected")
	}
	response.Reply.Operation = Cancel
	if response.Validate() == nil {
		t.Fatal("completion rebound to another operation")
	}
}

func TestRecoveryAckAllowsOnlyRestrictedRecoveryControls(t *testing.T) {
	ack := ControlInventoryAck{CredentialMode: "recovery_only", PolicyVersion: 1, ProcessBoot: strings.Repeat("a", 32), BarrierID: strings.Repeat("b", 32), Generation: Generation{BootEpoch: "boot", Counter: 1}, Reason: "recovery_pending"}
	for _, operation := range []Operation{ContextInspect, Resolve, FenceAbsent, Status, Collect, ResultChunk, Cancel, OriginBarrier, OriginInventory} {
		if !ack.AllowsControl(operation) {
			t.Fatalf("recovery deadlocked: %s", operation)
		}
	}
	for _, operation := range []Operation{Admit, ResumeExisting, OriginReopen} {
		if ack.AllowsControl(operation) {
			t.Fatalf("recovery widened authority: %s", operation)
		}
	}
	ack.CredentialMode = "regular"
	if ack.AllowsControl(OriginBarrier) {
		t.Fatal("blocked regular identity bypassed recovery gate")
	}
	ack.CredentialMode = "recovery_only"
	ack.Reason = "process_changed"
	if ack.AllowsControl(Cancel) {
		t.Fatal("unknown prior process bypassed drain attestation")
	}
}
