package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestV1RejectsV2RoutingFieldsAndOperations(t *testing.T) {
	root := "ctx1_" + strings.Repeat("a", 64)
	for _, data := range []string{
		`{"operation":"context_inspect","project":"work","root":"` + root + `","body":{}}`,
		`{"operation":"resolve_project","project":"work","body":{}}`,
	} {
		frame := validFrame()
		frame.Payload = json.RawMessage(data)
		if _, err := DecodeCommand(frame); err == nil {
			t.Fatal("v1 accepted a v2 command")
		}
	}
	frame := validFrame()
	frame.Version = 2
	frame.Payload = json.RawMessage(`{"operation":"resolve_project","root":"` + root + `","body":{}}`)
	command, err := DecodeCommandVersion(frame, 2)
	if err != nil || command.Root != root || command.Project != "" {
		t.Fatal("v2 lost its explicit root route")
	}
	for _, operation := range []Operation{Admit, ResumeExisting, Status, Cancel} {
		command.Operation = operation
		if command.ValidateVersion(2) == nil {
			t.Fatal("root route accepted a task command without a project")
		}
	}
	command.Operation, command.Project = ResolveProject, "work"
	if command.ValidateVersion(2) == nil {
		t.Fatal("ambiguous root and project route accepted")
	}
}

func TestV1RoutingCensusAndReplyRejectNewOperation(t *testing.T) {
	call := routingCall()
	call.Operation = ResolveProject
	inventory := ControlInventory{PolicyVersion: 1, ProcessBoot: strings.Repeat("b", 32), BarrierID: strings.Repeat("c", 32), Generation: Generation{BootEpoch: "newboot", Counter: 2}, Complete: true, Active: []ControlCall{call}}
	if inventory.ValidateVersion(1) == nil || inventory.ValidateVersion(2) != nil {
		t.Fatal("routing census operation set was not negotiated")
	}
	reply := ControlResponse{Completion: ControlCompletion{ProcessBoot: inventory.ProcessBoot, Call: call, Disposition: ControlSettled}, Reply: Reply{Operation: ResolveProject, Body: []byte(`{}`)}}
	if reply.ValidateVersion(1) == nil || reply.ValidateVersion(2) != nil {
		t.Fatal("reply operation set was not negotiated")
	}
}

func TestRelativeProjectRejectsTraversalAndNoncanonicalSelectors(t *testing.T) {
	for _, value := range []string{".", "backend", "apps/my project", "apps/世界"} {
		if !ValidRelativeProject(value) {
			t.Fatalf("valid selector denied: %q", value)
		}
	}
	for _, value := range []string{"", "..", "../project", "a/../../b", "/etc", "a//b", "./a", "a/", "a\\b", "C:/project", "a\x00b", strings.Repeat("x", 256)} {
		if ValidRelativeProject(value) {
			t.Fatalf("invalid selector accepted: %q", value)
		}
	}
}

func TestWorkspaceReportDoesNotAcceptV1OrDuplicateAuthority(t *testing.T) {
	workspace := WorkspaceCapability{WorkspaceBinding: WorkspaceBinding{ID: "workspace-one", Guard: "ctx1_" + strings.Repeat("a", 64)}, Name: "source", PolicyRevision: 1}
	report := CapabilityReportV2{ObservedAt: time.Now(), Root: &RootCapability{Root: "ctx1_" + strings.Repeat("b", 64), ContractVersion: 1, Features: []string{FeatureNamespaceAdmission, FeatureNamespaceMutationLease, WorkspaceFeature}}, Workspaces: []WorkspaceCapability{workspace}}
	if report.Validate() != nil {
		t.Fatal("bounded root and workspace report rejected")
	}
	data, err := Encode(report, MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	var legacy CapabilityReport
	if DecodeStrict(data, &legacy, MaxFrameBytes) == nil {
		t.Fatal("v1 accepted v2 root/workspace fields")
	}
	report.Workspaces = append(report.Workspaces, workspace)
	if report.Validate() == nil {
		t.Fatal("duplicate workspace accepted")
	}
	report.Workspaces = nil
	report.Root.Features = []string{FeatureNamespaceAdmission, FeatureNamespaceMutationLease}
	if report.Validate() == nil {
		t.Fatal("v2 report inferred workspace enforcement from wire version")
	}
}
