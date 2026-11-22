package connector

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func serviceReply(t *testing.T, f *fixture, command protocol.Command, version int) protocol.Reply {
	t.Helper()
	peer := &fakePeer{incoming: make(chan control, 1)}
	attachedService(t, f, peer)
	control := peer.control(t, command, 1)
	control.frame.Version = version
	peer.incoming <- control
	select {
	case reply := <-control.reply:
		return reply
	case <-time.After(10 * time.Second):
		t.Fatal("service did not return a joined control reply")
		return protocol.Reply{}
	}
}

func TestServiceV1TaskFailureKeepsLegacyWireShape(t *testing.T) {
	f := newFixture(t)
	f.state.CollectExit, f.state.CollectFailure = 1, "pending"
	f.writeState()
	reply := serviceReply(t, f, f.command(protocol.Collect), protocol.Version)
	assertLegacyFailureJSON(t, reply)
}

func TestServiceV2LegacyTaskFailureKeepsLegacyWireShape(t *testing.T) {
	f, _, selection := newWorkspaceFixture(t)
	resolved := resolveWorkspace(t, f, selection)
	task := f.task()
	task.Context = resolved.Project.Context
	f.state.CollectExit, f.state.CollectFailure = 1, "pending"
	f.writeState()
	command := protocol.Command{Operation: protocol.Collect, Project: resolved.Project.Handle, Body: encoded(t, protocol.TaskControl{Task: task})}
	assertLegacyFailureJSON(t, serviceReply(t, f, command, protocol.WireVersion2))
}

func assertLegacyFailureJSON(t *testing.T, reply protocol.Reply) {
	assertLegacyFailureCodeJSON(t, reply, "pending")
}

// Frozen independently from base 8937a4a:internal/protocol/peer.go. These fields
// and codes model the old strict reader, not the expanded current protocol.
type legacyWireFailure struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

func (f legacyWireFailure) valid() bool {
	switch f.Code {
	case "unauthenticated", "forbidden", "not_found", "device_offline", "device_not_ready", "conflict", "expired", "pending", "admission_unknown", "permanently_refused", "context_mismatch", "incompatible_delegate", "resource_limit", "result_unavailable", "evidence_invalid", "timeout", "result_verification_timeout", "protocol_error":
		return true
	default:
		return false
	}
}

func assertLegacyFailureCodeJSON(t *testing.T, reply protocol.Reply, expectedCode string) {
	t.Helper()
	data, err := protocol.Encode(reply, protocol.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	// This independent old-reader DTO has no Stage field. Strict decoding must
	// continue to work without relaxing the historical wire boundary.
	var oldReply struct {
		Operation protocol.Operation `json:"operation"`
		Error     *legacyWireFailure `json:"error,omitempty"`
		Body      json.RawMessage    `json:"body,omitempty"`
	}
	if protocol.DecodeStrict(data, &oldReply, protocol.MaxFrameBytes) != nil {
		t.Fatal("legacy strict reader rejected the task failure")
	}
	if oldReply.Error == nil || !oldReply.Error.valid() {
		t.Fatalf("legacy strict failure validator rejected the error code: %s", data)
	}
	golden := `{"operation":"collect","error":{"code":"` + expectedCode + `","retryable":true}}`
	if string(data) != golden {
		t.Fatalf("legacy task failure changed wire bytes or meaning: %s", data)
	}
}

type failureContractCase struct {
	name    string
	version int
	legacy  bool
	setup   func(*testing.T) (*fixture, protocol.Command)
}

func TestServiceFailureCodesRespectFrozenLegacyContracts(t *testing.T) {
	contracts := []failureContractCase{
		{"v1_route0", protocol.Version, true, func(t *testing.T) (*fixture, protocol.Command) {
			f := newFixture(t)
			return f, f.command(protocol.Collect)
		}},
		{"v2_route0", protocol.WireVersion2, true, func(t *testing.T) (*fixture, protocol.Command) {
			f, _, selection := newWorkspaceFixture(t)
			resolved := resolveWorkspace(t, f, selection)
			task := f.task()
			task.Context = resolved.Project.Context
			return f, protocol.Command{Operation: protocol.Collect, Project: resolved.Project.Handle, Body: encoded(t, protocol.TaskControl{Task: task})}
		}},
		{"v2_route1", protocol.WireVersion2, false, func(t *testing.T) (*fixture, protocol.Command) {
			f, _, task := newRoutedFixture(t)
			return f, protocol.Command{Operation: protocol.Collect, Project: task.Origin.OperationID, Body: encoded(t, protocol.TaskControl{Task: task})}
		}},
	}
	for _, contract := range contracts {
		t.Run(contract.name, func(t *testing.T) {
			for _, code := range []struct{ native, legacy string }{
				{"invalid_request", "pending"},
				{"unsupported_option", "pending"},
				{"not_found", "not_found"},
			} {
				t.Run(code.native, func(t *testing.T) {
					checkServiceFailureCodeContract(t, contract, code.native, code.legacy)
				})
			}
		})
	}
}

func checkServiceFailureCodeContract(t *testing.T, contract failureContractCase, nativeCode, legacyCode string) {
	t.Helper()
	f, command := contract.setup(t)
	f.state.CollectExit, f.state.CollectFailure = 1, nativeCode
	f.writeState()
	reply := serviceReply(t, f, command, contract.version)
	if contract.legacy {
		assertLegacyFailureCodeJSON(t, reply, legacyCode)
		return
	}
	if reply.Error == nil || reply.Error.Code != nativeCode || reply.Error.Stage != "collect" || !reply.Error.Retryable || reply.ValidateVersion(protocol.WireVersion2) != nil {
		t.Fatal("new operation contract lost the Native error code, stage or task retry default")
	}
}

func TestLegacyFailureProjectionUsesFrozenVocabularyWithoutMutatingInput(t *testing.T) {
	for _, contract := range []struct {
		name           string
		version, route int
	}{
		{"every_v1_reply", protocol.Version, 1},
		{"legacy_v2_reply", protocol.WireVersion2, 0},
		{"legacy_local_reply", 0, 0},
	} {
		t.Run(contract.name, func(t *testing.T) {
			for _, code := range []string{
				"unauthenticated", "forbidden", "not_found", "device_offline", "device_not_ready", "conflict", "expired", "pending", "admission_unknown", "permanently_refused", "context_mismatch", "incompatible_delegate", "resource_limit", "result_unavailable", "evidence_invalid", "timeout", "result_verification_timeout", "protocol_error",
			} {
				t.Run(code, func(t *testing.T) {
					checkLegacyProjection(t, contract.version, contract.route, code, code, false)
				})
			}
			for _, code := range []string{"invalid_request", "unsupported_option", "future_native_failure"} {
				t.Run(code, func(t *testing.T) {
					checkLegacyProjection(t, contract.version, contract.route, code, "pending", true)
				})
			}
		})
	}
}

func checkLegacyProjection(t *testing.T, version, route int, nativeCode, expectedCode string, retryable bool) {
	t.Helper()
	input := protocol.Reply{Operation: protocol.Collect, Error: &protocol.Failure{Code: nativeCode, Stage: "collect"}}
	reply := projectControlReply(input, version, protocol.Collect, route)
	if reply.Error == nil || reply.Operation != protocol.Collect || reply.Error.Code != expectedCode || reply.Error.Retryable != retryable || reply.Error.Stage != "" || len(reply.Body) != 0 {
		t.Fatal("legacy projection changed frozen code/defaults or fabricated task proof")
	}
	if input.Error.Code != nativeCode || input.Error.Stage != "collect" || input.Error.Retryable {
		t.Fatal("compatibility projection mutated its Native input")
	}
}

func TestServiceV2RoutedTaskFailureRetainsStage(t *testing.T) {
	f, _, task := newRoutedFixture(t)
	f.state.CollectExit, f.state.CollectFailure = 1, "pending"
	f.writeState()
	command := protocol.Command{Operation: protocol.Collect, Project: task.Origin.OperationID, Body: encoded(t, protocol.TaskControl{Task: task})}
	reply := serviceReply(t, f, command, protocol.WireVersion2)
	if reply.Error == nil || reply.Error.Stage != "collect" || reply.Error.Code != "pending" || !reply.Error.Retryable {
		t.Fatal("new operation-bound task lost its safe Native stage")
	}
}

func TestServiceV2MetadataFailuresRetainSafeNativeStage(t *testing.T) {
	for _, test := range []struct {
		name  string
		code  string
		stage string
		setup func(*testing.T, *fixture, protocol.ModelQuery) protocol.Command
	}{
		{"filesystem", "changed", "file_read", func(t *testing.T, f *fixture, _ protocol.ModelQuery) protocol.Command {
			f.state.FilesystemFailure = "changed"
			f.writeState()
			return filesystemCommand(t, f, protocol.FileSelection{ScopeID: "workspace-one", RelativePath: "file"})
		}},
		{"models", "invalid_request", "validate-request", func(t *testing.T, f *fixture, query protocol.ModelQuery) protocol.Command {
			f.state.ModelsFailure, f.state.ModelsExit = "invalid_request", 1
			f.writeState()
			return modelCommand(t, f, query)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _, query := newModelsFixture(t)
			reply := serviceReply(t, f, test.setup(t, f, query), protocol.WireVersion2)
			if reply.Error == nil || reply.Error.Code != test.code || reply.Error.Stage != test.stage || reply.ValidateVersion(protocol.WireVersion2) != nil {
				t.Fatal("v2 lost the validated Native failure stage")
			}
		})
	}
}

func TestNativeFailureKeepsBooleanPresenceAndPublicRetryActionSeparate(t *testing.T) {
	for _, test := range []struct {
		name      string
		command   string
		operation protocol.Operation
		data      string
		retryable bool
	}{
		{"model retry action", "models", protocol.ProviderModels, `{"schema_version":1,"command":"models","failure":{"code":"pending","stage":"inspect-provider","next_action":"retry_later"}}`, true},
		{"model input action", "models", protocol.ProviderModels, `{"schema_version":1,"command":"models","failure":{"code":"invalid_request","stage":"validate-request","next_action":"correct_request"}}`, false},
		{"filesystem false", "filesystem", protocol.ReadFile, `{"schema_version":1,"command":"filesystem","failure":{"code":"changed","stage":"file_read","retryable":false}}`, false},
		{"filesystem true", "filesystem", protocol.ReadFile, `{"schema_version":1,"command":"filesystem","failure":{"code":"changed","stage":"file_read","retryable":true}}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := decodeResponse([]byte(test.data), test.command, protocol.MaxFrameBytes)
			if err != nil || response.Failure == nil {
				t.Fatal("Native failure projection did not decode", err)
			}
			if test.command == "models" && response.Failure.Retryable != nil {
				t.Fatal("missing Native boolean became an explicit fact")
			}
			reply := nativeFailureReply(test.operation, response.Failure)
			if reply.Error == nil || reply.Error.Retryable != test.retryable {
				t.Fatal("public retry action or explicit boolean changed")
			}
		})
	}
}
