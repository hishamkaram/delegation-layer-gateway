package mcpadapter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func prepareFixture(brief string) PrepareInput {
	return PrepareInput{DeviceID: string(deviceID(0)), ProjectAlias: "public", Brief: brief, Provider: "provider", Permission: "read-only", BudgetSeconds: 60}
}

func TestSDKPrepareDispatchAndReadOnlyControlsPreserveOpaqueIdentity(t *testing.T) {
	f := newFixture(t, 1)
	alice := f.session(t, "alice")
	dispatch := f.session(t, "dispatch")
	preparedResult := f.call(t, dispatch, "prepare_dispatch", args(t, prepareFixture(privateCanary+" confidential brief")))
	assertPublic(t, preparedResult)
	envelope := decodeResult[Prepared](t, preparedResult)
	if envelope.Error != nil || envelope.Data == nil || envelope.Data.OperationID == "" || envelope.Data.TaskID == "" || envelope.Data.OperationID == envelope.Data.TaskID {
		t.Fatal("prepare failed to mint separate stable identities")
	}
	if len(f.link.commands) != 0 {
		t.Fatal("preparation launched a connector control")
	}
	input := args(t, OperationInput{OperationID: envelope.Data.OperationID})
	assertConfirmAndReadOnly(t, f, dispatch, alice, envelope.Data, input)
	bob := f.session(t, "bob")
	expectError[Operation](t, f.call(t, bob, "get_task_status", input), "not_found")
}

func TestStrictArgumentsRejectIdentitySpoofDuplicatesAndUnknownFields(t *testing.T) {
	cases := []json.RawMessage{
		json.RawMessage(`{"principal":"` + privateCanary + `"}`),
		json.RawMessage(`{"scopes":["task:dispatch"],"debug":"` + privateCanary + `"}`),
		json.RawMessage(`{"limit":1,"limit":2}`),
		json.RawMessage(`{"unknown":"` + privateCanary + `"}`),
	}
	f := newFixture(t, 1)
	session := f.session(t, "alice")
	for _, input := range cases {
		result := f.call(t, session, "list_devices", input)
		assertPublic(t, result)
		expectError[DevicePage](t, result, "invalid_request")
	}
	if len(f.link.commands) != 0 {
		t.Fatal("invalid arguments reached the connector")
	}
}

func TestUTF8BriefLimitUsesBytesAndNativeErrorsAreRedacted(t *testing.T) {
	f := newFixture(t, 1)
	session := f.session(t, "alice")
	valid := strings.Repeat("界", domain.MaxBriefBytes/3) + "a"
	result := f.call(t, session, "prepare_dispatch", args(t, prepareFixture(valid)))
	envelope := decodeResult[Prepared](t, result)
	if envelope.Error != nil || envelope.Data == nil {
		t.Fatal("valid multibyte UTF-8 byte boundary was rejected")
	}
	result = f.call(t, session, "prepare_dispatch", args(t, prepareFixture(valid+"界")))
	expectError[Prepared](t, result, "invalid_request")
	assertPublic(t, result)
	operations, err := f.store.ListOperations(t.Context(), f.alice, domain.OperationPageRequest{})
	page := checked(t, operations, err)
	if len(page.Items) != 1 || len(f.link.commands) != 0 {
		t.Fatal("oversized brief left an operation or launched work")
	}
	f.link.err = errors.New(privateCanary)
	result = f.call(t, session, "list_devices", json.RawMessage(`{}`))
	expectError[DevicePage](t, result, "internal_error")
	assertPublic(t, result)
}

func assertConfirmAndReadOnly(t *testing.T, f *fixture, dispatch, alice *mcp.ClientSession, prepared *Prepared, input json.RawMessage) {
	t.Helper()
	for range 2 {
		result := f.call(t, dispatch, "dispatch_task", input)
		assertPublic(t, result)
		dispatched := decodeResult[Operation](t, result)
		if dispatched.Error != nil || dispatched.Data == nil || dispatched.Data.OperationID != prepared.OperationID || dispatched.Data.TaskID != prepared.TaskID || !dispatched.Data.Reserved {
			t.Fatal("confirmation changed correlation or execution accounting")
		}
		if dispatched.Data.Observation != nil {
			t.Fatal("dispatch-only confirmation gained task-read observations")
		}
	}
	if len(f.link.commands) != 1 || f.link.commands[0].Operation != protocol.Admit {
		t.Fatal("duplicate confirmation resent an admission")
	}
	assertPassiveControls(t, f, alice, prepared, input)
}

func assertPassiveControls(t *testing.T, f *fixture, alice *mcp.ClientSession, prepared *Prepared, input json.RawMessage) {
	t.Helper()
	for _, name := range []string{"resolve_operation", "get_task_status", "collect_result"} {
		result := f.call(t, alice, name, input)
		assertPublic(t, result)
		observed := decodeResult[Operation](t, result)
		if observed.Error != nil || observed.Data == nil || observed.Data.OperationID != prepared.OperationID {
			t.Fatal("passive tool changed operation identity")
		}
	}
	for _, command := range f.link.commands[1:] {
		if command.Operation != protocol.Resolve && command.Operation != protocol.Status && command.Operation != protocol.Collect {
			t.Fatal("read-only tool admitted, resumed or fenced a task")
		}
	}
}
