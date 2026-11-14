package mcpadapter

import (
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestSDKCollectRejectionIsFinalAndPersistsIndependentClosure(t *testing.T) {
	f := newFixture(t, 1)
	session := f.session(t, "alice")
	prepared := decodeResult[Prepared](t, f.call(t, session, "prepare_dispatch", args(t, prepareFixture(privateCanary))))
	if prepared.Error != nil || prepared.Data == nil {
		t.Fatal("preparation failed")
	}
	input := args(t, OperationInput{OperationID: prepared.Data.OperationID})
	dispatched := decodeResult[Operation](t, f.call(t, session, "dispatch_task", input))
	if dispatched.Error != nil || dispatched.Data == nil || !dispatched.Data.Reserved {
		t.Fatal("dispatch did not reserve the operation")
	}
	f.link.observation = func(o *protocol.TaskObservation) {
		o.Publication, o.Verdict = "rejected", "rejected"
		o.Liveness = "ended"
		o.ExecutionClosure = &protocol.ExecutionClosure{Kind: "registered-native", ReferenceSHA256: strings.Repeat("a", 64)}
	}
	result := f.call(t, session, "collect_result", input)
	assertPublic(t, result)
	envelope := decodeResult[Operation](t, result)
	if !result.IsError || envelope.Data != nil || envelope.Error == nil || envelope.Error.Code != "result_unavailable" || envelope.Error.Retryable {
		t.Fatal("rejected collection did not return a final public tool error")
	}
	assertStoredRejectedClosure(t, f, domain.OperationID(prepared.Data.OperationID))
	if len(f.link.commands) != 2 || f.link.commands[1].Operation != protocol.Collect {
		t.Fatal("collection performed another admission or an unrelated control")
	}
}

func assertStoredRejectedClosure(t *testing.T, f *fixture, operation domain.OperationID) {
	t.Helper()
	view, err := f.store.GetOperation(t.Context(), f.alice, operation)
	stored := checked(t, view, err)
	if stored.Reserved || stored.Observation == nil || stored.Observation.Kind != domain.Terminal || stored.Observation.Closure == nil || stored.Observation.Result != nil {
		t.Fatal("collection error lost closure or fabricated an accepted result")
	}
}
