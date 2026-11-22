package recovery

import (
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func compactDrainView(t *testing.T) domain.AdministrativeTaskView {
	t.Helper()
	c := domain.Correlation{
		RequestVersion: 4, Kind: domain.RequestKindDispatch, BriefPresent: true,
		Operation: "operation", Task: domain.TaskID(strings.Repeat("a", 32)), Gateway: "gateway", AdmissionGeneration: "generation",
		Owner: domain.OperationOwner{Kind: domain.Owned, Principal: "principal"}, Destination: domain.Destination{Device: "device", Project: "operation"},
		Context: domain.ContextBinding{Root: domain.RootGuard(protocol.WireContextGuard("root")), Project: domain.ProjectGuard(protocol.WireContextGuard("project"))}, BriefDigest: domain.Hash([]byte("brief")),
		Route: domain.OperationRoute{Version: 1, RequestID: domain.RequestID(strings.Repeat("b", 32)), InputFormat: domain.DispatchInputV1, InputDigest: domain.Hash([]byte("caller input")), ScopeID: "workspace", RelativePath: "repo", WorkspaceGuard: protocol.WireContextGuard("workspace")},
	}
	preimage, err := domain.BuildOriginBinding(c)
	if err != nil {
		t.Fatal(err)
	}
	c.RequestDigest = domain.Hash([]byte(preimage))
	origin, err := domain.CompactOrigin(c)
	if err != nil {
		t.Fatal(err)
	}
	return domain.AdministrativeTaskView{Key: domain.NativeTaskKey{Device: "device", Root: c.Context.Root, Task: c.Task}, Correlation: &c, Binding: domain.AdministrativeTaskBinding{Task: c.Task, Context: c.Context, Origin: origin, SpecDigest: domain.Hash([]byte("Native spec"))}}
}

func TestCompactAdministrativeControlsPreserveOperationRouteAndOrigin(t *testing.T) {
	view := compactDrainView(t)
	input := DrainRequest{Key: view.Key, Route: view.Correlation.Destination, Action: domain.AdministrativeStatus}
	command, err := drainCommand(input, view)
	if err != nil {
		t.Fatal(err)
	}
	var control protocol.TaskControl
	if protocol.DecodeStrict(command.Body, &control, protocol.MaxFrameBytes) != nil {
		t.Fatal("administrative control lost its typed body")
	}
	wantRoute := protocol.TaskRoute{Version: 1, Selection: protocol.FileSelection{ScopeID: "workspace", RelativePath: "repo"}, WorkspaceGuard: protocol.WireContextGuard("workspace"), GuardFormat: protocol.FeatureProjectHashGuard}
	if command.Project != "operation" || command.Operation != protocol.Status || control.Task.Route != wantRoute || control.Task.Origin.Binding != view.Binding.Origin.Binding || control.Task.SpecSHA256 != view.Binding.SpecDigest.Hex() {
		t.Fatal("administrative control changed immutable origin, route or spec")
	}
	observation := protocol.TaskObservation{Task: control.Task, BriefSHA256: view.Correlation.BriefDigest.Hex(), Resolution: "existing", Admission: "admitted", Liveness: "running", Publication: "pending"}
	body, err := protocol.Encode(observation, protocol.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	reply := protocol.Reply{Operation: protocol.Status, Body: body}
	if _, err = drainObservation(reply, view, time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	observation.Task.Route.Selection.RelativePath = "retargeted"
	reply.Body, err = protocol.Encode(observation, protocol.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = drainObservation(reply, view, time.Now()); err == nil {
		t.Fatal("administrative observation accepted a changed execution route")
	}
}

func TestPresentInvalidAdministrativeBindingCannotFallBackToLegacy(t *testing.T) {
	view := compactDrainView(t)
	view.Binding.Origin.Binding = "invalid-present-compact-evidence"
	if _, err := drainBinding(view.Binding); err == nil {
		t.Fatal("invalid present binding silently became a legacy origin")
	}
}
