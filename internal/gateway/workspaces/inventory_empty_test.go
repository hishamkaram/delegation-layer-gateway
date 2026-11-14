package workspaces_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway/workspaces"
	"github.com/hishamkaram/delegation-layer-gateway/internal/mcpadapter"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type emptyWorkspacePresence struct{ source workspaces.Presence }

func (p emptyWorkspacePresence) Snapshot(device domain.DeviceID) (gateway.LinkSnapshot, error) {
	snapshot, err := p.source.Snapshot(device)
	if err != nil {
		return snapshot, err
	}
	if snapshot.CapabilitiesV2 == nil {
		return gateway.LinkSnapshot{}, domain.Reject(domain.EvidenceInvalid)
	}
	// A valid report can have a nil empty slice. Copy the observation so the
	// fixture's original shared report remains unchanged.
	report := *snapshot.CapabilitiesV2
	report.Workspaces = nil
	snapshot.CapabilitiesV2 = &report
	return snapshot, nil
}

func TestSDKOnlineZeroWorkspaceInventoryReturnsArray(t *testing.T) {
	f := newFixture(t)
	service := workspaceInventoryService(t, f, emptyWorkspacePresence{source: f.link})
	result := callWorkspaceInventorySDK(t, f, service)
	structured, err := json.Marshal(result.StructuredContent)
	require(t, err)
	assertEmptyWorkspaceArray(t, structured)
	if len(result.Content) != 1 {
		t.Fatal("inventory omitted its compatible JSON text result")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("inventory returned non-text compatibility content")
	}
	assertEmptyWorkspaceArray(t, []byte(text.Text))
	var envelope mcpadapter.Envelope[mcpadapter.WorkspaceInventory]
	require(t, protocol.DecodeStrict(structured, &envelope, 1<<20))
	if result.IsError || envelope.Error != nil || envelope.Data == nil {
		t.Fatal("valid online empty workspace inventory failed")
	}
	inventory := envelope.Data
	if !inventory.Online || !inventory.DelegateReady || inventory.DeviceID != string(f.device) || inventory.ObservedAt == nil || inventory.Workspaces == nil || len(inventory.Workspaces) != 0 {
		t.Fatal("empty-array normalization changed the dated online observation")
	}
	assertInventoryStartedNoControls(t, f)
}

func assertEmptyWorkspaceArray(t *testing.T, data []byte) {
	t.Helper()
	// Read the actual JSON token: decoding into []T alone can conceal null.
	var envelope struct {
		Data struct {
			Workspaces json.RawMessage `json:"workspaces"`
		} `json:"data"`
	}
	require(t, json.Unmarshal(data, &envelope))
	if !bytes.Equal(bytes.TrimSpace(envelope.Data.Workspaces), []byte(`[]`)) {
		t.Fatal("empty workspace inventory was not encoded as a JSON array")
	}
}
