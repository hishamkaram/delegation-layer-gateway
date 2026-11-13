package mcpadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type failingPresence struct{ failure error }

func (p failingPresence) Snapshot(domain.DeviceID) (gateway.LinkSnapshot, error) {
	return gateway.LinkSnapshot{}, p.failure
}

func TestSDKPresenceOfflineMetadataRequiresSoleCause(t *testing.T) {
	offline := &gateway.RemoteError{Failure: protocol.Failure{Code: "device_offline", Retryable: true}}
	var nilRemote *gateway.RemoteError
	for _, test := range []struct {
		name    string
		failure error
		offline bool
	}{
		{name: "sole-offline", failure: offline, offline: true},
		{name: "single-join-offline", failure: errors.Join(offline, nil), offline: true},
		{name: "mixed-storage", failure: errors.Join(offline, errors.New(privateCanary))},
		{name: "ordinary-wrapper", failure: fmt.Errorf("%s: %w", privateCanary, offline)},
		{name: "typed-nil", failure: nilRemote},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newInventoryObservationFixture(t)
			f.adapter.options.Presence = failingPresence{failure: test.failure}
			result := f.call(t, f.session(t, "inventory"), "list_devices", json.RawMessage(`{}`))
			if test.offline {
				assertOfflineDeviceMetadata(t, result)
				f.assertEvents(t, observability.MCPToolResponseReady)
			} else {
				expectError[DevicePage](t, result, "internal_error")
				_, online, err := f.adapter.snapshot(deviceID(0))
				if online {
					t.Fatal("Presence uncertainty became an online observation")
				}
				assertPresenceErrorGraph(t, err, test.failure)
				f.assertEvents(t, observability.MCPToolErrorReady)
			}
			assertPublic(t, result)
		})
	}
}

func assertPresenceErrorGraph(t *testing.T, actual, expected error) {
	t.Helper()
	if !errors.Is(actual, expected) {
		t.Fatal("Presence discarded an original cause")
	}
	// Inspect only the outer unwrap shape: errors.As would walk through and
	// conceal a new wrapper, which is exactly the regression this test rejects.
	if want, joined := expected.(interface{ Unwrap() []error }); joined {
		got, ok := actual.(interface{ Unwrap() []error })
		if !ok || len(got.Unwrap()) != len(want.Unwrap()) {
			t.Fatal("Presence changed an original error join")
		}
		for i, cause := range want.Unwrap() {
			assertPresenceErrorGraph(t, got.Unwrap()[i], cause)
		}
		return
	}
	if want, wrapped := expected.(interface{ Unwrap() error }); wrapped {
		got, ok := actual.(interface{ Unwrap() error })
		if !ok {
			t.Fatal("Presence changed an original error wrapper")
		}
		assertPresenceErrorGraph(t, got.Unwrap(), want.Unwrap())
		return
	}
	_, wrapped := actual.(interface{ Unwrap() error })
	_, joined := actual.(interface{ Unwrap() []error })
	if wrapped || joined {
		t.Fatal("Presence wrapped an original error leaf")
	}
}

func assertOfflineDeviceMetadata(t *testing.T, result *mcp.CallToolResult) {
	t.Helper()
	envelope := decodeResult[DevicePage](t, result)
	if envelope.Error != nil || envelope.Data == nil || len(envelope.Data.Devices) != 1 {
		t.Fatal("sole device-offline failure did not preserve authorized inventory")
	}
	device := envelope.Data.Devices[0]
	if device.DeviceID != string(deviceID(0)) || device.Online || device.DelegateReady || device.ExecutionReadiness != "not_ready" || device.ObservedAt != nil {
		t.Fatal("offline metadata invented a dated live observation")
	}
}
