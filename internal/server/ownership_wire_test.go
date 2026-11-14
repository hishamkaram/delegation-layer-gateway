package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/mcpadapter"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
)

func TestRuntimeRequiredOwnedTokenRedeemsThroughAuditedHTTPComposition(t *testing.T) {
	f := configFixture(t)
	f.owner(t, "subject")
	f.start(t)
	var token adminapi.Enrollment
	f.adminCall(t, "/v1/devices/enrollment-tokens", adminapi.OwnedEnrollmentInput{Issuer: f.cfg.Identity.Issuer, Subject: "subject", Name: "Headless"}, &token)
	request, _ := selfRequest(t)
	input := enrollment.EnrollmentRequest{Token: token.Token, CSRDERBase64: request.CSRDERBase64, RequireOwned: true}
	var first enrollment.EnrollmentResponse
	for attempt := range 2 {
		status, data := f.request(t, f.client, "POST", f.cfg.PublicURL+"/v1/enroll", jsonBytes(t, input), "")
		if status != 200 {
			t.Fatalf("required-owned runtime redemption status=%d", status)
		}
		var response enrollment.EnrollmentResponse
		require(t, protocol.DecodeStrict(data, &response, protocol.MaxEnrollmentBodyBytes))
		if response.DeviceID != token.DeviceID || response.CertificateDERBase64 == "" {
			t.Fatal("required-owned runtime receipt lost reserved identity")
		}
		if attempt == 0 {
			first = response
		} else if first != response {
			t.Fatal("runtime owned replay changed certificate receipt")
		}
	}
}

// Real Registry, JWKS/JWT, mTLS/WSS and official MCP SDK prove composition.
// Peers report metadata only; no Native binary or provider is executed.
func TestRuntimeOwnedOnlyWireV2PreservesLegacyV1AndAuthorizedDevicePage(t *testing.T) {
	f := configFixture(t)
	principal := f.owner(t, "subject")
	f.start(t)
	_, legacy := f.enrollDevice(t)
	f.adminCall(t, "/v1/projects", adminapi.RegisterProjectInput{DeviceID: "device", ProjectAlias: "public", RootGuard: protocol.WireContextGuard("legacy root"), ProjectGuard: protocol.WireContextGuard("legacy project")}, nil)
	routingAuditAdmin(t, f, "PUT", "/v1/grants", adminapi.PutGrantInput{PrincipalID: string(principal), DeviceID: "device", ProjectAlias: "public", Scopes: []domain.Scope{domain.InventoryRead}, Providers: []domain.ProviderID{"claude:print"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60})
	ownedReceipt, owned := f.selfEnroll(t)
	endpoint := strings.Replace(f.deviceURL(t), "https://", "wss://", 1)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	legacyV2 := transport.ClientConfig{WireVersion: 2, URL: endpoint, GatewayID: f.runtime.gatewayID, Certificate: legacy.Leaf, CapabilitiesV2: &protocol.CapabilityReportV2{ObservedAt: time.Now()}, Routing: &emptyCensus{boot: strings.Repeat("a", 32)}}
	if client, err := transport.Dial(ctx, legacyV2, f.deviceHTTP(t, &legacy), time.Now); err == nil {
		require(t, client.Close())
		t.Fatal("unowned credential established v2")
	}
	// Observe retirement without forced cleanup; it must never become online.
	waitRevokedDeviceRetirement(t, f)
	legacyV1 := legacyV2
	legacyV1.WireVersion = 1
	legacyV1.CapabilitiesV2 = nil
	legacyV1.Capabilities = protocol.CapabilityReport{ObservedAt: time.Now()}
	v1 := diagnosticDeviceDial(t, legacyV1, f.deviceHTTP(t, &legacy))
	t.Cleanup(func() { require(t, v1.Close()) })
	require(t, f.runtime.hub.WaitReady(ctx, "device"))
	before, err := f.runtime.hub.Snapshot("device")
	require(t, err)
	ownedV2 := transport.ClientConfig{WireVersion: 2, URL: endpoint, GatewayID: f.runtime.gatewayID, Certificate: owned.Leaf, CapabilitiesV2: &protocol.CapabilityReportV2{ObservedAt: time.Now()}, Routing: &emptyCensus{boot: strings.Repeat("b", 32)}}
	v2 := diagnosticDeviceDial(t, ownedV2, f.deviceHTTP(t, &owned))
	t.Cleanup(func() { require(t, v2.Close()) })
	require(t, f.runtime.hub.WaitReady(ctx, domain.DeviceID(ownedReceipt.DeviceID)))
	// Duplicate rejection must not displace a working legacy session.
	if client, duplicateErr := transport.Dial(ctx, legacyV2, f.deviceHTTP(t, &legacy), time.Now); duplicateErr == nil {
		require(t, client.Close())
		t.Fatal("duplicate unowned v2 connected")
	}
	after, err := f.runtime.hub.Snapshot("device")
	require(t, err)
	if !after.Online || after.WireVersion != 1 || after.Generation != before.Generation {
		t.Fatal("denied v2 displaced existing authorized v1")
	}
	page := routingAuditTool[mcpadapter.DevicePage](t, f.session(t), "list_devices", map[string]string{})
	if page.Error != nil || page.Data == nil || len(page.Data.Devices) != 2 {
		t.Fatalf("incompatible device poisoned authorized inventory: %+v", page.Error)
	}
	for _, device := range page.Data.Devices {
		if !device.Online {
			t.Fatal("accepted owned/v1 device missing from online inventory")
		}
	}
}
