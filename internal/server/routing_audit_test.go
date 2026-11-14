package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/mcpadapter"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
	"github.com/hishamkaram/delegation-layer-gateway/internal/transport"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const routingAuditCanary = "private-canary-routing-brief-must-not-be-logged"

// This peer models typed namespace and admission replies, not Delegate execution.
// Its one goroutine owns namespace fixture state; atomics expose command counts.
type routingAuditPeer struct {
	client     *transport.Client
	context    protocol.ContextBinding
	gateway    string
	principal  string
	generation string
	recovery   string
	open       bool
	commands   atomic.Int64
	admissions atomic.Int64
	exchanges  chan routingAuditExchange
}

type routingAuditExchange struct {
	requestBytes  int
	responseBytes int
	request       domain.RequestID
	connection    domain.ConnectionGeneration
}

type routingAuditCounts struct{ prepared, completed, cached, denied int }

func (p *routingAuditPeer) capability() protocol.ProjectCapability {
	return protocol.ProjectCapability{
		Alias: "project", Context: p.context, ContractVersion: protocol.Version,
		Features:            []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease},
		AdmissionGeneration: p.generation, AdmissionOpen: p.open, Ready: p.open,
		Providers: []protocol.ProviderCapability{{Provider: "provider", Permissions: []string{"read-only"}, MaxBudgetSeconds: 60, Authentication: "unknown"}},
	}
}

func (p *routingAuditPeer) serve(ctx context.Context) error {
	for {
		received, err := p.client.Receive(ctx)
		if err != nil {
			return err
		}
		if err = p.answer(ctx, received); err != nil {
			return err
		}
	}
}

func (p *routingAuditPeer) answer(ctx context.Context, received *transport.Received) error {
	frame, err := received.Claim(ctx)
	if err != nil {
		return err
	}
	var command protocol.Command
	if err = protocol.DecodeStrict(frame.Payload, &command, protocol.MaxFrameBytes); err != nil {
		return err
	}
	if command.Project != "project" || command.Operation.Validate() != nil {
		return errors.New("unexpected audit fixture command")
	}
	p.commands.Add(1)
	body, err := p.response(command, frame.OperationID)
	if err != nil {
		return err
	}
	completion := protocol.ControlCompletion{ProcessBoot: p.client.ProcessBoot(), Call: received.ControlCall(), Disposition: protocol.ControlSettled}
	reply := protocol.Reply{Operation: command.Operation, Body: body}
	if command.Operation == protocol.Admit {
		if err = p.recordExchange(ctx, received, frame, completion, reply); err != nil {
			return err
		}
	}
	if err = received.ReplyControl(ctx, reply, completion); err != nil {
		return err
	}
	if command.Operation == protocol.OriginReopen {
		return p.client.ReportCapabilities(ctx, protocol.CapabilityReport{ObservedAt: time.Now(), Projects: []protocol.ProjectCapability{p.capability()}})
	}
	return nil
}

func (p *routingAuditPeer) recordExchange(ctx context.Context, received *transport.Received, request protocol.Frame, completion protocol.ControlCompletion, reply protocol.Reply) error {
	// Request bytes come from the opposite endpoint's actual raw-frame receipt.
	// Encode the complete fixture response envelope, not just its semantic body.
	payload, err := protocol.Encode(protocol.ControlResponse{Completion: completion, Reply: reply}, protocol.MaxFrameBytes)
	if err != nil {
		return err
	}
	response, err := protocol.EncodeFrame(protocol.Frame{Version: protocol.Version, Type: protocol.Response, RequestID: request.RequestID, Generation: request.Generation, OperationID: request.OperationID, TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload})
	if err != nil {
		return err
	}
	metadata := received.Metadata()
	select {
	case p.exchanges <- routingAuditExchange{requestBytes: metadata.EncodedFrameBytes, responseBytes: len(response), request: domain.RequestID(metadata.RequestID), connection: metadata.Connection}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *routingAuditPeer) response(command protocol.Command, operation string) ([]byte, error) {
	switch command.Operation {
	case protocol.ContextInspect:
		return p.inspect(command.Body)
	case protocol.OriginBarrier:
		return p.barrier(command.Body)
	case protocol.OriginInventory:
		return p.inventory(command.Body)
	case protocol.OriginReopen:
		return p.reopen(command.Body)
	case protocol.Admit:
		return p.admit(command.Body, operation)
	case protocol.ResolveProject, protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel:
		return nil, errors.New("unexpected task control in audit fixture")
	default:
		return nil, fmt.Errorf("unexpected audit fixture operation: %s", command.Operation)
	}
}

func (p *routingAuditPeer) inspect(body []byte) ([]byte, error) {
	var input protocol.InspectRequest
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.GatewayID != p.gateway {
		return nil, errors.New("unexpected audit fixture inspection")
	}
	if !input.RootOnly {
		return protocol.Encode(p.capability(), protocol.MaxFrameBytes)
	}
	report := protocol.RootCapability{Root: p.context.Root, ContractVersion: protocol.Version, Features: []string{protocol.FeatureNamespaceAdmission, protocol.FeatureNamespaceMutationLease}, OriginRegistered: p.generation != ""}
	if report.OriginRegistered {
		report.Origin = &protocol.OriginStateReport{GatewayID: p.gateway, RecoveryID: p.recovery, Generation: p.generation, AdmissionOpen: p.open}
	}
	return protocol.Encode(report, protocol.MaxFrameBytes)
}

func (p *routingAuditPeer) barrier(body []byte) ([]byte, error) {
	var input protocol.OriginBarrierRequest
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.GatewayID != p.gateway || input.ExpectedRoot != p.context.Root || input.ExpectedGeneration != p.generation || input.Generation == "" {
		return nil, errors.New("unexpected audit fixture barrier")
	}
	p.generation, p.recovery = input.Generation, input.RecoveryID
	return protocol.Encode(protocol.OriginStateReport{GatewayID: p.gateway, RecoveryID: p.recovery, Generation: p.generation}, protocol.MaxFrameBytes)
}

func (p *routingAuditPeer) inventory(body []byte) ([]byte, error) {
	var input protocol.OriginInventoryRequest
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.GatewayID != p.gateway || input.Generation != p.generation || input.ExpectedRoot != p.context.Root || input.Cursor != "" {
		return nil, errors.New("unexpected audit fixture inventory")
	}
	return protocol.Encode(protocol.OriginInventoryReport{Complete: true, MembershipSHA256: strings.Repeat("1", 64), CompletenessReceipt: strings.Repeat("2", 64)}, protocol.MaxFrameBytes)
}

func (p *routingAuditPeer) reopen(body []byte) ([]byte, error) {
	var input protocol.OriginReopenRequest
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.GatewayID != p.gateway || input.Generation != p.generation || input.RecoveryID != p.recovery || input.ExpectedRoot != p.context.Root || input.CompletenessReceipt != strings.Repeat("2", 64) {
		return nil, errors.New("unexpected audit fixture reopen")
	}
	p.open = true
	return protocol.Encode(protocol.OriginStateReport{GatewayID: p.gateway, RecoveryID: p.recovery, Generation: p.generation, AdmissionOpen: true}, protocol.MaxFrameBytes)
}

func (p *routingAuditPeer) admit(body []byte, operation string) ([]byte, error) {
	var input protocol.Admission
	if protocol.DecodeStrict(body, &input, protocol.MaxFrameBytes) != nil || input.Validate() != nil || input.Brief != routingAuditCanary || input.Task.Context != p.context || input.Task.Origin.GatewayID != p.gateway || input.Task.Origin.PrincipalRef != p.principal || input.Task.Origin.OperationID != operation {
		return nil, errors.New("admission lost prepared request identity")
	}
	p.admissions.Add(1)
	task := input.Task
	task.SpecSHA256 = strings.Repeat("a", 64)
	digest := domain.Hash([]byte(input.Brief))
	return protocol.Encode(protocol.TaskObservation{Task: task, BriefSHA256: hex.EncodeToString(digest[:]), Resolution: "existing", Admission: "admitted", Liveness: "running", Publication: "pending"}, protocol.MaxFrameBytes)
}

func startRoutingAuditPeer(t *testing.T, f *fixture, principal string) *routingAuditPeer {
	t.Helper()
	_, certificate := f.enrollDevice(t)
	p := &routingAuditPeer{gateway: string(f.runtime.gatewayID), principal: principal, context: protocol.ContextBinding{Root: protocol.WireContextGuard("private-canary-root"), Project: protocol.WireContextGuard("private-canary-project")}, exchanges: make(chan routingAuditExchange, 1)}
	f.adminCall(t, "/v1/projects", adminapi.RegisterProjectInput{DeviceID: "device", ProjectAlias: "project", RootGuard: p.context.Root, ProjectGuard: p.context.Project}, nil)
	ctx, cancel := context.WithCancel(t.Context())
	client, err := transport.Dial(ctx, transport.ClientConfig{URL: strings.Replace(f.deviceURL(t), "https://", "wss://", 1), GatewayID: f.runtime.gatewayID, Certificate: certificate.Leaf, Capabilities: protocol.CapabilityReport{ObservedAt: time.Now(), Projects: []protocol.ProjectCapability{p.capability()}}, Routing: &emptyCensus{boot: strings.Repeat("a", 32)}}, f.deviceHTTP(t, &certificate), time.Now)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	p.client = client
	done := make(chan error, 1)
	go func() { done <- p.serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("audit peer transport close failed: %v", closeErr)
		}
		select {
		case final := <-done:
			if final != nil && !errors.Is(final, context.Canceled) && !errors.Is(final, transport.ErrOffline) {
				t.Errorf("audit peer failed before cleanup: %v", final)
			}
		case <-time.After(10 * time.Second):
			t.Error("audit peer goroutine did not join")
		}
	})
	ready, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	require(t, f.runtime.hub.WaitReady(ready, "device"))
	return p
}

func routingAuditAdmin(t *testing.T, f *fixture, method, path string, input any) {
	t.Helper()
	status, data := f.request(t, f.admin, method, "http://unix"+path, jsonBytes(t, input), "")
	if status != http.StatusOK {
		t.Fatalf("audit fixture administration failed: status=%d body=%s", status, data)
	}
}

func routingAuditTool[T any](t *testing.T, session *mcp.ClientSession, name string, input any) mcpadapter.Envelope[T] {
	t.Helper()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: input})
	require(t, err)
	encoded, err := json.Marshal(result.StructuredContent)
	require(t, err)
	var envelope mcpadapter.Envelope[T]
	require(t, json.Unmarshal(encoded, &envelope))
	if result.IsError != (envelope.Error != nil) || (envelope.Error == nil) == (envelope.Data == nil) {
		t.Fatal("inconsistent composed MCP response")
	}
	return envelope
}

func TestRuntimeRoutingAuditCorrelatesPreparedDispatchWithoutPayload(t *testing.T) {
	f := configFixture(t)
	f.start(t)
	var principal adminapi.Principal
	f.adminCall(t, "/v1/principals/resolve", adminapi.ResolvePrincipalInput{Issuer: f.cfg.Identity.Issuer, Subject: "subject"}, &principal)
	peer := startRoutingAuditPeer(t, f, principal.PrincipalID)
	routingAuditAdmin(t, f, http.MethodPut, "/v1/grants", adminapi.PutGrantInput{PrincipalID: principal.PrincipalID, DeviceID: "device", ProjectAlias: "project", Scopes: []domain.Scope{domain.TaskDispatch}, Providers: []domain.ProviderID{"provider"}, Permissions: []domain.Permission{domain.ReadOnly}, MaxBudgetSeconds: 60})
	root := adminapi.RootInput{DeviceID: "device", ProjectAlias: "project", RootGuard: peer.context.Root, ProjectGuard: peer.context.Project}
	var progress adminapi.RootProgress
	for range 4 {
		f.adminCall(t, "/v1/roots/initialize", root, &progress)
	}
	if progress.Stage != domain.RootReady {
		t.Fatal("real composed namespace initialization did not reach ready")
	}
	session := f.session(t)
	prepared := prepareRoutingAudit(t, session)
	exchange, dispatchSpan := dispatchRoutingAudit(t, session, peer, prepared)
	denyRoutingAudit(t, f, session, peer, principal.PrincipalID, prepared.OperationID, root)
	assertRoutingAuditCorrelation(t, f, principal.PrincipalID, prepared.OperationID, exchange, dispatchSpan)
}

func prepareRoutingAudit(t *testing.T, session *mcp.ClientSession) mcpadapter.Prepared {
	t.Helper()
	prepared := routingAuditTool[mcpadapter.Prepared](t, session, "prepare_dispatch", mcpadapter.PrepareInput{DeviceID: "device", ProjectAlias: "project", Provider: "provider", Permission: "read-only", BudgetSeconds: 60, Brief: routingAuditCanary})
	if prepared.Error != nil || prepared.Data.OperationID == "" || prepared.Data.TaskID == "" {
		t.Fatal("real composed preparation did not return immutable identity")
	}
	return *prepared.Data
}

func dispatchRoutingAudit(t *testing.T, session *mcp.ClientSession, peer *routingAuditPeer, prepared mcpadapter.Prepared) (routingAuditExchange, time.Duration) {
	t.Helper()
	input := mcpadapter.OperationInput{OperationID: prepared.OperationID}
	started := time.Now()
	for range 2 {
		dispatched := routingAuditTool[mcpadapter.Operation](t, session, "dispatch_task", input)
		if dispatched.Error != nil || dispatched.Data.OperationID != prepared.OperationID || dispatched.Data.TaskID != prepared.TaskID || dispatched.Data.DeviceID != "device" || dispatched.Data.ProjectAlias != "project" {
			t.Fatal("actual dispatch/replay lost prepared correlation")
		}
	}
	dispatchSpan := time.Since(started)
	var exchange routingAuditExchange
	select {
	case exchange = <-peer.exchanges:
	default:
		t.Fatal("successful real dispatch has no peer frame evidence")
	}
	if peer.admissions.Load() != 1 {
		t.Fatal("same-operation dispatch replay sent another admission")
	}
	return exchange, dispatchSpan
}

func denyRoutingAudit(t *testing.T, f *fixture, session *mcp.ClientSession, peer *routingAuditPeer, principal, operation string, root adminapi.RootInput) {
	t.Helper()
	routingAuditAdmin(t, f, http.MethodDelete, "/v1/grants", adminapi.GrantKey{PrincipalID: principal, DeviceID: "device", ProjectAlias: "project"})
	before := peer.commands.Load()
	denied := routingAuditTool[mcpadapter.Operation](t, session, "dispatch_task", mcpadapter.OperationInput{OperationID: operation})
	if denied.Error == nil || denied.Error.Code != "not_found" {
		t.Fatal("composed dispatch ignored removed grant")
	}
	// A subsequent actual control drains the same ordered WSS request lane. The
	// denied call must not insert an admission or any other peer control before it.
	f.adminCall(t, "/v1/projects/refresh", root, nil)
	if peer.commands.Load() != before+1 || peer.admissions.Load() != 1 {
		t.Fatal("denied dispatch sent an extra peer command")
	}
}

func routingAuditRecords(t *testing.T, f *fixture) []observability.Event {
	t.Helper()
	entries, err := os.ReadDir(f.cfg.AuditDirectory)
	require(t, err)
	var events []observability.Event
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "audit-") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(f.cfg.AuditDirectory, entry.Name()))
		require(t, readErr)
		if bytes.Contains(data, []byte(routingAuditCanary)) || bytes.Contains(data, []byte("private-canary-root")) || bytes.Contains(data, []byte("private-canary-project")) {
			t.Fatal("composed operation audit leaked request or local context")
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var event observability.Event
			require(t, json.Unmarshal(line, &event))
			events = append(events, event)
		}
	}
	return events
}

func assertRoutingAuditCorrelation(t *testing.T, f *fixture, principal, operation string, exchange routingAuditExchange, dispatchSpan time.Duration) {
	t.Helper()
	var counts routingAuditCounts
	for _, event := range routingAuditRecords(t, f) {
		if event.Code == observability.AuthorizationDenied && event.Principal == domain.PrincipalID(principal) && event.Control.Class == routing.ControlClass(protocol.Admit) {
			assertDeniedRoutingAudit(t, event.Control)
			counts.denied++
		}
		if event.Operation != domain.OperationID(operation) {
			continue
		}
		assertRoutingAuditIdentity(t, event, principal)
		if event.Code == observability.OperationPrepared {
			if event.Control.Class != routing.PrepareClass || event.Control.Transport != routing.NotAttempted {
				t.Fatal("preparation audit claimed a wire control")
			}
			counts.prepared++
			continue
		}
		if event.Code != observability.ControlCompleted {
			continue
		}
		if event.Control.Transport == routing.NotAttempted {
			assertCachedRoutingAudit(t, event.Control)
			counts.cached++
			continue
		}
		assertRoutingAuditTransfer(t, event.Control, exchange, dispatchSpan)
		counts.completed++
	}
	if counts != (routingAuditCounts{prepared: 1, completed: 1, cached: 1, denied: 1}) {
		t.Fatalf("composed operation audit correlation missing: %+v; expected one of each", counts)
	}
	assertRoutingAuditMetrics(t, f, principal, operation, exchange)
	if health := f.runtime.Health(); !health.AuditHealthy || health.AuditFailures != 0 || health.MetricFailures != 0 {
		t.Fatal("composed audit or metrics silently rejected routing metadata")
	}
}

func assertRoutingAuditIdentity(t *testing.T, event observability.Event, principal string) {
	t.Helper()
	if event.Principal != domain.PrincipalID(principal) || event.Device != "device" || event.Project != "project" || event.Control.Actor != routing.PrincipalActor || event.Control.Authorization != routing.Allowed {
		t.Fatal("operation audit identity differs from authenticated prepared destination")
	}
}

func assertDeniedRoutingAudit(t *testing.T, metadata routing.ControlMetadata) {
	t.Helper()
	if metadata.Authorization != routing.DeniedOrMissing || metadata.Transport != routing.NotAttempted || metadata.WriteState != routing.WriteNotStarted || metadata.EncodedRequestFrameBytes != 0 || metadata.EncodedResponseFrameBytes != 0 {
		t.Fatal("denied invocation fabricated authorization or transport")
	}
}

func assertCachedRoutingAudit(t *testing.T, metadata routing.ControlMetadata) {
	t.Helper()
	if metadata.Class != routing.ControlClass(protocol.Admit) || metadata.WriteState != routing.WriteNotStarted || metadata.Request != "" || metadata.Connection != (domain.ConnectionGeneration{}) || metadata.EncodedRequestFrameBytes != 0 || metadata.EncodedResponseFrameBytes != 0 || metadata.ResponseKnown {
		t.Fatal("cached replay audit fabricated another wire control")
	}
}

func assertRoutingAuditTransfer(t *testing.T, metadata routing.ControlMetadata, exchange routingAuditExchange, dispatchSpan time.Duration) {
	t.Helper()
	if metadata.Class != routing.ControlClass(protocol.Admit) || metadata.Recheck != routing.Allowed || metadata.Transport != routing.ReplyReceived || metadata.WriteState != routing.WriteCompleted || !metadata.ResponseKnown {
		t.Fatal("actual routing audit lost class, final authorization or observed response")
	}
	if metadata.Request != exchange.request || metadata.Connection != exchange.connection || metadata.EncodedRequestFrameBytes != exchange.requestBytes || metadata.EncodedResponseFrameBytes != exchange.responseBytes {
		t.Fatal("routing audit lengths or identities differ from the actual peer frames")
	}
	if metadata.DurationNS <= 0 || metadata.DurationNS > dispatchSpan.Nanoseconds() {
		t.Fatal("control observation duration is missing or outside its actual call interval")
	}
}

func assertRoutingAuditMetrics(t *testing.T, f *fixture, principal, operation string, exchange routingAuditExchange) {
	t.Helper()
	status, data := f.request(t, f.admin, http.MethodGet, "http://unix/v1/metadata/metrics", nil, "")
	if status != http.StatusOK {
		t.Fatal("composed protected metrics unavailable")
	}
	for _, forbidden := range []string{routingAuditCanary, principal, operation, "private-canary-root", "private-canary-project"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatal("composed metrics exposed payload or identity labels")
		}
	}
	for _, expected := range []string{
		`gateway_control_observations_total{class="admit",transport="reply_received"} 1` + "\n",
		fmt.Sprintf("gateway_observed_request_frame_bytes_total{class=\"admit\",transport=\"reply_received\"} %d\n", exchange.requestBytes),
		fmt.Sprintf("gateway_observed_response_frame_bytes_total{class=\"admit\",transport=\"reply_received\"} %d\n", exchange.responseBytes),
	} {
		if !bytes.Contains(data, []byte(expected)) {
			t.Fatal("composed metrics lost actual routed control observations")
		}
	}
}
