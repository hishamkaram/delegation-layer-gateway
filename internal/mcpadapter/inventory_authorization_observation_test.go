package mcpadapter

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/gateway"
	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type inventoryObservationFixture struct {
	*fixture
	directory string
	recorder  *observability.Recorder
	metrics   *observability.Metrics
}

func newInventoryObservationFixture(t *testing.T) *inventoryObservationFixture {
	t.Helper()
	directory := t.TempDir()
	check(t, os.Chmod(directory, 0o700))
	audit, err := observability.Open(directory, time.Now)
	check(t, err)
	t.Cleanup(func() { check(t, audit.Close()) })
	metrics := &observability.Metrics{}
	recorder, err := observability.NewRecorder(audit, metrics)
	check(t, err)
	return &inventoryObservationFixture{fixture: newRecordedFixture(t, 1, recorder), directory: directory, recorder: recorder, metrics: metrics}
}

func (f *inventoryObservationFixture) assertEvents(t *testing.T, codes ...observability.Code) {
	t.Helper()
	entries, err := os.ReadDir(f.directory)
	check(t, err)
	var events []observability.Event
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "audit-") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(f.directory, entry.Name()))
		check(t, readErr)
		for _, private := range []string{privateCanary, "hidden-alias-canary", string(deviceID(0))} {
			if strings.Contains(string(data), private) {
				t.Fatalf("inventory audit retained a rejected target or private marker: %s", private)
			}
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var event observability.Event
			check(t, json.Unmarshal([]byte(line), &event))
			events = append(events, event)
		}
	}
	if len(events) != len(codes) {
		t.Fatalf("inventory audit event count=%d, want %d: %+v", len(events), len(codes), events)
	}
	denials := 0
	for i, code := range codes {
		if events[i] != (observability.Event{Code: code, Principal: f.alice.Principal}) {
			t.Fatalf("inventory audit event %d lost ordering or enriched the rejected target: %+v", i, events[i])
		}
		if code == observability.AuthorizationDenied {
			denials++
		}
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://unix/v1/metadata/metrics", nil)
	check(t, err)
	response := httptest.NewRecorder()
	f.metrics.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), `gateway_events_total{event="authorization_denied"} `+strconv.Itoa(denials)+"\n") {
		t.Fatalf("inventory denial metric does not match the exact audit count: %s", response.Body.String())
	}
	if health := f.recorder.Health(); !health.AuditHealthy || health.AuditFailures != 0 || health.MetricFailures != 0 {
		t.Fatalf("inventory observations failed metadata validation: %+v", health)
	}
}

func TestInventoryRegistryDenialsAreObservedWithoutTargetMetadata(t *testing.T) {
	for _, name := range []string{"list_devices", "list_projects", "get_capabilities"} {
		t.Run(name, func(t *testing.T) {
			f := newInventoryObservationFixture(t)
			session := f.session(t, "inventory")
			code := "forbidden"
			if name == "get_capabilities" {
				f.project(t, "hidden-alias-canary", false)
				code = "not_found"
			} else {
				check(t, f.store.SetPrincipalRevoked(t.Context(), f.alice.Principal, true))
			}
			result := f.call(t, session, name, inventoryObservationArgs(t, name))
			expectError[json.RawMessage](t, result, code)
			assertPublic(t, result)
			f.assertEvents(t, observability.AuthorizationDenied, observability.MCPToolErrorReady)
		})
	}
}

func TestInventoryHiddenProjectFilteringDoesNotRecordDenials(t *testing.T) {
	f := newInventoryObservationFixture(t)
	f.project(t, "hidden-alias-canary", false)
	hidden := f.link.snapshot.Capabilities.Projects[0]
	hidden.Alias = "hidden-alias-canary"
	f.link.snapshot.Capabilities.Projects = append(f.link.snapshot.Capabilities.Projects, hidden)
	session := f.session(t, "inventory")
	devices := f.call(t, session, "list_devices", inventoryObservationArgs(t, "list_devices"))
	assertPublic(t, devices)
	devicePage := decodeResult[DevicePage](t, devices)
	if devicePage.Error != nil || devicePage.Data == nil || len(devicePage.Data.Devices) != 1 {
		t.Fatal("hidden project filtering changed the authorized device inventory")
	}
	projects := f.call(t, session, "list_projects", inventoryObservationArgs(t, "list_projects"))
	assertPublic(t, projects)
	projectPage := decodeResult[ProjectPage](t, projects)
	if projectPage.Error != nil || projectPage.Data == nil || len(projectPage.Data.Projects) != 1 || projectPage.Data.Projects[0].Alias != "public" {
		t.Fatal("hidden project filtering changed the authorized project inventory")
	}
	f.assertEvents(t, observability.MCPToolResponseReady, observability.MCPToolResponseReady)
}

type inventoryAuthorizationFaultRegistry struct {
	Registry
	failure error
}

func (r inventoryAuthorizationFaultRegistry) ListDevices(context.Context, domain.Actor, domain.DevicePageRequest) (domain.DevicePage, error) {
	return domain.DevicePage{}, r.failure
}

func (r inventoryAuthorizationFaultRegistry) ListProjects(context.Context, domain.Actor, domain.DeviceID, domain.ProjectPageRequest) (domain.ProjectPage, error) {
	return domain.ProjectPage{}, r.failure
}

func (r inventoryAuthorizationFaultRegistry) Authorize(context.Context, domain.AuthorizationRequest) (domain.Authorization, error) {
	return domain.Authorization{}, r.failure
}

func (r inventoryAuthorizationFaultRegistry) ListOperations(context.Context, domain.Actor, domain.OperationPageRequest) (domain.OperationPage, error) {
	return domain.OperationPage{}, r.failure
}

func TestInventoryMixedOperationalFaultIsNotAuthorizationDenial(t *testing.T) {
	for _, name := range []string{"list_devices", "list_projects", "get_capabilities", "list_operations"} {
		t.Run(name, func(t *testing.T) {
			f := newInventoryObservationFixture(t)
			policy := domain.Reject(domain.NotFound)
			storage := errors.New(privateCanary)
			failure := errors.Join(policy, storage)
			f.adapter.options.Registry = inventoryAuthorizationFaultRegistry{Registry: f.store, failure: failure}
			token := "inventory"
			if name == "list_operations" {
				token = "read"
			}
			session := f.session(t, token)
			result := f.call(t, session, name, inventoryObservationArgs(t, name))
			// A known policy leaf cannot classify an independent storage failure.
			expectError[json.RawMessage](t, result, "internal_error")
			assertPublic(t, result)
			err := inventoryObservationCall(t, f.adapter, f.alice, name)
			assertInventoryErrorGraph(t, err, failure, policy, storage)
			f.assertEvents(t, observability.MCPToolErrorReady)
		})
	}
}

func assertInventoryErrorGraph(t *testing.T, err, failure, policy, storage error) {
	t.Helper()
	var original *domain.Error
	if !errors.Is(err, failure) || !errors.Is(err, policy) || !errors.Is(err, storage) || !errors.As(err, &original) || original.Code != domain.NotFound {
		t.Fatal("inventory observation changed the original mixed error graph")
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatal("inventory observation added a wrapper around the original join")
	}
	causes := joined.Unwrap()
	if len(causes) != 2 {
		t.Fatal("inventory observation changed the original two-cause join")
	}
	for i, expected := range []error{policy, storage} {
		_, wrapped := causes[i].(interface{ Unwrap() error })
		_, nestedJoin := causes[i].(interface{ Unwrap() []error })
		if wrapped || nestedJoin || !errors.Is(causes[i], expected) {
			t.Fatal("inventory observation replaced or wrapped an original error leaf")
		}
	}
}

// Revoke through the real Registry after the initial inventory authorization,
// immediately before its readiness transaction rechecks the same grant.
type inventoryReadinessRevocation struct {
	Registry
	revoke func(context.Context) error
	fault  error
}

func (r inventoryReadinessRevocation) CheckProjectReadiness(ctx context.Context, input domain.ProjectReadinessRequest) (bool, error) {
	if err := r.revoke(ctx); err != nil {
		return false, err
	}
	ready, err := r.Registry.CheckProjectReadiness(ctx, input)
	return ready, errors.Join(err, r.fault)
}

func TestInventoryLateReadinessDenialIsObserved(t *testing.T) {
	for _, test := range []struct {
		name  string
		fault error
		code  string
		codes []observability.Code
	}{
		{name: "sole-policy", code: "not_found", codes: []observability.Code{observability.AuthorizationDenied, observability.MCPToolErrorReady}},
		{name: "mixed-storage", fault: errors.New(privateCanary), code: "internal_error", codes: []observability.Code{observability.MCPToolErrorReady}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, name := range []string{"list_devices", "list_projects", "get_capabilities"} {
				t.Run(name, func(t *testing.T) {
					f := newInventoryObservationFixture(t)
					f.adapter.options.Registry = inventoryReadinessRevocation{Registry: f.store, fault: test.fault, revoke: func(ctx context.Context) error {
						return f.store.RevokeGrant(ctx, domain.GrantKey{Principal: f.alice.Principal, Destination: domain.Destination{Device: deviceID(0), Project: "public"}})
					}}
					session := f.session(t, "inventory")
					result := f.call(t, session, name, inventoryPublicObservationArgs(t, name))
					expectError[json.RawMessage](t, result, test.code)
					assertPublic(t, result)
					f.assertEvents(t, test.codes...)
				})
			}
		})
	}
}

func TestInventoryIneligibleReadinessDoesNotRecordDenial(t *testing.T) {
	for _, name := range []string{"list_devices", "list_projects", "get_capabilities"} {
		t.Run(name, func(t *testing.T) {
			f := newInventoryObservationFixture(t)
			capability := &f.link.snapshot.Capabilities.Projects[0]
			if capability.AdmissionGeneration == strings.Repeat("a", 32) {
				capability.AdmissionGeneration = strings.Repeat("b", 32)
			} else {
				capability.AdmissionGeneration = strings.Repeat("a", 32)
			}
			session := f.session(t, "inventory")
			result := f.call(t, session, name, inventoryPublicObservationArgs(t, name))
			assertPublic(t, result)
			if result.IsError {
				t.Fatal("ordinary ineligible readiness became a public authorization failure")
			}
			f.assertEvents(t, observability.MCPToolResponseReady)
		})
	}
}

type inventoryOperationsRevocation struct {
	Registry
	revoke func(context.Context) error
}

func (r inventoryOperationsRevocation) ListOperations(ctx context.Context, actor domain.Actor, input domain.OperationPageRequest) (domain.OperationPage, error) {
	if err := r.revoke(ctx); err != nil {
		return domain.OperationPage{}, err
	}
	return r.Registry.ListOperations(ctx, actor, input)
}

func TestInventoryOperationListDenialIsObserved(t *testing.T) {
	f := newInventoryObservationFixture(t)
	f.adapter.options.Registry = inventoryOperationsRevocation{Registry: f.store, revoke: func(ctx context.Context) error {
		return f.store.SetPrincipalRevoked(ctx, f.alice.Principal, true)
	}}
	// A task-read scope reaches the Registry boundary instead of the MCP
	// inventory-only token's earlier insufficient-scope rejection.
	session := f.session(t, "read")
	result := f.call(t, session, "list_operations", inventoryObservationArgs(t, "list_operations"))
	expectError[OperationPage](t, result, "forbidden")
	assertPublic(t, result)
	f.assertEvents(t, observability.AuthorizationDenied, observability.MCPToolErrorReady)
}

type inventoryHiddenProjectFault struct {
	Registry
	fault error
}

func (r inventoryHiddenProjectFault) Authorize(ctx context.Context, request domain.AuthorizationRequest) (domain.Authorization, error) {
	authorized, err := r.Registry.Authorize(ctx, request)
	if request.Destination.Project == "hidden-alias-canary" {
		return authorized, errors.Join(err, r.fault)
	}
	return authorized, err
}

func TestInventoryHiddenProjectMixedFaultIsNotSilentlyFiltered(t *testing.T) {
	f := newInventoryObservationFixture(t)
	f.project(t, "hidden-alias-canary", false)
	hidden := f.link.snapshot.Capabilities.Projects[0]
	hidden.Alias = "hidden-alias-canary"
	f.link.snapshot.Capabilities.Projects = append(f.link.snapshot.Capabilities.Projects, hidden)
	f.adapter.options.Registry = inventoryHiddenProjectFault{Registry: f.store, fault: errors.New(privateCanary)}
	session := f.session(t, "inventory")
	result := f.call(t, session, "list_devices", inventoryObservationArgs(t, "list_devices"))
	expectError[DevicePage](t, result, "internal_error")
	assertPublic(t, result)
	f.assertEvents(t, observability.MCPToolErrorReady)
}

func TestInventoryEarlyScopeDenialIsRecordedOnce(t *testing.T) {
	f := newInventoryObservationFixture(t)
	session := f.session(t, "inventory")
	result := f.call(t, session, "list_operations", inventoryObservationArgs(t, "list_operations"))
	expectError[OperationPage](t, result, "forbidden")
	assertPublic(t, result)
	f.assertEvents(t, observability.AuthorizationDenied, observability.MCPToolErrorReady)
}

func TestInventoryObservationDoesNotDuplicateRoutedTaskDenial(t *testing.T) {
	f := newInventoryObservationFixture(t)
	// The actual Gateway denial already has its own observer. This fixture sink
	// records it so an additional adapter event would be visible as a duplicate.
	observer := gateway.RoutingObserverFunc(func(value gateway.RoutingObservation) {
		if value.Control.Authorization == routing.DeniedOrMissing {
			f.recorder.Record(observability.Event{Code: observability.AuthorizationDenied, Principal: value.Principal})
		}
	})
	identity, err := f.store.Identity(t.Context())
	check(t, err)
	service, err := gateway.New(f.store, f.link, identity, rand.Reader, f.clock.now, observer)
	check(t, err)
	f.adapter.options.Operations = service
	session := f.session(t, "alice")
	prepared := decodeResult[Prepared](t, f.call(t, session, "prepare_dispatch", args(t, prepareFixture(privateCanary))))
	if prepared.Error != nil || prepared.Data == nil {
		t.Fatal("valid task preparation failed before the denial boundary")
	}
	check(t, f.store.RevokeGrant(t.Context(), domain.GrantKey{Principal: f.alice.Principal, Destination: domain.Destination{Device: deviceID(0), Project: "public"}}))
	result := f.call(t, session, "dispatch_task", args(t, OperationInput{OperationID: prepared.Data.OperationID}))
	expectError[Operation](t, result, "not_found")
	assertPublic(t, result)
	if len(f.link.commands) != 0 {
		t.Fatal("routed policy denial published a connector command")
	}
	f.assertEvents(t, observability.MCPToolResponseReady, observability.AuthorizationDenied, observability.MCPToolErrorReady)
}

func inventoryPublicObservationArgs(t *testing.T, name string) json.RawMessage {
	t.Helper()
	if name == "get_capabilities" {
		return args(t, CapabilitiesInput{DeviceID: string(deviceID(0)), ProjectAlias: "public"})
	}
	return inventoryObservationArgs(t, name)
}

func inventoryObservationArgs(t *testing.T, name string) json.RawMessage {
	t.Helper()
	switch name {
	case "list_devices", "list_operations":
		return json.RawMessage(`{}`)
	case "list_projects":
		return args(t, ProjectsInput{DeviceID: string(deviceID(0))})
	case "get_capabilities":
		return args(t, CapabilitiesInput{DeviceID: string(deviceID(0)), ProjectAlias: "hidden-alias-canary"})
	default:
		t.Fatalf("unsupported inventory test tool: %s", name)
		return nil
	}
}

func inventoryObservationCall(t *testing.T, adapter *Adapter, actor domain.Actor, name string) error {
	t.Helper()
	switch name {
	case "list_devices":
		_, err := adapter.devices(t.Context(), actor, PageInput{})
		return err
	case "list_projects":
		_, err := adapter.projects(t.Context(), actor, ProjectsInput{DeviceID: string(deviceID(0))})
		return err
	case "get_capabilities":
		_, err := adapter.capabilities(t.Context(), actor, CapabilitiesInput{DeviceID: string(deviceID(0)), ProjectAlias: "hidden-alias-canary"})
		return err
	case "list_operations":
		_, err := adapter.operations(t.Context(), actor, PageInput{})
		return err
	default:
		t.Fatalf("unsupported inventory test tool: %s", name)
		return nil
	}
}
