package adminapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type routingDrainPort struct {
	read   func(context.Context, domain.DeviceID, time.Time) (routing.DrainTarget, error)
	attest func(context.Context, routing.Drain) (routing.DrainResult, error)
}

func (p routingDrainPort) ReadRoutingDrainTarget(ctx context.Context, id domain.DeviceID, now time.Time) (routing.DrainTarget, error) {
	return p.read(ctx, id, now)
}

func (p routingDrainPort) AttestRoutingDrained(ctx context.Context, d routing.Drain) (routing.DrainResult, error) {
	return p.attest(ctx, d)
}

type generationCloser func(context.Context, domain.CredentialRef, domain.ConnectionGeneration) (adminapi.ConnectionStatus, error)

func (f generationCloser) DisconnectGeneration(ctx context.Context, c domain.CredentialRef, g domain.ConnectionGeneration) (adminapi.ConnectionStatus, error) {
	return f(ctx, c, g)
}

func frozenDrain() (adminapi.RoutingDrainInput, routing.DrainTarget) {
	confirmed := true
	target := routing.DrainTarget{Device: "device", Recovery: "restore", Credential: domain.CredentialRef{Device: "device", Epoch: "epoch", Generation: 3}, ProcessBoot: strings.Repeat("b", 32), Generation: domain.ConnectionGeneration{BootEpoch: "gateway-boot", Counter: 7}, Blocked: true}
	input := adminapi.RoutingDrainInput{DeviceID: "device", RecoveryID: "restore", ExpectedCredential: adminapi.CredentialBinding{DeviceID: "device", Epoch: "epoch", Generation: 3}, ExpectedProcessBoot: strings.Repeat("b", 32), ExpectedConnection: protocol.Generation{BootEpoch: "gateway-boot", Counter: 7}, Scope: routing.AllPriorControls, PriorCLIJoinsConfirmed: &confirmed}
	return input, target
}

func drainJSON(t *testing.T, input adminapi.RoutingDrainInput) string {
	t.Helper()
	data, err := json.Marshal(input)
	check(t, err)
	return string(data)
}

func TestUnixRoutingDrainFrozenIdentityAndCommit(t *testing.T) {
	for _, status := range []adminapi.ConnectionStatus{adminapi.ConnectionJoined, adminapi.ConnectionRetired} {
		t.Run(string(status), func(t *testing.T) { testUnixRoutingDrainCommit(t, status) })
	}
}

func testUnixRoutingDrainCommit(t *testing.T, status adminapi.ConnectionStatus) {
	t.Helper()
	input, target := frozenDrain()
	committed, closed := false, false
	var trustedNow time.Time
	port := routingDrainPort{read: func(ctx context.Context, id domain.DeviceID, now time.Time) (routing.DrainTarget, error) {
		if id != "device" {
			t.Errorf("wrong target device: %s", id)
		}
		trustedNow = now
		return target, nil
	}, attest: func(ctx context.Context, d routing.Drain) (routing.DrainResult, error) {
		want := routing.Drain{Device: "device", Recovery: "restore", Credential: target.Credential, Generation: target.Generation, CurrentBoot: target.ProcessBoot, Scope: routing.AllPriorControls, Now: trustedNow}
		if d != want {
			t.Errorf("frozen binding changed: got %+v want %+v", d, want)
		}
		committed = true
		target.Blocked = false
		target.Covered = true
		return routing.DrainResult{Disposition: routing.Drained, Target: target}, nil
	}}
	closer := generationCloser(func(ctx context.Context, c domain.CredentialRef, g domain.ConnectionGeneration) (adminapi.ConnectionStatus, error) {
		if !committed || c != target.Credential || g != target.Generation {
			t.Error("disconnect did not use committed captured identity")
		}
		closed = true
		return status, nil
	})
	f := newFixtureOptions(t, nil, func(o *adminapi.Options) { o.RoutingDrains = port; o.GenerationDisconnector = closer })
	var gotTarget adminapi.RoutingDrainTarget
	f.call(t, http.MethodPost, "/v1/routing/drain-target", `{"device_id":"device"}`, &gotTarget)
	check(t, gotTarget.Validate())
	wantTarget := adminapi.RoutingDrainTarget{DeviceID: "device", RecoveryID: "restore", Credential: input.ExpectedCredential, Connection: input.ExpectedConnection, ProcessBoot: input.ExpectedProcessBoot, Blocked: true}
	if gotTarget != wantTarget || trustedNow != f.now {
		t.Fatalf("target changed: %+v", gotTarget)
	}
	var response adminapi.RoutingDrainResponse
	f.call(t, http.MethodPost, "/v1/routing/drain", drainJSON(t, input), &response)
	check(t, response.Validate())
	if !committed || !closed || !response.Committed || response.Disposition != routing.Drained || response.ConnectionStatus != status {
		t.Fatalf("drain result: %+v", response)
	}
}

func TestUnixRoutingDrainAlreadySatisfiedNeverDisconnects(t *testing.T) {
	input, target := frozenDrain()
	target.Blocked = false
	target.Covered = true
	target.Generation.Counter++
	calls := 0
	f := newFixtureOptions(t, nil, func(o *adminapi.Options) {
		o.RoutingDrains = routingDrainPort{attest: func(context.Context, routing.Drain) (routing.DrainResult, error) {
			calls++
			return routing.DrainResult{Disposition: routing.AlreadySatisfied, Target: target}, nil
		}}
		o.GenerationDisconnector = generationCloser(func(context.Context, domain.CredentialRef, domain.ConnectionGeneration) (adminapi.ConnectionStatus, error) {
			t.Error("no-op disconnected")
			return adminapi.ConnectionJoined, nil
		})
	})
	var response adminapi.RoutingDrainResponse
	f.call(t, http.MethodPost, "/v1/routing/drain", drainJSON(t, input), &response)
	check(t, response.Validate())
	if calls != 1 || response.Committed || response.Disposition != routing.AlreadySatisfied || response.ConnectionStatus != adminapi.ConnectionUnchanged || response.Target.Connection.Counter != 8 {
		t.Fatalf("no-op changed meaning: %+v", response)
	}
}

func TestUnixRoutingDrainDisconnectFailureKeepsCommit(t *testing.T) {
	input, target := frozenDrain()
	f := newFixtureOptions(t, nil, func(o *adminapi.Options) {
		o.RoutingDrains = routingDrainPort{attest: func(context.Context, routing.Drain) (routing.DrainResult, error) {
			return routing.DrainResult{Disposition: routing.Drained, Target: target}, nil
		}}
		o.GenerationDisconnector = generationCloser(func(context.Context, domain.CredentialRef, domain.ConnectionGeneration) (adminapi.ConnectionStatus, error) {
			return "", errors.New("secret-path-canary")
		})
	})
	status, data := f.request(t, http.MethodPost, "/v1/routing/drain", drainJSON(t, input))
	var failure adminapi.Failure
	check(t, json.Unmarshal(data, &failure))
	if status != 503 || !failure.Committed || failure.Code != "disconnect_unconfirmed" || bytes.Contains(data, []byte("canary")) {
		t.Fatalf("commit failure response: %d %s", status, data)
	}
}

func TestUnixRoutingDrainRejectsWithoutEffects(t *testing.T) {
	input, _ := frozenDrain()
	port := routingDrainPort{read: func(context.Context, domain.DeviceID, time.Time) (routing.DrainTarget, error) {
		t.Error("invalid read reached Registry")
		return routing.DrainTarget{}, nil
	}, attest: func(context.Context, routing.Drain) (routing.DrainResult, error) {
		t.Error("invalid mutation reached Registry")
		return routing.DrainResult{}, nil
	}}
	closer := generationCloser(func(context.Context, domain.CredentialRef, domain.ConnectionGeneration) (adminapi.ConnectionStatus, error) {
		t.Error("invalid mutation disconnected")
		return adminapi.ConnectionJoined, nil
	})
	f := newFixtureOptions(t, nil, func(o *adminapi.Options) { o.RoutingDrains = port; o.GenerationDisconnector = closer })
	body := drainJSON(t, input)
	noConfirmation := input
	noConfirmation.PriorCLIJoinsConfirmed = nil
	falseConfirmation := input
	no := false
	falseConfirmation.PriorCLIJoinsConfirmed = &no
	badBinding := input
	badBinding.ExpectedCredential.DeviceID = "other"
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/v1/routing/drain", body, 405},
		{http.MethodPost, "/v1/routing/drain?x=y", body, 400},
		{http.MethodPost, "/v1/routing/drain", drainJSON(t, noConfirmation), 400},
		{http.MethodPost, "/v1/routing/drain", drainJSON(t, falseConfirmation), 400},
		{http.MethodPost, "/v1/routing/drain", drainJSON(t, badBinding), 400},
		{http.MethodPost, "/v1/routing/drain", strings.TrimSuffix(body, "}") + `,"unknown":true}`, 400},
		{http.MethodPost, "/v1/routing/drain", strings.Repeat(" ", adminapi.MaxBodyBytes) + body, 400},
		{http.MethodPost, "/v1/routing/drain-target", `{"device_id":"../private"}`, 400},
	} {
		status, data := f.request(t, tc.method, tc.path, tc.body)
		if status != tc.status {
			t.Fatalf("rejection: %d %s", status, data)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/routing/drain", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-private request: %d", response.Code)
	}
	// A missing exact-generation closer must fail before Registry mutation.
	missing := newFixtureOptions(t, nil, func(o *adminapi.Options) { o.RoutingDrains = port })
	status, data := missing.request(t, http.MethodPost, "/v1/routing/drain", body)
	if status != http.StatusConflict {
		t.Fatalf("missing closer: %d %s", status, data)
	}
}

func TestRoutingDrainResponseRejectsInconsistentOutcomes(t *testing.T) {
	input, _ := frozenDrain()
	target := adminapi.RoutingDrainTarget{DeviceID: input.DeviceID, RecoveryID: input.RecoveryID, Credential: input.ExpectedCredential, ProcessBoot: input.ExpectedProcessBoot, Connection: input.ExpectedConnection, Covered: true}
	valid := adminapi.RoutingDrainResponse{Committed: true, Disposition: routing.Drained, Target: target, ConnectionStatus: adminapi.ConnectionJoined}
	check(t, valid.Validate())
	for _, mutate := range []func(*adminapi.RoutingDrainResponse){
		func(r *adminapi.RoutingDrainResponse) { r.Committed = false },
		func(r *adminapi.RoutingDrainResponse) { r.ConnectionStatus = adminapi.ConnectionUnchanged },
		func(r *adminapi.RoutingDrainResponse) { r.Target.Credential.Generation = 0 },
		func(r *adminapi.RoutingDrainResponse) { r.Disposition = "unknown" },
	} {
		bad := valid
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("accepted inconsistent outcome: %+v", bad)
		}
	}
	valid.Committed = false
	valid.Disposition = routing.AlreadySatisfied
	valid.ConnectionStatus = adminapi.ConnectionUnchanged
	check(t, valid.Validate())
	for _, mutate := range []func(*adminapi.RoutingDrainResponse){
		func(r *adminapi.RoutingDrainResponse) { r.Committed = true },
		func(r *adminapi.RoutingDrainResponse) { r.ConnectionStatus = adminapi.ConnectionRetired },
		func(r *adminapi.RoutingDrainResponse) { r.Target.Blocked = true },
		func(r *adminapi.RoutingDrainResponse) { r.Target.Covered = false },
	} {
		bad := valid
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("accepted inconsistent no-op: %+v", bad)
		}
	}
}

func TestUnixRoutingDrainRegistryDenialNeverDisconnects(t *testing.T) {
	input, _ := frozenDrain()
	input.Scope = routing.KnownPriorBoot
	input.PriorBoot = strings.Repeat("a", 32)
	called := false
	f := newFixtureOptions(t, nil, func(o *adminapi.Options) {
		o.RoutingDrains = routingDrainPort{attest: func(ctx context.Context, d routing.Drain) (routing.DrainResult, error) {
			called = true
			if d.Scope != routing.KnownPriorBoot || d.PriorBoot != strings.Repeat("a", 32) {
				t.Errorf("prior boot scope changed: %+v", d)
			}
			return routing.DrainResult{}, domain.Reject(domain.Forbidden)
		}}
		o.GenerationDisconnector = generationCloser(func(context.Context, domain.CredentialRef, domain.ConnectionGeneration) (adminapi.ConnectionStatus, error) {
			t.Error("denied mutation disconnected")
			return adminapi.ConnectionJoined, nil
		})
	})
	status, data := f.request(t, http.MethodPost, "/v1/routing/drain", drainJSON(t, input))
	var failure adminapi.Failure
	check(t, json.Unmarshal(data, &failure))
	if !called || status != http.StatusForbidden || failure.Committed || failure.Code != "forbidden" {
		t.Fatalf("denied mutation response: %d %s", status, data)
	}
}
