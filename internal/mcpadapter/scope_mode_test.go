package mcpadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestFileAccessRequiresBothTokenScopesBeforeHandler(t *testing.T) {
	f := newFixture(t, 0)
	calls := 0
	type input struct{}
	type output struct {
		Accepted bool `json:"accepted"`
	}
	check(t, register(f.adapter, "file_access_probe", "Test all-of scope boundary", []domain.Scope{domain.TaskDispatch, domain.TaskRead}, toolHints{ReadOnly: true, Idempotent: true, AllScopes: true}, func(context.Context, domain.Actor, input) (output, error) {
		calls++
		return output{Accepted: true}, nil
	}))
	for _, token := range []string{"inventory", "read", "dispatch"} {
		result := f.call(t, f.session(t, token), "file_access_probe", json.RawMessage(`{}`))
		expectError[output](t, result, "forbidden")
		if calls != 0 {
			t.Fatal("partial token authority reached file handler")
		}
	}
	result := decodeResult[output](t, f.call(t, f.session(t, "alice"), "file_access_probe", json.RawMessage(`{}`)))
	if result.Error != nil || result.Data == nil || !result.Data.Accepted || calls != 1 {
		t.Fatal("combined task scopes did not authorize file handler")
	}
}

func TestRefreshAcquisitionHintDoesNotBecomeResourceScope(t *testing.T) {
	f := newFixture(t, 0)
	// A valid task-only token works without offline_access in its bearer claims.
	result := decodeResult[DevicePage](t, f.call(t, f.session(t, "inventory"), "list_devices", json.RawMessage(`{}`)))
	if result.Error != nil || result.Data == nil {
		t.Fatal("refresh acquisition hint became a required bearer permission")
	}
	challenge := f.adapter.challenge("invalid_token", "Expired", []domain.Scope{domain.TaskDispatch, domain.TaskRead})
	if !strings.Contains(challenge, `scope="task:dispatch task:read offline_access"`) {
		t.Fatal("refresh and all-of scopes absent from acquisition challenge")
	}
	if strings.Contains(f.adapter.challenge("insufficient_scope", "Missing", []domain.Scope{domain.TaskDispatch, domain.TaskRead}), "offline_access") {
		t.Fatal("incremental task permission requires refresh permission")
	}
}
