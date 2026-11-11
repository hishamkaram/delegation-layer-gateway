package registry

import (
	"fmt"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestDispatchReplayCannotReadCachedResult(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "result-privacy")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireOK(t, err)
	dispatcher := domain.Actor{Principal: f.actor.Principal, Scopes: domain.ScopeSet{domain.TaskDispatch}}
	dispatch, err := f.store.GetForDispatch(t.Context(), dispatcher, c.Operation, f.now)
	if view := must(t, dispatch, err); view.Operation.Delivery != domain.PossibleSend || view.Request.Brief != "" || view.Operation.Observation != nil {
		t.Fatal("possible-send duplicate failed to return private dispatch view")
	}
	observation := domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Terminal, Closure: canonicalClosureEvidence(), ObservedAt: f.now, SpecDigest: domain.Hash([]byte("spec")), Result: &domain.ResultDescriptor{Digest: domain.Hash([]byte("accepted result")), Bytes: 15}}}
	_, err = f.store.ApplyResolution(t.Context(), domain.ValidatedResolution{ValidatedObservation: observation, DurableRequest: true})
	requireOK(t, err)
	dispatch, err = f.store.GetForDispatch(t.Context(), dispatcher, c.Operation, f.now)
	if view := must(t, dispatch, err); view.Operation.Delivery != domain.Resolved || view.Request.Brief != "" || view.Operation.Observation != nil {
		t.Fatal("resolved duplicate exposed request or results")
	}
	decision, err := f.markSettledControl(t.Context(), dispatcher, f.transmission(c))
	got := must(t, decision, err)
	if got.Kind != domain.ObserveExisting || got.Operation.Observation != nil || got.Request.Brief != "" {
		t.Fatal("dispatch-only confirmation exposed cached result or original request")
	}
	_, err = f.store.GetOperation(t.Context(), dispatcher, c.Operation)
	requireCode(t, err, domain.Forbidden)
}

func TestUnknownObservationCannotEraseImmutableSpecBinding(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "spec-continuity")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireOK(t, err)
	observation := domain.ValidatedObservation{Correlation: c, Credential: f.credential, Connection: f.connection, Now: f.now, Observation: domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("original spec"))}}
	requireOK(t, f.store.RecordObservation(t.Context(), observation))
	observation.Observation = domain.DelegateObservation{Kind: domain.Unknown, ObservedAt: f.now}
	requireOK(t, f.store.RecordObservation(t.Context(), observation))
	observation.Observation = domain.DelegateObservation{Kind: domain.Existing, ObservedAt: f.now, SpecDigest: domain.Hash([]byte("substituted spec"))}
	requireCode(t, f.store.RecordObservation(t.Context(), observation), domain.Conflict)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "new-boot", f.now)
	_ = must(t, connection, err)
	observation.Observation.SpecDigest = domain.Hash([]byte("original spec"))
	requireCode(t, f.store.RecordObservation(t.Context(), observation), domain.Conflict)
}

func TestCorruptFrozenRequestAndStorageFailureNeverBecomePossibleSend(t *testing.T) {
	f := newFixture(t)
	c := f.prepare(t, "request-integrity")
	view, err := f.store.GetForDispatch(t.Context(), f.actor, c.Operation, f.now)
	original := must(t, view, err).Request
	changed := original
	changed.Brief = "substituted brief"
	encoded, err := encode(changed)
	requireOK(t, err)
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET request=? WHERE id=?", encoded, c.Operation)
	requireOK(t, err)
	_, err = f.store.GetForDispatch(t.Context(), f.actor, c.Operation, f.now)
	requireCode(t, err, domain.EvidenceInvalid)
	_, err = f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	requireCode(t, err, domain.EvidenceInvalid)
	encoded, err = encode(original)
	requireOK(t, err)
	_, err = f.store.db.ExecContext(t.Context(), "UPDATE operations SET request=? WHERE id=?", encoded, c.Operation)
	requireOK(t, err)
	_, err = f.store.db.ExecContext(t.Context(), `CREATE TRIGGER fail_possible_send BEFORE UPDATE OF state ON operations WHEN NEW.state='possible_send' BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END`)
	requireOK(t, err)
	if _, err = f.markSettledControl(t.Context(), f.actor, f.transmission(c)); err == nil {
		t.Fatal("storage failure was hidden")
	}
	operation, err := f.store.GetOperation(t.Context(), f.actor, c.Operation)
	if got := must(t, operation, err); got.Reserved || got.Delivery != domain.Prepared {
		t.Fatal("failed commit changed reservation or possible-send state")
	}
	_, err = f.store.db.ExecContext(t.Context(), "DROP TRIGGER fail_possible_send")
	requireOK(t, err)
	decision, err := f.markSettledControl(t.Context(), f.actor, f.transmission(c))
	if must(t, decision, err).Kind != domain.SendOnce {
		t.Fatal("failed commit consumed send permission")
	}
}

func TestDraftExpiryUsesNanosecondOrdering(t *testing.T) {
	f := newFixture(t)
	f.now = f.now.Add(100 * time.Millisecond)
	c := f.prepare(t, "fractional-expiry")
	summary, err := f.store.ExpireUnsent(t.Context(), f.now.Add(domain.DraftTTL-time.Nanosecond))
	if must(t, summary, err).Count != 0 {
		t.Fatal("draft expired before its precise deadline")
	}
	summary, err = f.store.ExpireUnsent(t.Context(), f.now.Add(domain.DraftTTL))
	if must(t, summary, err).Count != 1 {
		t.Fatal("draft remained at precise expiry boundary")
	}
	view, err := f.store.GetOperation(t.Context(), f.actor, c.Operation)
	if must(t, view, err).Delivery != domain.ExpiredUnsent {
		t.Fatal("wrong expired delivery state")
	}
}

func TestInventoryPaginationFiltersCurrentGrantsAcrossTwoHundredDevices(t *testing.T) {
	f := newFixture(t)
	for i := range 200 {
		id := domain.DeviceID(fmt.Sprintf("endpoint-%03d", i))
		device, err := f.store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: id, Name: "Duplicate display name"})
		_ = must(t, device, err)
		d := domain.Destination{Device: id, Project: "project"}
		requireOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: d, Context: binding()}))
		requireOK(t, f.store.PutGrant(t.Context(), domain.Grant{Key: domain.GrantKey{Principal: f.actor.Principal, Destination: d}, Scopes: domain.ScopeSet{domain.InventoryRead}}))
	}
	requireOK(t, f.store.RevokeGrant(t.Context(), domain.GrantKey{Principal: f.actor.Principal, Destination: domain.Destination{Device: "endpoint-099", Project: "project"}}))
	seen := make(map[domain.DeviceID]bool)
	request := domain.DevicePageRequest{Limit: 100}
	for {
		page, err := f.store.ListDevices(t.Context(), f.actor, request)
		result := must(t, page, err)
		if len(result.Items) > 100 {
			t.Fatal("page exceeds configured bound")
		}
		for _, item := range result.Items {
			if seen[item.ID] || item.ID == "endpoint-099" {
				t.Fatal("duplicate or unauthorized device in inventory")
			}
			seen[item.ID] = true
		}
		if result.Next == "" {
			break
		}
		request.After = result.Next
	}
	if len(seen) != 200 {
		t.Fatalf("want 200 authorized fixture devices, got %d", len(seen))
	}
}

func TestProjectInventoryRejectsStoredLocalContextTokens(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.db.ExecContext(t.Context(), "UPDATE projects SET root_guard=? WHERE device=? AND alias=?", "base64-local-path-token", f.credential.Device, "project")
	requireOK(t, err)
	if _, err = f.store.ListProjects(t.Context(), f.actor, "device", domain.ProjectPageRequest{}); err == nil {
		t.Fatal("inventory exposed a path-bearing local context token")
	}
}
