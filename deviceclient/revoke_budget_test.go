package deviceclient

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
	"github.com/hishamkaram/delegation-layer-gateway/internal/enrollment"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func TestSaturatedHeadlessProfileCanPinFirstManageFlowAndRemoveWorkspace(t *testing.T) {
	f := realHeadlessProfile(t)
	workspaces, err := ListWorkspaces(t.Context(), f.options.ProfileDirectory)
	if err != nil {
		t.Fatal(err)
	}
	pin := connector.ProjectPin{Request: protocol.ResolveProjectRequest{RequestID: fmt.Sprintf("%032x", 1), WorkspaceID: workspaces[0].ID, RelativePath: "project"}, WorkspaceContext: f.options.Workspaces[0].NativeContext, Project: connector.Project{Alias: fmt.Sprintf("%032x", 1), Root: f.options.DelegateRoot, Directory: filepath.Join(f.options.Workspaces[0].Directory, "project"), RootToken: f.options.DelegateRootContext, ProjectToken: "immutable-project"}}
	projects := newProfileProjects(f.options.ProfileDirectory)
	commitProject(t, projects, pin)
	originalPins := saturateHeadlessBase(t, f.options.ProfileDirectory)
	if err = RevokeDevice(t.Context(), f.options.ProfileDirectory, f.options.PresentChallenge); err != nil {
		t.Fatal("saturated headless base blocked first management flow", err)
	}
	removed, err := RemoveWorkspace(t.Context(), f.options.ProfileDirectory, workspaces[0].ID, workspaces[0].Revision)
	if err != nil || removed.Enabled {
		t.Fatal("issuer pinning consumed workspace revocation capacity", err)
	}
	assertManagedProfilePins(t, f.options.ProfileDirectory, originalPins)
	retained, err := projects.LookupPin(t.Context(), pin.Request.RequestID)
	if err != nil || retained.WireIdentity() != pin.WireIdentity() {
		t.Fatal("removal rebound retained identity", err)
	}
}

func realHeadlessProfile(t *testing.T) *gatewayFixture {
	t.Helper()
	f := newGatewayFixture(t)
	store, owner, _ := realSelfService(t, f)
	raw, hash, err := enrollment.NewToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.CreateOwnedEnrollment(t.Context(), owner.Principal, "Headless", hash, f.now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := enrollment.New(store, f.ca, rand.Reader, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := enrollment.HTTPHandler(service, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.tokenHTTP = handler
	f.mu.Unlock()
	token, err := json.Marshal(enrollmentToken{Token: raw, DeviceID: string(device.ID), ExpiresAt: f.now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	f.options.EnrollmentTokenReader = strings.NewReader(string(token))
	f.options.DeviceName = "Headless"
	if _, err = Connect(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	return f
}

func assertManagedProfilePins(t *testing.T, directory string, original []byte) {
	t.Helper()
	current, err := openProfile(directory, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := current.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	afterPins, err := encodedPins(current.value.Pins)
	if err != nil || !bytes.Equal(original, afterPins) || current.value.Issuer == (issuerEndpoints{}) {
		t.Fatal("first management flow rewrote pins or did not persist endpoints", err)
	}
}

func saturateHeadlessBase(t *testing.T, directory string) []byte {
	t.Helper()
	store, err := openProfile(directory, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	next := *store.value
	if next.Issuer != (issuerEndpoints{}) {
		t.Fatal("fixture already pinned OAuth endpoints")
	}
	seed := next.Workspaces[0]
	for i := range 4 {
		record := seed
		record.ID = fmt.Sprintf("%032x", i+100)
		record.Alias = fmt.Sprintf("padding-%d", i)
		record.NativeContext = strings.Repeat("w", maxNativeContextBytes)
		if i == 3 {
			record.NativeContext = "t"
		}
		next.Workspaces = append(next.Workspaces, record)
	}
	base := next
	base.Pins = nil
	data, err := profileEncoding(base, maxProfileBytes)
	if err != nil {
		t.Fatal(err)
	}
	padding := ordinaryBaseLimit(next) - len(data)
	last := len(next.Workspaces) - 1
	if padding < 0 || padding+1 > maxNativeContextBytes {
		t.Fatal("invalid saturated-base fixture")
	}
	next.Workspaces[last].NativeContext += strings.Repeat("x", padding)
	if err = store.save(next); err != nil {
		t.Fatal(err)
	}
	pins, err := encodedPins(next.Pins)
	if err != nil {
		t.Fatal(err)
	}
	return pins
}
