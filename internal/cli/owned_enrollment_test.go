package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/registry"
	"github.com/hishamkaram/delegation-layer-gateway/internal/testsupport"
)

type ownedCLIAdmin struct {
	socket, parent string
	store          *registry.Store
	owner          domain.PrincipalID
}

func newOwnedCLIAdmin(t *testing.T) *ownedCLIAdmin {
	t.Helper()
	parent := testsupport.PrivateSocketDirectory(t)
	require(t, os.Chmod(parent, 0o700))
	authority := adminapi.NewAuthorizer()
	store, err := registry.Create(t.Context(), filepath.Join(parent, "registry.sqlite"), registry.CreateOptions{Admin: authority})
	require(t, err)
	t.Cleanup(func() { require(t, store.Close()) })
	handler, err := adminapi.NewHandler(adminapi.Options{Store: store, OwnerPolicies: store, OwnedEnrollments: store, Authority: authority, Disconnector: disconnectFixture{}, Random: rand.Reader, Now: time.Now})
	require(t, err)
	socket := filepath.Join(parent, "admin.sock")
	server, err := adminapi.Listen(socket, handler)
	require(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() { cancel(); require(t, server.Close()); require(t, <-done) })
	code, out, diagnostic := command(t, "users", "allow", "--socket", socket, "--issuer", "https://issuer.example/", "--subject", "alice", "--provider", "claude:print", "--max-devices", "2")
	if code != 0 || diagnostic != "" {
		t.Fatal("real Unix owner setup failed", code, diagnostic)
	}
	var view adminapi.OwnerPolicyView
	require(t, json.Unmarshal([]byte(out), &view))
	return &ownedCLIAdmin{socket: socket, parent: parent, store: store, owner: domain.PrincipalID(view.PrincipalID)}
}

func (f *ownedCLIAdmin) args(output string) []string {
	args := []string{"devices", "enrollment-token", "--socket", f.socket, "--issuer", "https://issuer.example/", "--subject", "alice", "--name", "Headless Mac"}
	if output != "" {
		args = append(args, "--output-file", output)
	}
	return args
}

func (f *ownedCLIAdmin) devices(t *testing.T) []domain.Device {
	t.Helper()
	page, err := f.store.ListDevices(t.Context(), domain.Actor{Principal: f.owner, Scopes: domain.ScopeSet{domain.InventoryRead}}, domain.DevicePageRequest{Limit: 10})
	require(t, err)
	return page.Items
}

func TestOwnedEnrollmentCommandWritesExclusivePrivateTokenWithoutStdout(t *testing.T) {
	f := newOwnedCLIAdmin(t)
	code, out, diagnostic := command(t, f.args("")...)
	if code != 2 || out != "" || len(f.devices(t)) != 0 {
		t.Fatal("missing private output admitted a device", code, diagnostic)
	}
	output := filepath.Join(f.parent, "owned-token.json")
	code, out, diagnostic = command(t, f.args(output)...)
	if code != 0 || out != "" || diagnostic != "" {
		t.Fatal("owned token delivery did not stay private", code, diagnostic)
	}
	data, token := assertOwnedTokenPrivateOutput(t, f, output)

	code, out, diagnostic = command(t, f.args(output)...)
	if code != 2 || out != "" || strings.Contains(diagnostic, token.Token) || len(f.devices(t)) != 1 {
		t.Fatal("existing token output was overwritten or caused another mutation")
	}
	after, err := os.ReadFile(output)
	require(t, err)
	if !bytes.Equal(after, data) {
		t.Fatal("private output lost exclusive ownership")
	}
}

func assertOwnedTokenPrivateOutput(t *testing.T, f *ownedCLIAdmin, output string) ([]byte, adminapi.Enrollment) {
	t.Helper()
	data, err := os.ReadFile(output)
	require(t, err)
	var token adminapi.Enrollment
	require(t, json.Unmarshal(data, &token))
	info, err := os.Lstat(output)
	require(t, err)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || token.Token == "" || token.DeviceID == "" {
		t.Fatal("private token file contract invalid")
	}
	devices := f.devices(t)
	if len(devices) != 1 || string(devices[0].ID) != token.DeviceID {
		t.Fatal("private output was not bound to newly owned device")
	}
	return data, token
}

func TestOwnedEnrollmentOutputAliasFailsBeforeCreatingDevice(t *testing.T) {
	f := newOwnedCLIAdmin(t)
	foreign := filepath.Join(f.parent, "foreign")
	require(t, os.WriteFile(foreign, []byte("foreign private content"), 0o600))
	alias := filepath.Join(f.parent, "alias")
	require(t, os.Symlink(foreign, alias))
	code, out, _ := command(t, f.args(alias)...)
	if code != 2 || out != "" || len(f.devices(t)) != 0 {
		t.Fatal("output symlink reached administrative mutation")
	}
	data, err := os.ReadFile(foreign)
	require(t, err)
	if string(data) != "foreign private content" {
		t.Fatal("foreign output changed")
	}
}

func TestOwnedEnrollmentLostResponseAndExactArgvNeverRemint(t *testing.T) {
	f := newOwnedCLIAdmin(t)
	socket := filepath.Join(f.parent, "drop-response.sock")
	var calls atomic.Int64
	client := newOwnedMintProxyClient(t, f.socket)
	startAdminResponseServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); dropCommittedOwnedMint(t, client, w, r) }))

	output := filepath.Join(f.parent, "uncertain-token.json")
	args := f.args(output)
	for i := range args {
		if args[i] == f.socket {
			args[i] = socket
		}
	}
	code, out, diagnostic := command(t, args...)
	if code != 3 || out != "" || !strings.Contains(diagnostic, "credential_delivery_unconfirmed") || calls.Load() != 1 || len(f.devices(t)) != 1 {
		t.Fatal("lost credential response retried or hid committed state", code, diagnostic)
	}
	data, err := os.ReadFile(output)
	require(t, err)
	if len(data) != 0 {
		t.Fatal("unknown credential invented into reserved output")
	}
	code, out, diagnostic = command(t, args...)
	if code != 2 || out != "" || calls.Load() != 1 || len(f.devices(t)) != 1 {
		t.Fatal("same command reminted after uncertain response", code, diagnostic)
	}
}

func newOwnedMintProxyClient(t *testing.T, socket string) *http.Client {
	t.Helper()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func dropCommittedOwnedMint(t *testing.T, client *http.Client, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	forward, err := http.NewRequestWithContext(r.Context(), r.Method, "http://unix"+r.URL.Path, r.Body)
	if err != nil {
		t.Error(err)
		return
	}
	forward.Header.Set("Content-Type", "application/json")
	response, err := client.Do(forward)
	if err != nil {
		t.Error(err)
		return
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if err = errors.Join(readErr, closeErr); err != nil {
		t.Error(err)
		return
	}
	if response.StatusCode != http.StatusOK {
		t.Error("real owner mint did not commit")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		t.Error("fixture requires HTTP1 hijacker")
		return
	}
	connection, _, err := hijacker.Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	if err = connection.Close(); err != nil {
		t.Error(err)
	}
}
