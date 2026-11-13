package registry

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func addRoutingDevice(t *testing.T, f *fixture, id domain.DeviceID) *fixture {
	t.Helper()
	return addRoutingDeviceMode(t, f, id, domain.Regular)
}

func addRoutingDeviceMode(t *testing.T, f *fixture, id domain.DeviceID, mode domain.CredentialMode) *fixture {
	t.Helper()
	device, err := f.store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: id, Name: string(id)})
	_ = must(t, device, err)
	token := domain.Hash([]byte(id))
	requireOK(t, f.store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: token, Device: id, Mode: mode, Generation: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(domain.EnrollmentTTL)}))
	publicKey, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	keyBytes := must(t, publicKey, err)
	intent, err := f.store.BeginEnrollment(t.Context(), domain.EnrollmentAttempt{TokenHash: token, CSRHash: domain.Hash([]byte("fixture-csr")), PublicKeyHash: domain.Hash(keyBytes), Issuance: domain.IssuanceID(id), Serial: bytes.Repeat([]byte{1}, 16), Now: f.now})
	reserved := must(t, intent, err)
	receipt, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: reserved.ID, CertificateDER: signFixture(t, reserved, f.key), Now: f.now})
	ref := must(t, receipt, err).Intent.Credential
	connection, err := f.store.NextConnectionGeneration(t.Context(), ref, "fleet-gateway", f.now)
	peer := &fixture{store: f.store, credential: ref, connection: must(t, connection, err), now: f.now}
	peer.reconcileRouting(t, nil)
	return peer
}

func TestRoutingGlobalScanPoolsAndSharedDeviceScanBound(t *testing.T) {
	first := newFixture(t)
	second := addRoutingDevice(t, first, "device2")
	third := addRoutingDevice(t, first, "device3")
	fourth := addRoutingDevice(t, first, "device4")
	fifth := addRoutingDevice(t, first, "device5")
	for _, peer := range []*fixture{first, second, third} {
		requireOK(t, peer.store.AcquireRouting(t.Context(), routingRequest(t, peer, protocol.Resolve, 1)))
	}
	requireCode(t, fourth.store.AcquireRouting(t.Context(), routingRequest(t, fourth, protocol.Status, 1)), domain.ResourceLimit)
	requireCode(t, first.store.AcquireRouting(t.Context(), routingRequest(t, first, protocol.Cancel, 2)), domain.ResourceLimit)
	requireOK(t, fourth.store.AcquireRouting(t.Context(), routingRequest(t, fourth, protocol.Cancel, 2)))
	requireCode(t, fifth.store.AcquireRouting(t.Context(), routingRequest(t, fifth, protocol.FenceAbsent, 1)), domain.ResourceLimit)
}
