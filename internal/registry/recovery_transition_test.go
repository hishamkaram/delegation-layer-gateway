package registry

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func enrollFixtureDevice(t *testing.T, f *fixture, id domain.DeviceID, mode domain.CredentialMode) domain.CredentialRef {
	t.Helper()
	f.next++
	device, err := transaction(t.Context(), f.store, func(tx *sql.Tx) (domain.Device, error) { return readDevice(t.Context(), tx, id) })
	current := must(t, device, err)
	token := domain.Hash([]byte(fmt.Sprintf("device-enrollment-%d", f.next)))
	requireOK(t, f.store.CreateEnrollment(t.Context(), domain.EnrollmentGrant{TokenHash: token, Device: id, Mode: mode, Generation: current.CredentialGeneration + 1, CreatedAt: f.now, ExpiresAt: f.now.Add(domain.EnrollmentTTL)}))
	encoded, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	spki := must(t, encoded, err)
	serial := make([]byte, 16)
	serial[0], serial[15] = 1, byte(f.next)
	intent, err := f.store.BeginEnrollment(t.Context(), domain.EnrollmentAttempt{TokenHash: token, CSRHash: domain.Hash([]byte("device CSR")), PublicKeyHash: domain.Hash(spki), Issuance: domain.IssuanceID(fmt.Sprintf("device-issuance-%d", f.next)), Serial: serial, Now: f.now})
	reserved := must(t, intent, err)
	receipt, err := f.store.CompleteIssuance(t.Context(), domain.IssuanceCompletion{Intent: reserved.ID, CertificateDER: signFixture(t, reserved, f.key), Now: f.now})
	return must(t, receipt, err).Intent.Credential
}

func TestRecoveryAllowsMixedDeviceCredentialTransition(t *testing.T) {
	f := newFixture(t)
	source := f.prepare(t, "multi-device-snapshot-hold")
	_, err := f.markSettledControl(t.Context(), f.actor, f.transmission(source))
	requireOK(t, err)
	secondRoute := domain.Destination{Device: "second-device", Project: "work"}
	_, err = f.store.RegisterDevice(t.Context(), domain.DeviceRegistration{ID: secondRoute.Device, Name: "Second"})
	requireOK(t, err)
	requireOK(t, f.store.RegisterProject(t.Context(), domain.ProjectRegistration{Destination: secondRoute, Context: binding()}))
	_, err = f.store.BeginRecovery(t.Context(), domain.RecoveryStart{ID: "multi-device-recovery", Epoch: "multi-device-epoch", Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.SealRecoveryRoster(t.Context(), domain.RecoveryRosterSeal{Recovery: "multi-device-recovery", ExpectedDestinations: 2}))
	f.credential = f.enroll(t, domain.RecoveryOnly)
	connection, err := f.store.NextConnectionGeneration(t.Context(), f.credential, "primary-recovery", f.now)
	f.connection = must(t, connection, err)
	second := enrollFixtureDevice(t, f, secondRoute.Device, domain.RecoveryOnly)
	secondConnection, err := f.store.NextConnectionGeneration(t.Context(), second, "secondary-recovery", f.now)
	secondGeneration := must(t, secondConnection, err)
	primaryRoot := domain.RecoveryDestination{Recovery: "multi-device-recovery", Device: f.credential.Device, Root: binding().Root}
	secondaryRoot := domain.RecoveryDestination{Recovery: primaryRoot.Recovery, Device: second.Device, Root: binding().Root}
	primaryGeneration := f.barrierGeneration(t, primaryRoot)
	secondPlan, err := f.store.PrepareRecoveryBarrier(t.Context(), domain.BarrierPreparation{Destination: secondaryRoot, Credential: second, Connection: secondGeneration, Now: f.now})
	secondaryGeneration := must(t, secondPlan, err).Generation
	for _, item := range []struct {
		destination domain.RecoveryDestination
		generation  domain.AdmissionGeneration
		credential  domain.CredentialRef
		connection  domain.ConnectionGeneration
	}{{primaryRoot, primaryGeneration, f.credential, f.connection}, {secondaryRoot, secondaryGeneration, second, secondGeneration}} {
		requireOK(t, f.store.RecordBarrier(t.Context(), domain.ValidatedBarrierReceipt{Destination: item.destination, Generation: item.generation, Receipt: domain.Hash([]byte("barrier " + string(item.destination.Device)))}))
		complete := domain.Hash([]byte("complete " + string(item.destination.Device)))
		_, err = f.store.ApplyImportedInventoryPage(t.Context(), domain.ImportedInventoryPage{Destination: item.destination, Generation: item.generation, Membership: domain.Hash([]byte("empty canonical inventory")), CompletenessReceipt: &complete, Credential: item.credential, Connection: item.connection, Now: f.now})
		requireOK(t, err)
	}
	requireOK(t, f.store.RegisterRoutingRecoveryRoster(t.Context(), primaryRoot.Recovery, []domain.DeviceID{f.credential.Device, second.Device}))
	f.reconcileRouting(t, nil)
	reconcileFixtureDevice(t, f, second, secondGeneration)
	// This fixture registered the second device before any connector census.
	// Its absent prior peer requires an explicit all-prior CLI-join assertion.
	target, err := f.store.ReadRoutingDrainTarget(t.Context(), second.Device, f.now)
	current := must(t, target, err)
	_, err = f.store.AttestRoutingDrained(t.Context(), routing.Drain{Device: current.Device, Credential: current.Credential, Recovery: current.Recovery, Scope: routing.AllPriorControls, CurrentBoot: current.ProcessBoot, Generation: current.Generation, Now: f.now})
	requireOK(t, err)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	f.credential = f.enroll(t, domain.Regular)
	connection, err = f.store.NextConnectionGeneration(t.Context(), f.credential, "primary-regular", f.now)
	f.connection = must(t, connection, err)
	f.reconcileRouting(t, nil)
	requireOK(t, f.store.BindAdministrativeRoute(t.Context(), fixtureAdministrativeRoute(f)))
	_, err = f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: primaryRoot.Recovery, Now: f.now})
	requireCode(t, err, domain.Forbidden)
	second = enrollFixtureDevice(t, f, second.Device, domain.Regular)
	secondConnection, err = f.store.NextConnectionGeneration(t.Context(), second, "secondary-regular", f.now)
	secondGeneration = must(t, secondConnection, err)
	reconcileFixtureDevice(t, f, second, secondGeneration)
	plan, err := f.store.ApproveRecoveryReopen(t.Context(), domain.RecoveryApproval{Recovery: primaryRoot.Recovery, Now: f.now})
	if len(must(t, plan, err).Targets) != 2 {
		t.Fatal("transitioning the second device lost a recovery root")
	}
}

func reconcileFixtureDevice(t *testing.T, f *fixture, credential domain.CredentialRef, generation domain.ConnectionGeneration) {
	t.Helper()
	_, err := f.store.ReconcileRouting(t.Context(), credential, protocol.ControlInventory{PolicyVersion: protocol.RoutingPolicyVersion, ProcessBoot: strings.Repeat("c", 32), BarrierID: strings.Repeat("d", 32), Generation: protocol.Generation{BootEpoch: string(generation.BootEpoch), Counter: generation.Counter}, Complete: true}, f.now)
	requireOK(t, err)
}
