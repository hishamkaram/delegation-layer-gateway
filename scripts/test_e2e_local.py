"""Pure harness safety checks; no native/provider process may start here."""

import os
import fcntl
import contextlib
import io
import json
import importlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import e2e_local


class MaintainedFixtureLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository = os.environ.get("DELEGATE_ACCEPTANCE_REPOSITORY")
        if not repository:
            raise unittest.SkipTest(
                "set DELEGATE_ACCEPTANCE_REPOSITORY for maintained FIFO tests"
            )
        cls.acceptance = e2e_local.load_acceptance(Path(repository))

    @contextlib.contextmanager
    def one_shot_writer(self):
        fixtures = importlib.import_module(
            "scripts.acceptance.private_cli.tests.test_shutdown"
        )
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            fixture = fixtures.ManagedLifetimeFixture(base)
            fixture.task.rmdir()
            root = object.__new__(e2e_local.DelegateRoot)
            root.owner = mock.Mock()
            root.owner.acceptance = self.acceptance
            root.owner.until.side_effect = lambda check, *_: check()
            root.state = fixture.state
            root.context = {
                "root_token": "fixture-root",
                "project_token": "fixture-project",
            }
            root.nonce = "one-shot-nonce"
            root.waiters = base / "waiters"
            root.waiters.mkdir(mode=0o700)
            root.counter = base / "counter"
            root.counter.write_text("")
            before = root.fixture_execution_snapshot()
            path = root.waiters / f"{root.nonce}-{os.getpid()}.fifo"
            os.mkfifo(path, 0o600)
            writer = [os.open(path, os.O_RDWR | os.O_NONBLOCK)]
            try:
                os.write(writer[0], f"{root.nonce}\t{os.getpid()}\n".encode())
                root.counter.write_text("execution\n")
                yield root, before, path, writer
            finally:
                if writer[0] >= 0:
                    os.close(writer[0])

    def test_one_handshake_supports_repeated_borrowed_live_checks_then_closes_once(
        self,
    ):
        with self.one_shot_writer() as (root, before, path, _writer):
            patcher = None
            try:
                with root.fixture_execution_lease(before, "b" * 32) as (
                    observation,
                    lease,
                ):
                    self.assertEqual(observation.path, path)
                    self.assertEqual(observation.pid, os.getpid())
                    self.assertEqual(
                        observation.identity, (path.stat().st_dev, path.stat().st_ino)
                    )
                    patcher = mock.patch.object(lease, "close", wraps=lease.close)
                    closed = patcher.start()
                    lease.assert_live()
                    lease.assert_live()
                    self.assertGreaterEqual(lease.descriptor, 0)
            finally:
                if patcher is not None:
                    patcher.stop()
            closed.assert_called_once_with()
            self.assertEqual(lease.descriptor, -1)
            self.assertEqual(lease.parent_descriptor, -1)
            # The writer emitted one handshake only: a fresh acquisition cannot
            # consume it again, even while the original writer remains open.
            with self.assertRaisesRegex(RuntimeError, "no live writer"):
                self.acceptance.leases.LiveFIFOLease.acquire(
                    "b" * 32, os.getpid(), path, root.nonce, timeout=0.02
                )

    def test_body_failure_and_intentional_writer_close_both_release_observer(self):
        for fails in (False, True):
            with (
                self.subTest(fails=fails),
                self.one_shot_writer() as (root, before, _path, writer),
            ):
                observed = []

                def body():
                    with root.fixture_execution_lease(before, "b" * 32) as (
                        _observation,
                        lease,
                    ):
                        observed.append((lease, lease.descriptor))
                        os.close(writer[0])
                        writer[0] = -1
                        if fails:
                            raise ValueError("controlled body failure")

                if fails:
                    with self.assertRaisesRegex(ValueError, "controlled body failure"):
                        body()
                else:
                    body()
                lease, descriptor = observed[0]
                self.assertEqual(lease.descriptor, -1)
                self.assertEqual(lease.parent_descriptor, -1)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)


class MCPPolicyTests(unittest.TestCase):
    def test_sequential_mcp_preserves_spacing_request_policy_and_response_validation(
        self,
    ):
        h = object.__new__(e2e_local.Harness)
        h.public = "https://fixture.invalid"
        h.material = {"ca_file": "fixture-ca", "token_file": "fixture-token"}
        h.fixture_allowed_ips = ("192.0.2.10",)
        h.last_mcp_started = 0
        h.responses = []
        accepted = {"structuredContent": {"data": {"accepted": True}}}
        denied = {"structuredContent": {"error": {"code": "denied"}}, "isError": True}
        h.helper = mock.Mock(side_effect=[accepted, denied])
        with mock.patch.object(
            e2e_local.time, "monotonic", side_effect=[10, 10, 10.25, 10.5]
        ):
            with mock.patch.object(e2e_local.time, "sleep") as sleep:
                self.assertEqual(
                    h.mcp("resolve_operation", {"operation_id": "one"}),
                    {"accepted": True},
                )
                self.assertEqual(
                    h.mcp("prepare_dispatch", {}, failure=True), {"code": "denied"}
                )
        sleep.assert_called_once_with(0.25)
        self.assertEqual(h.responses, [accepted, denied])
        self.assertEqual(
            h.helper.call_args_list[0],
            mock.call(
                "mcp",
                {
                    "endpoint": "https://fixture.invalid/mcp",
                    "ca_file": "fixture-ca",
                    "token_file": "fixture-token",
                    "tool": "resolve_operation",
                    "arguments": {"operation_id": "one"},
                    "allowed_ips": ["192.0.2.10"],
                },
            ),
        )
        with self.assertRaisesRegex(e2e_local.ProofFailure, "operation failed"):
            h.consume_mcp(denied)


class HarnessBoundaryTests(unittest.TestCase):
    def execution_root(self, directory):
        base = Path(directory).resolve()
        root = object.__new__(e2e_local.DelegateRoot)
        root.owner = mock.Mock()
        root.state = base / "state"
        root.context = {"root_token": "root", "project_token": "project"}
        root.nonce = "nonce"
        root.waiters = base / "waiters"
        root.waiters.mkdir()
        root.counter = base / "counter"
        root.counter.write_text("execution\nexecution\n")
        os.mkfifo(root.waiters / "nonce-123.fifo", 0o600)
        return root

    def test_stale_fifo_without_new_execution_never_proves_fixture_started(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.execution_root(directory)
            before = root.fixture_execution_snapshot()

            def timeout(check, *_args):
                self.assertIsNone(check())
                raise e2e_local.ProofFailure("new fixture absent")

            root.owner.until.side_effect = timeout
            with self.assertRaisesRegex(e2e_local.ProofFailure, "new fixture absent"):
                root.wait_fixture_execution(before, "new-task")
            root.owner.acceptance.leases.LiveFIFOLease.acquire.assert_not_called()
            root.owner.acceptance.supervisor.read_managed_closure.assert_called_once_with(
                root.state, ()
            )

    def test_new_execution_requires_fresh_identity_and_validated_live_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.execution_root(directory)
            before = root.fixture_execution_snapshot()
            lease = mock.Mock(spec=["identity", "assert_live", "close"])
            fresh = root.waiters / "nonce-456.fifo"

            def observe(check, *_args):
                self.assertIsNone(check())
                os.mkfifo(fresh, 0o600)
                # A new path alone is insufficient without an actual execution.
                self.assertIsNone(check())
                root.counter.write_text("execution\n" * 3)
                lease.identity = (fresh.stat().st_dev, fresh.stat().st_ino)
                return check()

            root.owner.until.side_effect = observe
            root.owner.acceptance.leases.LiveFIFOLease.acquire.return_value = lease
            result = root.wait_fixture_execution(before, "new-task")
            self.assertEqual(
                result,
                e2e_local.FixtureLeaseObservation(
                    "new-task", 456, fresh, lease.identity
                ),
            )
            args, kwargs = root.owner.acceptance.leases.LiveFIFOLease.acquire.call_args
            self.assertEqual(args, ("new-task", 456, fresh, "nonce"))
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 10)
            lease.assert_live.assert_called_once_with()
            lease.close.assert_called_once_with()

    def test_fixture_start_rejects_overshoot_replacement_and_malformed_entries(self):
        for fault in ("overshoot", "replacement", "regular", "bad-name", "context"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = self.execution_root(directory)
                before = root.fixture_execution_snapshot()
                if fault == "overshoot":
                    root.counter.write_text("execution\n" * 4)
                elif fault == "replacement":
                    old = root.waiters / "nonce-123.fifo"
                    old.rename(root.waiters / "old")
                    os.mkfifo(old, 0o600)
                elif fault == "regular":
                    (root.waiters / "nonce-456.fifo").touch()
                elif fault == "bad-name":
                    os.mkfifo(root.waiters / "nonce-abc.fifo", 0o600)
                else:
                    root.context["root_token"] = "another-root"
                root.owner.until.side_effect = lambda check, *_args: check()
                with self.assertRaises(e2e_local.ProofFailure):
                    root.wait_fixture_execution(before, "new-task")
                root.owner.acceptance.leases.LiveFIFOLease.acquire.assert_not_called()

    def test_fixture_lease_identity_change_or_liveness_failure_closes_observer(self):
        for fault in ("identity", "liveness"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = self.execution_root(directory)
                before = root.fixture_execution_snapshot()
                fresh = root.waiters / "nonce-456.fifo"
                os.mkfifo(fresh, 0o600)
                root.counter.write_text("execution\n" * 3)
                lease = mock.Mock(spec=["identity", "assert_live", "close"])
                lease.identity = (fresh.stat().st_dev, fresh.stat().st_ino)
                if fault == "identity":
                    lease.identity = (0, 0)
                else:
                    lease.assert_live.side_effect = e2e_local.ProofFailure("lease died")
                root.owner.until.side_effect = lambda check, *_args: check()
                root.owner.acceptance.leases.LiveFIFOLease.acquire.return_value = lease
                with self.assertRaises(e2e_local.ProofFailure):
                    root.wait_fixture_execution(before, "new-task")
                lease.close.assert_called_once_with()

    def gate_root(self, base):
        root = object.__new__(e2e_local.DelegateRoot)
        root.owner = mock.Mock()
        root.gate = base / "gate"
        root.fixture_gate = None
        descriptor = os.open(root.gate, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        gate = e2e_local.SimpleNamespace(descriptor=descriptor)

        def release():
            if gate.descriptor >= 0:
                os.close(gate.descriptor)
                gate.descriptor = -1

        gate.release = mock.Mock(side_effect=release)
        self.addCleanup(release)
        root.owner.acceptance.leases.LockedReleaseGate.acquire.return_value = gate
        return root, gate

    def test_root_reuses_original_gate_and_rejects_closed_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            root, gate = self.gate_root(Path(directory).resolve())
            original_inode = root.gate.stat().st_ino
            self.assertIs(root.acquire_fixture_gate(), gate)
            self.assertIs(root.acquire_fixture_gate(), gate)
            self.assertEqual(root.gate.stat().st_ino, original_inode)
            root.owner.acceptance.leases.LockedReleaseGate.acquire.assert_called_once_with(
                root.gate
            )
            root.release_fixture_gate()
            self.assertTrue(root.gate.exists())
            with self.assertRaisesRegex(e2e_local.ProofFailure, "already released"):
                root.acquire_fixture_gate()
            root.owner.acceptance.leases.LockedReleaseGate.acquire.assert_called_once()

    def test_root_rejects_replaced_gate_without_reacquiring(self):
        with tempfile.TemporaryDirectory() as directory:
            root, gate = self.gate_root(Path(directory).resolve())
            root.acquire_fixture_gate()
            root.gate.rename(root.gate.with_suffix(".original"))
            root.gate.touch(mode=0o600)
            with self.assertRaisesRegex(e2e_local.ProofFailure, "inode was replaced"):
                root.acquire_fixture_gate()
            self.assertGreaterEqual(gate.descriptor, 0)
            root.owner.acceptance.leases.LockedReleaseGate.acquire.assert_called_once()

    def test_root_finish_releases_gate_before_canonical_cleanup_even_on_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root, gate = self.gate_root(Path(directory).resolve())
                root.acquire_fixture_gate()
                root.state = Path(directory).resolve() / "state"
                root.pending = []
                root.close_engine = mock.Mock(return_value={})

                def closure(*_args, **_kwargs):
                    self.assertEqual(gate.descriptor, -1)
                    if fail:
                        raise e2e_local.ProofFailure("canonical fault")

                root.owner.acceptance.supervisor.await_managed_lifetime_closure.side_effect = closure
                if fail:
                    with self.assertRaisesRegex(
                        e2e_local.ProofFailure, "canonical fault"
                    ):
                        root.finish()
                else:
                    self.assertEqual(root.finish(), {})
                gate.release.assert_called_once_with()

    def test_handler_only_records_until_an_explicit_checkpoint(self):
        interruptions = e2e_local.Interruptions()
        interruptions.handle(e2e_local.signal.SIGINT, None)
        self.assertTrue(interruptions.interrupted)
        self.assertTrue(interruptions.pending)
        with self.assertRaises(e2e_local.ProofFailure):
            interruptions.checkpoint()
        self.assertFalse(interruptions.pending)
        interruptions.handle(e2e_local.signal.SIGTERM, None)
        self.assertTrue(interruptions.pending)

    def test_run_checks_interruption_before_starting_the_next_stage(self):
        stages = (
            "start_network",
            "start_connectors",
            "task_scenarios",
            "recovery_scenarios",
        )
        for interrupt_after in (None, *stages):
            with self.subTest(interrupt_after=interrupt_after):
                harness = object.__new__(e2e_local.Harness)
                harness.interruptions = e2e_local.Interruptions()
                harness.summary = {"result": "started"}
                harness.base = Path("/owned/fixture")
                harness.finish = mock.Mock(return_value=True)
                for stage in stages:
                    action = mock.Mock()
                    if stage == interrupt_after:
                        action.side_effect = lambda: harness.interruptions.handle(
                            e2e_local.signal.SIGINT, None
                        )
                    setattr(harness, stage, action)
                if interrupt_after is None:
                    harness.interruptions.handle(e2e_local.signal.SIGINT, None)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(harness.run(), 1)
                completed = stages.index(interrupt_after) + 1 if interrupt_after else 0
                for index, stage in enumerate(stages):
                    self.assertEqual(
                        getattr(harness, stage).call_count, int(index < completed)
                    )
                harness.finish.assert_called_once_with()
                self.assertEqual(harness.summary["failure_kind"], "ProofFailure")

    def test_command_delivers_only_after_the_owned_wait_and_result_read(self):
        harness = object.__new__(e2e_local.Harness)
        harness.interruptions = e2e_local.Interruptions()
        harness.sequence = 0
        harness.base = Path("/owned/fixture")
        harness.env = {}
        process = mock.Mock()
        process.json.return_value = {"closed": True}

        def completed_command(*_args, **_kwargs):
            harness.interruptions.handle(e2e_local.signal.SIGINT, None)
            return process

        harness.processes = mock.Mock()
        harness.processes.run.side_effect = completed_command
        with self.assertRaises(e2e_local.ProofFailure):
            harness.command(Path("/owned/literal"), ["status"])
        harness.processes.run.assert_called_once()
        process.json.assert_called_once_with(bound=1 << 20)
        harness.interruptions.handle(e2e_local.signal.SIGINT, None)
        with self.assertRaises(e2e_local.ProofFailure):
            harness.command(Path("/owned/literal"), ["status"])
        self.assertEqual(harness.processes.run.call_count, 1)

    def test_until_checks_pending_signal_before_another_observation(self):
        harness = object.__new__(e2e_local.Harness)
        harness.interruptions = e2e_local.Interruptions()

        def observed():
            harness.interruptions.handle(e2e_local.signal.SIGINT, None)
            return False

        observe = mock.Mock(side_effect=observed)
        with mock.patch.object(e2e_local.time, "sleep") as sleep:
            with self.assertRaises(e2e_local.ProofFailure):
                harness.until(observe, 5, "bounded observation")
        observe.assert_called_once_with()
        sleep.assert_not_called()

    def test_connector_handle_is_published_before_interruption_delivery(self):
        harness = object.__new__(e2e_local.Harness)
        harness.interruptions = e2e_local.Interruptions()
        harness.args = mock.Mock(gateway=Path("/owned/gateway"))
        harness.connectors = []
        process = mock.Mock()

        def started(*_args, **_kwargs):
            harness.interruptions.handle(e2e_local.signal.SIGINT, None)
            return process

        harness.processes = mock.Mock()
        harness.processes.start.side_effect = started
        root = mock.Mock()
        with self.assertRaises(e2e_local.ProofFailure):
            harness.start_connector(root)
        self.assertEqual(harness.connectors, [process])
        harness.processes.start.assert_called_once()

    def test_cleanup_context_restores_state_without_replacing_original_error(self):
        interruptions = e2e_local.Interruptions()
        with self.assertRaisesRegex(ValueError, "original cleanup error"):
            with interruptions.cleanup():
                interruptions.handle(e2e_local.signal.SIGINT, None)
                interruptions.checkpoint()
                raise ValueError("original cleanup error")
        self.assertFalse(interruptions.cleanup_active)
        self.assertTrue(interruptions.pending)
        self.assertFalse(interruptions.finalized)

    def test_first_signal_after_finalization_cannot_interrupt_evidence_writing(self):
        interruptions = e2e_local.Interruptions()
        with interruptions.cleanup():
            self.assertFalse(interruptions.finalize_cleanup())
            interruptions.handle(e2e_local.signal.SIGINT, None)
        self.assertTrue(interruptions.finalized)
        self.assertFalse(interruptions.interrupted)
        self.assertFalse(interruptions.pending)

    def test_first_signal_before_finish_call_cannot_escape_cleanup(self):
        self.assert_first_cleanup_signal("before_finish")

    def test_first_signal_before_cleanup_flag_cannot_escape_acquisition(self):
        self.assert_first_cleanup_signal("cleanup_acquisition")

    def test_first_cleanup_signal_before_connector_loop_preserves_all_joins(self):
        self.assert_first_cleanup_signal("connectors")

    def test_first_cleanup_signal_before_jwks_preserves_summary_and_prior_error(self):
        self.assert_first_cleanup_signal("jwks")

    def assert_first_cleanup_signal(self, stage):
        for prior_failure in (False, True):
            with (
                self.subTest(stage=stage, prior_failure=prior_failure),
                tempfile.TemporaryDirectory() as directory,
            ):

                class BeforeFinishHarness(e2e_local.Harness):
                    def __getattribute__(self, name):
                        if name == "finish" and object.__getattribute__(
                            self, "inject_finish_signal"
                        ):
                            self.inject_finish_signal = False
                            first_signal()
                        return super().__getattribute__(name)

                class AcquisitionInterruptions(e2e_local.Interruptions):
                    def __getattribute__(self, name):
                        if name == "cleanup_active" and object.__getattribute__(
                            self, "inject_acquisition_signal"
                        ):
                            self.inject_acquisition_signal = False
                            first_signal()
                        return super().__getattribute__(name)

                harness_type = (
                    BeforeFinishHarness
                    if stage == "before_finish"
                    else e2e_local.Harness
                )
                harness = object.__new__(harness_type)
                harness.inject_finish_signal = stage == "before_finish"
                if stage == "cleanup_acquisition":
                    harness.interruptions = AcquisitionInterruptions()
                    harness.interruptions.inject_acquisition_signal = True
                else:
                    harness.interruptions = e2e_local.Interruptions()
                harness.base = Path(directory).resolve()
                ledger = harness.base / "fixture-attempts"
                ledger.write_bytes(b"attempt\n" * 4)
                ledger.chmod(0o600)
                harness.summary = {"result": "started"}
                harness.operations = {}
                harness.closed_operations = set()
                connectors = [mock.Mock(), mock.Mock()]
                previous_failure = {}

                def first_signal():
                    previous_failure.update(
                        json.loads(
                            json.dumps(
                                {
                                    key: harness.summary[key]
                                    for key in ("failure_kind", "failure_trace")
                                    if key in harness.summary
                                }
                            )
                        )
                    )
                    harness.interruptions.handle(e2e_local.signal.SIGINT, None)

                class ConnectorList(list):
                    def __reversed__(self):
                        first_signal()
                        return super().__reversed__()

                harness.connectors = (
                    ConnectorList(connectors) if stage == "connectors" else connectors
                )
                harness.gateway = mock.Mock()
                harness.stop_process = mock.Mock()
                harness.gateway_intake_faults = mock.Mock(return_value=[])
                harness.native_capture_faults = mock.Mock(return_value=[])
                roots = [mock.Mock(), mock.Mock()]

                def close_root():
                    harness.interruptions.checkpoint()
                    return {"closed": True}

                for root in roots:
                    root.finish.side_effect = close_root
                harness.roots = roots
                harness.jwks = mock.Mock()
                if stage == "jwks":
                    harness.jwks.shutdown.side_effect = first_signal
                harness.jwks_thread = mock.Mock()
                harness.processes = mock.Mock()
                harness.processes.finished_naturally.return_value = True
                harness.start_network = mock.Mock(
                    side_effect=ValueError("controlled original failure")
                    if prior_failure
                    else None
                )
                harness.start_connectors = mock.Mock()
                harness.task_scenarios = mock.Mock()
                harness.recovery_scenarios = mock.Mock()
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(harness.run(), 1)
                self.assertEqual(
                    harness.stop_process.call_args_list,
                    [
                        mock.call(connectors[1]),
                        mock.call(connectors[0]),
                        mock.call(harness.gateway),
                    ],
                )
                for root in roots:
                    root.finish.assert_called_once_with()
                harness.jwks.shutdown.assert_called_once_with()
                harness.jwks_thread.join.assert_called_once_with()
                harness.jwks.server_close.assert_called_once_with()
                persisted = json.loads((harness.base / "summary.json").read_text())
                self.assertTrue(persisted["cleanup_confirmed"])
                self.assertTrue(persisted["interrupted_during_cleanup"])
                self.assertTrue(persisted["interrupted"])
                self.assertEqual(persisted["result"], "failed")
                self.assertEqual(
                    {
                        key: persisted[key]
                        for key in ("failure_kind", "failure_trace")
                        if key in persisted
                    },
                    previous_failure,
                )
                if prior_failure:
                    self.assertEqual(persisted["failure_kind"], "ValueError")
                else:
                    self.assertNotIn("failure_kind", persisted)
                    self.assertNotIn("failure_trace", persisted)
                self.assertTrue(harness.interruptions.finalized)
                self.assertFalse(harness.interruptions.pending)
                self.assertFalse(harness.interruptions.cleanup_active)
                harness.interruptions.handle(e2e_local.signal.SIGTERM, None)
                self.assertFalse(harness.interruptions.pending)

    def test_late_rejected_attempt_fails_acceptance_after_joined_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = object.__new__(e2e_local.Harness)
            harness.interruptions = e2e_local.Interruptions()
            harness.base = Path(directory).resolve()
            harness.args = mock.Mock(gateway=Path("/fixture/gateway"))
            harness.summary = {"result": "started"}
            harness.operations = {}
            harness.closed_operations = set()
            harness.connectors = []
            harness.gateway = None
            harness.jwks = None
            harness.processes = mock.Mock(entries=[])
            harness.processes.pending.return_value = []
            harness.processes.finished_naturally.return_value = True
            root = mock.Mock(native_captures=None)

            def close_native_root():
                ledger = harness.base / "fixture-attempts"
                ledger.write_bytes(b"attempt\n" * 5 + b"rejected_limit\n")
                ledger.chmod(0o600)
                return {"fixture": "independently closed"}

            root.finish.side_effect = close_native_root
            harness.roots = [root]
            harness.start_network = mock.Mock()
            harness.start_connectors = mock.Mock()
            harness.task_scenarios = mock.Mock()
            harness.recovery_scenarios = mock.Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(harness.run(), 1)
            self.assertTrue(harness.summary["cleanup_confirmed"])
            self.assertEqual(harness.summary["result"], "failed")
            self.assertEqual(harness.summary["fixture_attempts"]["attempted"], 5)

    def test_final_local_attempt_count_remains_exact(self):
        for count, result in ((3, "failed"), (4, "local_recovery_passed")):
            with self.subTest(count=count):
                harness = object.__new__(e2e_local.Harness)
                harness.summary = {"result": "local_recovery_passed"}
                harness.fixture_attempts = mock.Mock(
                    return_value={
                        "attempted": count,
                        "rejected_concurrent": 0,
                        "rejected_limit": 0,
                    }
                )
                harness.record_final_fixture_attempts()
                self.assertEqual(harness.summary["result"], result)

    def test_fifth_literal_attempt_is_visible_after_budget_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            fixture = base / "literal"
            fixture.write_text(f"#!{e2e_local.sys.executable}\nraise SystemExit(0)\n")
            fixture.chmod(0o700)
            counter = base / "executions"
            wrapper = base / "wrapper"
            wrapper.write_text(e2e_local.provider_wrapper(fixture, counter, base))
            wrapper.chmod(0o700)
            codes = [
                subprocess.run([wrapper, "--mode", "json"], check=False).returncode
                for _ in range(5)
            ]
            self.assertEqual(codes, [0, 0, 0, 0, 73])
            self.assertEqual(len(counter.read_bytes().splitlines()), 4)
            self.assertTrue(
                (base / "fixture-attempts").exists(),
                "rejected fifth attempt has no evidence",
            )
            harness = object.__new__(e2e_local.Harness)
            harness.base = base
            self.assertEqual(
                harness.fixture_attempts(),
                {"attempted": 5, "rejected_concurrent": 0, "rejected_limit": 1},
            )
            with self.assertRaises(e2e_local.ProofFailure):
                harness.assert_fixture_attempts(4)
            with self.assertRaises(e2e_local.ProofFailure):
                harness.assert_fixture_attempts(5)

    def test_concurrent_literal_attempt_is_visible_before_lease_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            counter = base / "executions"
            wrapper = base / "wrapper"
            wrapper.write_text(
                e2e_local.provider_wrapper(Path("/usr/bin/true"), counter, base)
            )
            wrapper.chmod(0o700)
            with (base / "provider-active.lock").open("wb") as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                completed = subprocess.run([wrapper, "--mode", "json"], check=False)
            self.assertEqual(completed.returncode, 72)
            self.assertFalse(counter.exists())
            self.assertTrue(
                (base / "fixture-attempts").exists(),
                "rejected concurrent attempt has no evidence",
            )
            harness = object.__new__(e2e_local.Harness)
            harness.base = base
            self.assertEqual(
                harness.fixture_attempts(),
                {"attempted": 1, "rejected_concurrent": 1, "rejected_limit": 0},
            )
            with self.assertRaises(e2e_local.ProofFailure):
                harness.assert_fixture_attempts(0)
            with self.assertRaises(e2e_local.ProofFailure):
                harness.assert_fixture_attempts(1)

    def test_attempt_oracle_rejects_malformed_or_unsafe_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = object.__new__(e2e_local.Harness)
            harness.base = Path(temporary).resolve()
            harness.assert_fixture_attempts(0)
            ledger = harness.base / "fixture-attempts"
            ledger.write_bytes(b"attempt\n")
            ledger.chmod(0o600)
            harness.assert_fixture_attempts(1)
            for data in (
                b"attempt",
                b"attempt\r\n",
                b"private-canary\n",
                b"attempt\n" * 3000,
            ):
                with self.subTest(data_length=len(data)):
                    ledger.write_bytes(data)
                    with self.assertRaises(e2e_local.ProofFailure):
                        harness.fixture_attempts()
            ledger.write_bytes(b"attempt\n")
            ledger.chmod(0o644)
            with self.assertRaises(e2e_local.ProofFailure):
                harness.fixture_attempts()
            with self.assertRaises(e2e_local.ProofFailure):
                harness.assert_fixture_attempts(True)

    def test_help_probe_does_not_record_an_execution_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            counter = base / "executions"
            wrapper = base / "wrapper"
            wrapper.write_text(
                e2e_local.provider_wrapper(Path("/usr/bin/true"), counter, base)
            )
            wrapper.chmod(0o700)
            result = subprocess.run([wrapper, "--mode", "json", "--help"], check=False)
            self.assertEqual(result.returncode, 0)
            self.assertFalse(counter.exists())
            harness = object.__new__(e2e_local.Harness)
            harness.base = base
            harness.assert_fixture_attempts(0)

    def test_observer_started_before_start_exception_is_stopped_and_joined(self):
        root = object.__new__(e2e_local.DelegateRoot)
        root.owner = mock.Mock()
        root.owner.interruptions = e2e_local.Interruptions()
        root.env = {}
        root.state = Path("/owned/state")
        root.config = root.state / ".supervisor/pueue.yml"
        root.pending = []
        root.daemon = mock.Mock()
        root.daemon.poll.return_value = None
        observers = []
        original = e2e_local.threading.Thread.start
        original_join = e2e_local.threading.Thread.join
        joined = []

        def observed_join(thread, *args, **kwargs):
            value = original_join(thread, *args, **kwargs)
            joined.append(thread)
            return value

        def interrupted_start(thread):
            original(thread)
            observers.append(thread)
            raise e2e_local.ProofFailure("controlled interruption after actual start")

        try:
            with (
                mock.patch.object(
                    e2e_local.threading.Thread, "start", interrupted_start
                ),
                mock.patch.object(e2e_local.threading.Thread, "join", observed_join),
            ):
                with self.assertRaises(e2e_local.ProofFailure):
                    root.close_engine(())
            self.assertEqual(len(observers), 1)
            self.assertEqual(joined, observers)
            self.assertFalse(
                observers[0].is_alive(), "started observer escaped cleanup"
            )
            root.owner.acceptance.supervisor.shutdown_terminal_private_supervisor.assert_not_called()
        finally:
            root.daemon.poll.return_value = {}
            for thread in observers:
                thread.join(2)

    def test_signal_exception_is_deferred_until_observer_is_owned(self):
        root = object.__new__(e2e_local.DelegateRoot)
        root.owner = mock.Mock()
        root.owner.interruptions = e2e_local.Interruptions()
        root.env = {}
        root.state = Path("/owned/state")
        root.config = root.state / ".supervisor/pueue.yml"
        root.pending = []
        root.daemon = mock.Mock()
        root.daemon.poll.return_value = None
        observers = []
        completed_start = []
        original = e2e_local.threading.Thread.start

        def signal_during_start(thread):
            original(thread)
            observers.append(thread)
            root.owner.interruptions.handle(e2e_local.signal.SIGINT, None)
            completed_start.append(True)

        try:
            with mock.patch.object(
                e2e_local.threading.Thread, "start", signal_during_start
            ):
                with self.assertRaises(e2e_local.ProofFailure):
                    root.close_engine(())
            self.assertEqual(completed_start, [True])
            self.assertFalse(observers[0].is_alive())
            root.owner.acceptance.supervisor.shutdown_terminal_private_supervisor.assert_not_called()
            self.assertTrue(root.owner.interruptions.interrupted)
            self.assertFalse(root.owner.interruptions.pending)
        finally:
            root.daemon.poll.return_value = {}
            for thread in observers:
                thread.join(2)

    def test_public_execution_closure_completes_accepted_result_observation(self):
        harness = object.__new__(e2e_local.Harness)
        harness.closed_operations = set()
        view = {
            "reserved": False,
            "observation": {
                "kind": "terminal",
                "execution_closure": {"kind": "registered-native"},
                "result": {"length": 36, "sha256": "a" * 64},
            },
        }
        harness.mcp = mock.Mock(return_value=view)

        def one_observation(check, *_args):
            value = check()
            e2e_local.require(
                value is not None, "canonical terminal observation was missed"
            )
            return value

        harness.until = one_observation
        self.assertEqual(harness.await_operation("operation", result=True), view)
        self.assertIn("operation", harness.closed_operations)

    def test_foreground_daemon_is_reaped_while_shutdown_requires_pid_absence(self):
        root = object.__new__(e2e_local.DelegateRoot)
        root.owner = mock.Mock()
        root.owner.interruptions = e2e_local.Interruptions()
        root.env = {}
        root.state = Path("/owned/state")
        root.config = root.state / ".supervisor/pueue.yml"
        root.pending = []
        closure = {"fixture": "closure authorized independently by maintained reader"}
        with subprocess.Popen(
            [e2e_local.sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ) as child:

            def observe_child():
                code = child.poll()
                return (
                    None if code is None else {"exit_code": code, "natural_wait": True}
                )

            def wait_child(timeout, expected):
                code = child.wait(timeout=timeout)
                self.assertEqual(code, expected)
                return code

            root.daemon = mock.Mock()
            root.daemon.poll.side_effect = observe_child
            root.daemon.wait.side_effect = wait_child

            def shutdown(*_args, **_kwargs):
                child.stdin.close()
                deadline = e2e_local.time.monotonic() + 3
                while e2e_local.time.monotonic() < deadline:
                    try:
                        os.getpgid(child.pid)
                    except ProcessLookupError:
                        return closure
                    e2e_local.time.sleep(0.01)
                raise TimeoutError("owned daemon PID remains present until reaped")

            root.owner.acceptance.supervisor.shutdown_terminal_private_supervisor.side_effect = shutdown
            try:
                self.assertEqual(root.close_engine(()), closure)
                root.daemon.wait.assert_called_once_with(15, expected=0)
            finally:
                child.stdin.close()
                child.wait(timeout=5)

    def test_daemon_observer_failure_joins_and_preserves_shutdown_error(self):
        root = object.__new__(e2e_local.DelegateRoot)
        root.owner = mock.Mock()
        root.owner.interruptions = e2e_local.Interruptions()
        root.env = {}
        root.state = Path("/owned/state")
        root.config = root.state / ".supervisor/pueue.yml"
        root.pending = []
        root.daemon = mock.Mock()
        failed = e2e_local.threading.Event()
        threads = []
        thread_type = e2e_local.threading.Thread

        def observe():
            failed.set()
            raise OSError("private observer failure")

        def shutdown(*_args, **_kwargs):
            self.assertTrue(failed.wait(3))
            raise TimeoutError("private shutdown failure")

        def own_thread(*args, **kwargs):
            thread = thread_type(*args, **kwargs)
            threads.append(thread)
            return thread

        root.daemon.poll.side_effect = observe
        root.owner.acceptance.supervisor.shutdown_terminal_private_supervisor.side_effect = shutdown
        with mock.patch.object(e2e_local.threading, "Thread", side_effect=own_thread):
            with self.assertRaises(e2e_local.CleanupUnconfirmed) as failure:
                root.close_engine(())
        self.assertEqual(len(threads), 1)
        self.assertFalse(threads[0].is_alive())
        self.assertIsInstance(failure.exception.__cause__, e2e_local.BaseExceptionGroup)
        causes = failure.exception.__cause__.exceptions
        self.assertEqual([type(error) for error in causes], [TimeoutError, OSError])
        root.daemon.wait.assert_not_called()

    def test_default_work_parent_uses_operator_home(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            with (
                mock.patch.object(Path, "home", return_value=Path(directory)),
                mock.patch.object(e2e_local, "checked_binary", side_effect=Path),
            ):
                args = e2e_local.arguments(
                    [
                        "--gateway",
                        "/owned/gateway",
                        "--delegate",
                        "/owned/delegate",
                        "--delegate-run",
                        "/owned/delegate-run",
                        "--pueue",
                        "/owned/pueue",
                        "--pueued",
                        "/owned/pueued",
                        "--fixture-tool",
                        "/owned/helper",
                        "--delegate-repository",
                        directory,
                        "--run-native",
                    ]
                )
            self.assertEqual(args.work_parent, home)

    def test_failure_trace_excludes_messages_paths_and_source_content(self):
        try:
            raise TimeoutError("PRIVATE-ERROR-MESSAGE")
        except TimeoutError as error:
            trace = e2e_local.failure_trace(error)
        self.assertEqual(len(trace), 1)
        self.assertEqual(trace[0]["file"], "test_e2e_local.py")
        self.assertEqual(
            trace[0]["function"],
            "test_failure_trace_excludes_messages_paths_and_source_content",
        )
        self.assertIsInstance(trace[0]["line"], int)
        self.assertNotIn("PRIVATE-ERROR-MESSAGE", str(trace))
        self.assertNotIn(str(Path(__file__).parent), str(trace))

    def test_direct_cli_has_no_diagnostic_capture_owner(self):
        harness = object.__new__(e2e_local.Harness)
        harness.roots = [mock.Mock(native_captures=None)]
        self.assertEqual(harness.native_capture_faults(), [])

    def test_native_launcher_preserves_literal_argument_boundaries(self):
        selected = Path("/owned/native with spaces/$(literal)/delegate")
        repository = Path("/owned/source with spaces")
        captures = Path("/owned/captures")
        source = e2e_local.native_capture_launcher(selected, repository, captures)
        with (
            mock.patch.object(e2e_local.os, "execv") as execute,
            mock.patch("sys.argv", ["launcher", "dispatch", "literal argument"]),
        ):
            exec(compile(source, "<owned launcher>", "exec"), {})
        executable, arguments = execute.call_args.args
        self.assertEqual(executable, e2e_local.sys.executable)
        self.assertEqual(
            arguments,
            [
                e2e_local.sys.executable,
                str(
                    Path(e2e_local.__file__)
                    .with_name("e2e_native_capture.py")
                    .resolve()
                ),
                "--delegate",
                str(selected),
                "--repository",
                str(repository),
                "--capture-root",
                str(captures),
                "--",
                "dispatch",
                "literal argument",
            ],
        )

    def test_native_capture_requires_complete_waited_bounded_observation(self):
        complete = {
            "diagnostic_only": True,
            "direct_wait_confirmed": True,
            "cleanup_confirmed": True,
            "capture_failed": False,
            "interrupted": False,
            "output_within_limits": True,
            "child_exit_code": 0,
        }
        self.assertTrue(e2e_local.native_capture_complete(complete))
        for field, invalid in (
            ("direct_wait_confirmed", False),
            ("cleanup_confirmed", False),
            ("capture_failed", True),
            ("interrupted", True),
            ("output_within_limits", False),
            ("child_exit_code", 3),
            ("child_exit_code", -15),
            ("child_exit_code", 255),
            ("child_exit_code", True),
        ):
            with self.subTest(field=field, invalid=invalid):
                self.assertFalse(
                    e2e_local.native_capture_complete({**complete, field: invalid})
                )

    def test_missing_native_capture_blocks_root_cleanup(self):
        self.assert_native_capture_failure(create_capture_root=True)

    def test_missing_capture_root_still_joins_jwks_and_records_failure(self):
        self.assert_native_capture_failure(create_capture_root=False)

    def test_nested_capture_metadata_still_joins_and_records_failure(self):
        self.assert_native_capture_failure(create_capture_root=True, deep_metadata=True)

    def assert_native_capture_failure(self, create_capture_root, deep_metadata=False):
        with tempfile.TemporaryDirectory() as directory:
            harness = object.__new__(e2e_local.Harness)
            harness.interruptions = e2e_local.Interruptions()
            harness.base = Path(directory).resolve()
            harness.summary = {"result": "started"}
            harness.args = mock.Mock(gateway=Path("/fixture/gateway"))
            harness.operations = {}
            harness.closed_operations = set()
            harness.connectors = []
            harness.gateway = None
            root = mock.Mock()
            root.native_captures = harness.base / "native"
            if create_capture_root:
                root.native_captures.mkdir(mode=0o700)
                (root.native_captures / "native-incomplete").mkdir(mode=0o700)
                if deep_metadata:
                    metadata = root.native_captures / "native-incomplete/metadata.json"
                    metadata.write_bytes(b"[" * 10000 + b"]" * 10000)
                    metadata.chmod(0o600)
            harness.roots = [root]
            harness.jwks = mock.Mock()
            harness.jwks_thread = mock.Mock()
            harness.processes = mock.Mock(entries=[])
            harness.processes.pending.return_value = []
            harness.processes.finished_naturally.return_value = True
            harness.start_network = mock.Mock()
            harness.start_connectors = mock.Mock()
            harness.task_scenarios = mock.Mock()
            harness.recovery_scenarios = mock.Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(harness.run(), 3)
            root.finish.assert_not_called()
            self.assertFalse(harness.summary["cleanup_confirmed"])
            harness.jwks.shutdown.assert_called_once_with()
            harness.jwks_thread.join.assert_called_once_with()
            harness.jwks.server_close.assert_called_once_with()
            self.assertTrue((harness.base / "summary.json").is_file())

    def test_permanent_refusal_finishes_cleanup_without_task_closure(self):
        harness = object.__new__(e2e_local.Harness)
        harness.closed_operations = set()
        view = {"observation": {"kind": "refused"}, "reserved": False}
        harness.mcp = mock.Mock(return_value=view)
        harness.until = lambda check, *_args: check()
        self.assertEqual(harness.await_operation("operation"), view)
        self.assertEqual(harness.closed_operations, {"operation"})
        harness.mcp.assert_called_once_with(
            "resolve_operation", {"operation_id": "operation"}
        )

    def test_permanent_refusal_cannot_satisfy_accepted_result_proof(self):
        harness = object.__new__(e2e_local.Harness)
        harness.closed_operations = set()
        harness.mcp = mock.Mock(
            return_value={"observation": {"kind": "refused"}, "reserved": False}
        )
        harness.until = lambda check, *_args: check()
        with self.assertRaises(e2e_local.ProofFailure):
            harness.await_operation("operation", result=True)
        self.assertEqual(harness.closed_operations, {"operation"})

    def test_refusal_with_retained_reservation_stays_pending(self):
        harness = object.__new__(e2e_local.Harness)
        harness.closed_operations = set()
        harness.mcp = mock.Mock(
            return_value={"observation": {"kind": "refused"}, "reserved": True}
        )
        harness.until = mock.Mock(side_effect=TimeoutError)
        with self.assertRaises(TimeoutError):
            harness.await_operation("operation")
        check = harness.until.call_args.args[0]
        self.assertIsNone(check())
        self.assertEqual(harness.closed_operations, set())

    def test_child_environment_drops_accounts_and_auth(self):
        with mock.patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "must-not-inherit",
                "HOME": "/real-home",
                "HTTP_PROXY": "http://private-proxy",
            },
        ):
            env = e2e_local.child_environment(
                Path("/fixture/home"),
                Path("/fixture/tmp"),
                [Path("/fixture/bin")],
                Path("/fixture/ca.pem"),
            )
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("HTTP_PROXY", env)
        self.assertEqual(env["HOME"], "/fixture/home")
        self.assertEqual(env["PATH"], "/fixture/bin")
        self.assertEqual(env["SSL_CERT_FILE"], "/fixture/ca.pem")

    def test_short_root_counts_bytes_before_startup(self):
        self.assertEqual(
            e2e_local.short_root(Path("/tmp/owned/s")), Path("/tmp/owned/s")
        )
        with self.assertRaises(e2e_local.ProofFailure):
            e2e_local.short_root(Path("/tmp/" + "é" * 50))

    def test_provider_source_change_is_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            processes = root / "scripts/acceptance/processes"
            processes.mkdir(parents=True)
            (processes / "operations.py").write_text("")
            private = root / "scripts/acceptance/private_cli"
            private.mkdir()
            (private / "fixtures.py").write_text(
                "raise RuntimeError('must never execute')"
            )
            with self.assertRaisesRegex(e2e_local.ProofFailure, "source changed"):
                e2e_local.load_acceptance(root)

    def test_cancel_proof_requires_requested_termination_and_native_wait(self):
        task = {
            "termination": {"cause": "requested", "scope_empty": True},
            "worker_wait": {"observed_at": "2026-01-01T00:00:02Z"},
            "intent": {"deadline": "2026-01-01T00:00:30Z"},
        }
        e2e_local.require_requested_closure({"tasks": {"task": task}}, "task")
        task["termination"]["cause"] = "budget"
        with self.assertRaises(e2e_local.ProofFailure):
            e2e_local.require_requested_closure({"tasks": {"task": task}}, "task")
        task["termination"]["cause"] = "requested"
        task["worker_wait"]["observed_at"] = "2026-01-01T00:00:31Z"
        with self.assertRaises(e2e_local.ProofFailure):
            e2e_local.require_requested_closure({"tasks": {"task": task}}, "task")

    def test_context_tokens_are_only_hashed_wire_guards(self):
        guard = e2e_local.context_guard("local-project-path-canary")
        self.assertEqual(len(guard), 69)
        self.assertTrue(guard.startswith("ctx1_"))
        self.assertNotIn("canary", guard)

    def test_nonzero_exit_keeps_intake_unconfirmed_after_direct_wait(self):
        harness = object.__new__(e2e_local.Harness)
        harness.summary = {"result": "failed"}
        process = mock.Mock()
        process.pid = 123
        process.poll.return_value = {"exit_code": 1, "natural_wait": True}
        process.wait.return_value = 1
        with self.assertRaises(e2e_local.CleanupUnconfirmed):
            harness.stop_process(process)
        process.wait.assert_called_once_with(45, expected=None)
        process.process.send_signal.assert_not_called()
        self.assertEqual(
            harness.summary["process_exit_failures"],
            [{"pid": 123, "exit_code": 1, "direct_wait_confirmed": True}],
        )
        self.assertEqual(harness.summary["result"], "failed")

    def test_exit_three_remains_cleanup_unconfirmed_after_wait(self):
        harness = object.__new__(e2e_local.Harness)
        harness.summary = {}
        process = mock.Mock()
        process.pid = 123
        process.poll.return_value = {"exit_code": 3, "natural_wait": True}
        process.wait.return_value = 3
        with self.assertRaises(e2e_local.CleanupUnconfirmed):
            harness.stop_process(process)
        process.wait.assert_called_once_with(45, expected=None)
        self.assertEqual(harness.summary["process_exit_failures"][0]["exit_code"], 3)

    def test_failed_process_never_turns_into_passing_acceptance(self):
        harness = object.__new__(e2e_local.Harness)
        harness.interruptions = e2e_local.Interruptions()
        harness.summary = {"result": "started"}
        harness.base = Path("/fixture")
        harness.start_network = mock.Mock()
        harness.start_connectors = mock.Mock()
        harness.task_scenarios = mock.Mock()
        harness.recovery_scenarios = mock.Mock()

        def finish():
            harness.summary["result"] = "failed"
            harness.summary["process_exit_failures"] = [{"pid": 123, "exit_code": 1}]
            return True

        harness.finish = finish
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness.run(), 1)

    def test_unconfirmed_cleanup_returns_distinct_exit_three(self):
        harness = object.__new__(e2e_local.Harness)
        harness.interruptions = e2e_local.Interruptions()
        harness.summary = {"result": "started"}
        harness.base = Path("/fixture")
        harness.start_network = mock.Mock()
        harness.start_connectors = mock.Mock()
        harness.task_scenarios = mock.Mock()
        harness.recovery_scenarios = mock.Mock()
        harness.finish = mock.Mock(return_value=False)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness.run(), 3)

    def test_gateway_control_cleanup_report_survives_its_confirmed_wait(self):
        harness = object.__new__(e2e_local.Harness)
        harness.args = mock.Mock(gateway=Path("/fixture/gateway"))
        harness.summary = {}
        gateway = mock.Mock(argv=["/fixture/gateway", "admin"], pid=123)
        gateway.poll.return_value = {"exit_code": 3, "natural_wait": True}
        delegate = mock.Mock(argv=["/fixture/delegate", "status"], pid=124)
        delegate.poll.return_value = {"exit_code": 3, "natural_wait": True}
        harness.processes = mock.Mock(entries=[gateway, delegate])
        harness.processes.pending.return_value = []
        self.assertEqual(
            harness.gateway_intake_faults(),
            [
                {
                    "stage": "gateway_intake_unconfirmed",
                    "pid": 123,
                    "exit_code": 3,
                    "direct_wait_confirmed": True,
                }
            ],
        )

    def test_connector_panic_wait_cannot_authorize_native_root_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = object.__new__(e2e_local.Harness)
            harness.interruptions = e2e_local.Interruptions()
            harness.base = Path(directory).resolve()
            harness.args = mock.Mock(gateway=Path("/fixture/gateway"))
            harness.summary = {"result": "started"}
            harness.operations = {}
            harness.closed_operations = set()
            process = mock.Mock(argv=["/fixture/gateway", "connector", "run"], pid=123)
            process.poll.return_value = {"exit_code": 2, "natural_wait": True}
            process.wait.return_value = 2
            harness.connectors = [process]
            harness.gateway = None
            root = mock.Mock()
            root.native_captures = Path(directory).resolve() / "native"
            root.native_captures.mkdir(mode=0o700)
            root.finish.return_value = {}
            harness.roots = [root]
            harness.jwks = None
            harness.processes = mock.Mock(entries=[process])
            harness.processes.pending.return_value = []
            harness.processes.finished_naturally.return_value = True
            harness.start_network = mock.Mock()
            harness.start_connectors = mock.Mock()
            harness.task_scenarios = mock.Mock()
            harness.recovery_scenarios = mock.Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(harness.run(), 3)
            root.finish.assert_not_called()
            self.assertFalse(harness.summary["cleanup_confirmed"])
            self.assertEqual(harness.summary["result"], "failed")
            self.assertTrue(
                harness.summary["process_exit_failures"][0]["direct_wait_confirmed"]
            )
            process.wait.assert_called_once_with(45, expected=None)

    def test_failed_enrollment_has_no_local_cli_owner_but_fails_acceptance(self):
        for code, expected_exit, cleanup in ((1, 1, True), (2, 1, True), (3, 3, False)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                harness = object.__new__(e2e_local.Harness)
                harness.interruptions = e2e_local.Interruptions()
                harness.base = Path(directory).resolve()
                harness.args = mock.Mock(gateway=Path("/fixture/gateway"))
                harness.summary = {"result": "started"}
                harness.operations = {}
                harness.closed_operations = set()
                process = mock.Mock(
                    argv=["/fixture/gateway", "connector", "enroll"], pid=123
                )
                process.poll.return_value = {"exit_code": code, "natural_wait": True}
                harness.connectors = []
                harness.gateway = None
                root = mock.Mock()
                root.native_captures = Path(directory).resolve() / "native"
                root.native_captures.mkdir(mode=0o700)
                root.finish.return_value = {}
                harness.roots = [root]
                harness.jwks = None
                harness.processes = mock.Mock(entries=[process])
                harness.processes.pending.return_value = []
                harness.processes.finished_naturally.return_value = True
                harness.start_network = mock.Mock()
                harness.start_connectors = mock.Mock(
                    side_effect=e2e_local.ProofFailure("enrollment failed")
                )
                harness.task_scenarios = mock.Mock()
                harness.recovery_scenarios = mock.Mock()
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(harness.run(), expected_exit)
                self.assertEqual(harness.summary["cleanup_confirmed"], cleanup)
                self.assertEqual(harness.summary["result"], "failed")
                self.assertEqual(root.finish.call_count, int(cleanup))
                harness.task_scenarios.assert_not_called()
                self.assertEqual(
                    harness.summary["process_exit_failures"],
                    [{"pid": 123, "exit_code": code, "direct_wait_confirmed": True}],
                )

    def test_unknown_or_unwaited_roles_cannot_authorize_native_cleanup(self):
        waited = {"exit_code": 0, "natural_wait": True}
        for arguments, result in (
            (["unknown"], waited),
            ([], waited),
            (["connector", "unknown"], waited),
            (["connector", "enroll"], None),
            (["connector", "enroll"], {"exit_code": -15, "natural_wait": True}),
            (["connector", "enroll"], {"exit_code": 4, "natural_wait": True}),
            (["connector", "enroll"], {"exit_code": 255, "natural_wait": True}),
            (["connector", "enroll"], {"exit_code": 0, "natural_wait": False}),
        ):
            with self.subTest(arguments=arguments, result=result):
                self.assertFalse(e2e_local.gateway_process_joined(arguments, result))

    def test_offline_maintenance_waits_are_classified_without_native_intake(self):
        commands = (
            [
                "begin-recovery",
                "--database",
                "/owned/registry",
                "--recovery-id",
                "restore",
            ],
            ["migrate", "--database", "/owned/registry"],
            ["users", "show", "--config", "/owned/config", "--subject", "owner"],
            ["devices", "revoke", "--config", "/owned/config", "--device", "device"],
        )
        for arguments in commands:
            for code in (0, 1, 2):
                with self.subTest(command=arguments[0], code=code):
                    self.assertTrue(
                        e2e_local.gateway_process_joined(
                            arguments, {"exit_code": code, "natural_wait": True}
                        )
                    )
            for result in (
                None,
                {"exit_code": 0, "natural_wait": False},
                {"exit_code": 3, "natural_wait": True},
                {"exit_code": -15, "natural_wait": True},
                {"exit_code": 4, "natural_wait": True},
            ):
                with self.subTest(command=arguments[0], result=result):
                    self.assertFalse(
                        e2e_local.gateway_process_joined(arguments, result)
                    )

    def test_unassigned_gateway_start_still_blocks_native_cleanup(self):
        harness = object.__new__(e2e_local.Harness)
        harness.args = mock.Mock(gateway=Path("/fixture/gateway"))
        harness.summary = {}
        process = mock.Mock(argv=["/fixture/gateway", "connector", "run"], pid=123)
        process.poll.return_value = None
        harness.processes = mock.Mock(entries=[process])
        harness.processes.pending.return_value = [
            {"pid": None, "argv": ["/fixture/gateway", "serve"]}
        ]
        faults = harness.gateway_intake_faults()
        self.assertEqual(len(faults), 2)
        self.assertFalse(faults[0]["direct_wait_confirmed"])
        self.assertEqual(faults[1], {"stage": "gateway_start_unconfirmed"})


if __name__ == "__main__":
    unittest.main()
