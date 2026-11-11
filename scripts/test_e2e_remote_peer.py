"""Remote peer boundary checks; no SSH, Delegate or provider process launches."""

import base64
import json
import importlib
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from types import SimpleNamespace

import e2e_remote_peer as peer


def cleanup_root():
    gate = SimpleNamespace(descriptor=1)

    def release():
        gate.descriptor = -1

    return SimpleNamespace(
        daemon=None,
        finish=mock.Mock(),
        fixture_gate=gate,
        release_fixture_gate=mock.Mock(side_effect=release),
    )


class PeerBoundaryTests(unittest.TestCase):
    def test_run_identity_is_canonical_and_derives_exact_known_path(self):
        self.assertEqual(
            peer.run_directory(Path("/owned/home"), "0123456789abcdef"),
            Path("/owned/home/gp-0123456789abcdef"),
        )
        for value in (
            None,
            True,
            "0123456789abcdeF",
            "0" * 15,
            "0" * 17,
            "../0123456789abc",
            "/0123456789abcde",
        ):
            with self.subTest(value=value), self.assertRaises(peer.local.ProofFailure):
                peer.run_directory(Path("/owned/home"), value)

    def test_hold_and_wait_use_only_root_snapshot_and_fresh_execution_port(self):
        owner = object.__new__(peer.Peer)
        owner.finished = False
        owner.fixture_observers = ExitStack()
        self.addCleanup(owner.fixture_observers.close)
        owner.fixture_observer = None
        owner.interruptions = peer.local.Interruptions()
        snapshot = peer.local.FixtureExecutionSnapshot(
            Path("/owned/state"), "nonce", ("root", "project"), 0, frozenset()
        )
        task = "a" * 32
        owner.root = cleanup_root()
        owner.root.state, owner.root.nonce = snapshot.root, snapshot.nonce
        owner.root.context = {"root_token": "root", "project_token": "project"}
        observation = peer.local.FixtureLeaseObservation(
            task, 123, Path("/owned/nonce-123.fifo"), (1, 2)
        )
        lease = mock.Mock(spec=["assert_live", "close"])

        @contextmanager
        def observe():
            try:
                yield observation, lease
            finally:
                lease.close()

        owner.root.acquire_fixture_gate = mock.Mock()
        owner.root.fixture_execution_snapshot = mock.Mock(return_value=snapshot)
        owner.root.fixture_execution_lease = mock.Mock(side_effect=lambda *_: observe())
        owner.root.invocations = mock.Mock(return_value=1)
        owner.root.fixture_waiters = mock.Mock(
            return_value=frozenset({("nonce-123.fifo", 1, 2)})
        )
        owner.fixture_attempts = mock.Mock(
            return_value={"attempted": 1, "rejected_concurrent": 0, "rejected_limit": 0}
        )
        self.assertEqual(owner.operate({"operation": "hold_fixture"}), {"held": True})
        self.assertIs(owner.fixture_snapshot, snapshot)
        response = owner.operate({"operation": "wait_fixture_started", "task_id": task})
        self.assertTrue(response["live_lease_proven"])
        owner.root.fixture_execution_lease.assert_called_once_with(snapshot, task)
        self.assertFalse(hasattr(owner, "gate"))
        for value in (
            {"operation": "wait_fixture_started"},
            {"operation": "wait_fixture_started", "task_id": "../bad"},
        ):
            with self.assertRaises(peer.local.ProofFailure):
                owner.operate(value)
        owner.root.fixture_execution_lease.assert_called_once()
        lease.assert_live.side_effect = peer.local.ProofFailure(
            "fresh execution not proven"
        )
        with self.assertRaisesRegex(
            peer.local.ProofFailure, "fresh execution not proven"
        ):
            owner.operate({"operation": "wait_fixture_started", "task_id": task})
        owner.root.fixture_gate.descriptor = -1
        with self.assertRaises(peer.local.ProofFailure):
            owner.operate({"operation": "wait_fixture_started", "task_id": task})

    def test_strict_lines_reject_duplicate_oversized_and_incomplete_input(self):
        for data in (
            b'{"operation":"shutdown","operation":"enroll"}\n',
            b"x" * (peer.MAX_LINE + 1),
            b"{}",
        ):
            with (
                self.subTest(data_length=len(data)),
                self.assertRaises((ValueError, peer.local.ProofFailure)),
            ):
                peer.decode_line(data)
        self.assertEqual(
            peer.decode_line(b'{"operation":"shutdown"}\n'), {"operation": "shutdown"}
        )

    def test_endpoint_is_exact_ip_scheme_port_and_path(self):
        self.assertEqual(
            peer.endpoint("wss://100.64.0.99:9444/device", "wss", "/device"),
            "100.64.0.99",
        )
        for url in (
            "ws://100.64.0.99:9444/device",
            "wss://example.invalid:9444/device",
            "wss://user@100.64.0.99:9444/device",
            "wss://100.64.0.99/device",
            "wss://100.64.0.99:9444/device?token=secret",
            "wss://0.0.0.0:9444/device",
        ):
            with (
                self.subTest(url=url),
                self.assertRaises((ValueError, peer.local.ProofFailure)),
            ):
                peer.endpoint(url, "wss", "/device")

    def test_manifest_rejects_invalid_budget_before_files_or_imports(self):
        base = {field: "unused" for field in peer.Manifest.__dataclass_fields__}
        base["schema_version"] = 1
        base["run_id"] = "0123456789abcdef"
        base["capture_native"] = False
        for allocation in (True, 0, 3, 30, "2"):
            with (
                self.subTest(allocation=allocation),
                self.assertRaises(peer.local.ProofFailure),
                mock.patch.object(peer, "owned_path") as path,
            ):
                peer.Manifest.parse({**base, "allocation": allocation})
            path.assert_not_called()
        with self.assertRaises(peer.local.ProofFailure):
            peer.Manifest.parse({**base, "allocation": 1, "shell": "unexpected"})

    def test_manifest_capture_option_is_optional_exact_bool_and_keeps_closed_fields(
        self,
    ):
        value = {
            **{
                key: "/owned/" + key
                for key in (
                    "gateway",
                    "delegate",
                    "delegate_run",
                    "pueue",
                    "pueued",
                    "delegate_repository",
                )
            },
            "schema_version": 1,
            "run_id": "0123456789abcdef",
            "allocation": 1,
            "ca_pem": "fixture public CA",
            "device_ca_pem": "fixture public CA",
            "gateway_id": "gateway-a",
            "device_id": "device-a",
            "project_alias": "project-a",
            "enrollment_url": "https://127.0.0.1:9443/v1/enroll",
            "wss_url": "wss://127.0.0.1:9444/device",
        }
        with (
            mock.patch.object(
                peer, "owned_path", side_effect=lambda path, **_: Path(path)
            ),
            mock.patch.object(peer, "validate_selected_pairs"),
            mock.patch.object(peer.ssl, "PEM_cert_to_DER_cert"),
        ):
            self.assertIs(peer.Manifest.parse(value).capture_native, False)
            for flag in (False, True):
                self.assertIs(
                    peer.Manifest.parse(
                        {**value, "capture_native": flag}
                    ).capture_native,
                    flag,
                )
            for invalid in (0, 1, "true", None, [], {}):
                with (
                    self.subTest(invalid=invalid),
                    self.assertRaises(peer.local.ProofFailure),
                ):
                    peer.Manifest.parse({**value, "capture_native": invalid})
            with self.assertRaises(peer.local.ProofFailure):
                peer.Manifest.parse(
                    {**value, "capture_native": True, "shell": "unexpected"}
                )
        self.assertNotIn(
            "capture_native", value, "parsing does not mutate caller input"
        )

    def test_enrollment_is_exact_device_and_canonical_32_byte_token(self):
        enrollment = {
            "device_id": "device-a",
            "token": base64.urlsafe_b64encode(bytes(32)).decode().rstrip("="),
            "expires_at": "2030-01-01T00:00:00Z",
        }
        self.assertEqual(peer.enrollment_input(enrollment, "device-a"), enrollment)
        for delta in (
            {"device_id": "device-b"},
            {"token": "x"},
            {"token": enrollment["token"] + "="},
            {"expires_at": "2030-01-01"},
            {"extra": True},
        ):
            with (
                self.subTest(delta=delta),
                self.assertRaises((ValueError, peer.local.ProofFailure)),
            ):
                peer.enrollment_input({**enrollment, **delta}, "device-a")

    def test_allocation_reuses_attempt_before_cap_and_never_allows_more_than_two(self):
        for allocation in (1, 2):
            source = peer.allocation_wrapper(
                Path("/fixture/pi"),
                Path("/fixture/counter"),
                Path("/fixture"),
                allocation,
            )
            self.assertIn(f"if count >= {allocation}:", source)
            self.assertLess(
                source.index("event(b'attempt')"),
                source.index(f"if count >= {allocation}:"),
            )
            self.assertIn("LOCK_EX | fcntl.LOCK_NB", source)
        with self.assertRaises(peer.local.ProofFailure):
            peer.allocation_wrapper(
                Path("/fixture/pi"), Path("/fixture/counter"), Path("/fixture"), 3
            )
        with (
            mock.patch.object(peer.local, "provider_wrapper", return_value="changed"),
            self.assertRaises(peer.local.ProofFailure),
        ):
            peer.allocation_wrapper(
                Path("/fixture/pi"), Path("/fixture/counter"), Path("/fixture"), 1
            )

    def test_fixed_operation_rejects_dynamic_arguments_without_side_effects(self):
        owner = object.__new__(peer.Peer)
        owner.finished = False
        owner.interruptions = peer.local.Interruptions()
        for request in (
            {"operation": "command"},
            {"operation": "start_connector", "argv": ["sh"]},
            {"operation": "shutdown", "path": "/tmp"},
        ):
            with (
                self.subTest(request=request),
                self.assertRaises(peer.local.ProofFailure),
            ):
                owner.operate(request)

    def test_closure_projection_keeps_requested_wait_deadline_and_no_private_payload(
        self,
    ):
        record = {
            "termination": {"cause": "requested", "scope_empty": True},
            "worker_wait": {"observed_at": "2030-01-01T00:00:01Z", "result": "success"},
            "intent": {"deadline": "2030-01-01T00:00:30Z"},
            "brief": "private",
            "result": "private",
        }
        result = peer.project_closure({"tasks": {"a" * 32: record}})
        self.assertEqual(
            result["a" * 32],
            {
                "cause": "requested",
                "scope_empty": True,
                "worker_wait": "2030-01-01T00:00:01Z",
                "worker_wait_result": "success",
                "deadline": "2030-01-01T00:00:30Z",
            },
        )
        self.assertNotIn("private", json.dumps(result))
        record["termination"] = None
        self.assertIsNone(
            peer.project_closure({"tasks": {"a" * 32: record}})["a" * 32]["scope_empty"]
        )

    def test_input_eof_and_partial_eof_are_distinct(self):
        for contents, fails in ((b'{"operation":"shutdown"}\n', False), (b"{", True)):
            read_fd, write_fd = os.pipe()
            with os.fdopen(read_fd, "rb") as stream:
                os.write(write_fd, contents)
                os.close(write_fd)
                if fails:
                    with self.assertRaises(peer.local.ProofFailure):
                        list(peer.lines(stream, peer.local.Interruptions(), 1))
                else:
                    self.assertEqual(
                        list(peer.lines(stream, peer.local.Interruptions(), 1)),
                        [{"operation": "shutdown"}],
                    )

    def test_signal_is_delivered_during_bounded_input_wait(self):
        interruptions = peer.local.Interruptions()
        interruptions.handle(15, None)
        read_fd, write_fd = os.pipe()
        try:
            with (
                os.fdopen(read_fd, "rb") as stream,
                self.assertRaises(peer.local.ProofFailure),
            ):
                next(peer.lines(stream, interruptions, 1))
        finally:
            os.close(write_fd)

    def test_output_backpressure_delivers_cooperative_signal_before_deadline(self):
        read_fd, write_fd = os.pipe()
        os.set_blocking(write_fd, False)
        while True:
            try:
                os.write(write_fd, b"x" * 4096)
            except BlockingIOError:
                break
        os.set_blocking(write_fd, True)
        interruptions = peer.local.Interruptions()
        timer = threading.Timer(0.02, interruptions.handle, args=(15, None))
        try:
            with (
                os.fdopen(write_fd, "w") as stream,
                mock.patch.object(sys, "stdout", stream),
                mock.patch.object(peer, "OUTPUT_TIMEOUT", 2),
            ):
                timer.start()
                started = time.monotonic()
                with self.assertRaisesRegex(peer.local.ProofFailure, "interrupted"):
                    peer.emit({"event": "bounded"}, interruptions)
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(os.get_blocking(stream.fileno()))
        finally:
            timer.cancel()
            timer.join()
            os.close(read_fd)

    def test_request_envelope_enforces_exact_contiguous_bounded_ids(self):
        payload = {"operation": "inspect_closure"}
        self.assertIs(
            peer.request_payload({"request_id": 1, "payload": payload}, 1), payload
        )
        self.assertIs(
            peer.request_payload({"request_id": 33, "payload": payload}, 33), payload
        )
        for envelope, expected in (
            ({"request_id": True, "payload": payload}, 1),
            ({"request_id": 1.0, "payload": payload}, 1),
            ({"request_id": "1", "payload": payload}, 1),
            ({"request_id": 0, "payload": payload}, 1),
            ({"request_id": -1, "payload": payload}, 1),
            ({"request_id": 2, "payload": payload}, 1),
            ({"request_id": 1, "payload": payload}, 2),
            ({"request_id": 3, "payload": payload}, 2),
            ({"request_id": 34, "payload": payload}, 34),
            ({"request_id": 1}, 1),
            ({"request_id": 1, "payload": payload, "extra": None}, 1),
            ({"request_id": 1, "payload": []}, 1),
            ({"request_id": 1, "payload": {"request_id": 1}}, 1),
            ({"request_id": 1, "payload": {"payload": {}}}, 1),
        ):
            with self.subTest(envelope=envelope, expected=expected):
                with self.assertRaises(peer.local.ProofFailure):
                    peer.request_payload(envelope, expected)

    def test_main_echoes_request_ids_without_changing_inner_payloads(self):
        operation = {"operation": "inspect_closure"}
        owner = SimpleNamespace(
            initialize=mock.Mock(return_value={"base": "/owned"}),
            operate=mock.Mock(return_value={"closure_confirmed": False}),
            finished=False,
            finish=mock.Mock(return_value={"cleanup_confirmed": True}),
            processes=object(),
            __init__=mock.Mock(),
        )
        inputs = [{"request_id": 1, "payload": {}}] + [
            {"request_id": request_id, "payload": operation} for request_id in (2, 3)
        ]
        receipts = []
        with (
            mock.patch.object(peer, "lines", return_value=iter(inputs)),
            mock.patch.object(peer.Manifest, "parse") as parse,
            mock.patch.object(peer.Peer, "__new__", return_value=owner),
            mock.patch.object(peer.signal, "signal"),
            mock.patch.object(
                peer, "emit", side_effect=lambda value, _: receipts.append(value)
            ),
        ):
            self.assertEqual(peer.main(), 0)
        parse.assert_called_once_with({})
        self.assertEqual(
            owner.operate.call_args_list, [mock.call(operation), mock.call(operation)]
        )
        self.assertEqual(
            [(value["event"], value.get("request_id")) for value in receipts],
            [
                ("initialized", 1),
                ("inspect_closure", 2),
                ("inspect_closure", 3),
                ("final", None),
            ],
        )

    def test_main_invalid_request_sequence_has_no_operation_side_effect_and_cleans_up(
        self,
    ):
        for invalid_id in (2, 4, True):
            with self.subTest(invalid_id=invalid_id):
                operation = {"operation": "inspect_closure"}
                owner = SimpleNamespace(
                    initialize=mock.Mock(return_value={}),
                    operate=mock.Mock(return_value={"closure_confirmed": False}),
                    finished=False,
                    finish=mock.Mock(return_value={"cleanup_confirmed": True}),
                    processes=object(),
                    __init__=mock.Mock(),
                )
                inputs = [{"request_id": 1, "payload": {}}] + [
                    {"request_id": request_id, "payload": operation}
                    for request_id in (2, invalid_id)
                ]
                receipts = []
                with (
                    mock.patch.object(peer, "lines", return_value=iter(inputs)),
                    mock.patch.object(peer.Manifest, "parse"),
                    mock.patch.object(peer.Peer, "__new__", return_value=owner),
                    mock.patch.object(peer.signal, "signal"),
                    mock.patch.object(
                        peer,
                        "emit",
                        side_effect=lambda value, _: receipts.append(value),
                    ),
                ):
                    self.assertEqual(peer.main(), 1)
                owner.operate.assert_called_once_with(operation)
                owner.finish.assert_called_once()
                self.assertEqual(
                    [(value["event"], value.get("request_id")) for value in receipts],
                    [
                        ("initialized", 1),
                        ("inspect_closure", 2),
                        ("failed", None),
                        ("final", None),
                    ],
                )

    def test_response_body_cannot_override_transport_fields(self):
        self.assertEqual(
            peer.event_frame("initialized", {"base": "/owned"}, 1),
            {"event": "initialized", "request_id": 1, "base": "/owned"},
        )
        for result in ({"event": "final"}, {"request_id": 99}, [], None):
            with self.subTest(result=result):
                with self.assertRaises(peer.local.ProofFailure):
                    peer.event_frame("initialized", result, 1)
                with self.assertRaises(peer.local.ProofFailure):
                    peer.event_frame("final", result)

    def test_main_eof_always_runs_owned_cleanup_and_reports_separately(self):
        owner = SimpleNamespace(
            initialize=mock.Mock(return_value={"base": "/owned"}),
            finished=False,
            finish=mock.Mock(
                return_value={"cleanup_confirmed": True, "cleanup_gate_released": True}
            ),
            processes=object(),
            __init__=mock.Mock(),
        )
        receipts = []
        with (
            mock.patch.object(
                peer, "lines", return_value=iter([{"request_id": 1, "payload": {}}])
            ),
            mock.patch.object(peer.Manifest, "parse"),
            mock.patch.object(peer.Peer, "__new__", return_value=owner),
            mock.patch.object(peer.signal, "signal"),
            mock.patch.object(
                peer, "emit", side_effect=lambda value, _: receipts.append(value)
            ),
        ):
            self.assertEqual(peer.main(), 0)
        owner.finish.assert_called_once()
        self.assertEqual(
            receipts[-1],
            {
                "event": "final",
                "cleanup_confirmed": True,
                "cleanup_gate_released": True,
            },
        )


class PairSelectionTests(unittest.TestCase):
    def test_bundle_fixture_accepts_a_symlinked_temporary_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            physical = base / "physical"
            physical.mkdir()
            alias = base / "alias"
            alias.symlink_to(physical, target_is_directory=True)
            case = PairSelectionTests(
                "test_bundle_precedence_matches_native_before_path"
            )
            result = unittest.TestResult()
            with mock.patch.object(tempfile, "tempdir", str(alias)):
                case.run(result)
            self.assertEqual(result.testsRun, 1)
            self.assertEqual(result.skipped, [])
            self.assertEqual(result.failures + result.errors, [])

    def pair(self, directory, first, second):
        directory.mkdir(parents=True, exist_ok=True)
        for name in (first, second):
            path = directory / name
            path.write_text("literal; never executed in this test")
            path.chmod(0o700)
        return directory / first, directory / second

    def test_runner_is_the_explicit_adjacent_named_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            delegate, runner = self.pair(base / "bin", "delegate", "delegate-run")
            client, daemon = self.pair(base / "native", "pueue", "pueued")
            peer.validate_selected_pairs(delegate, runner, client, daemon)
            for wrong_delegate, wrong_runner in (
                (delegate, base / "other/delegate-run"),
                (delegate, runner.with_name("other")),
                (delegate.with_name("other"), runner),
            ):
                with self.assertRaises(peer.local.ProofFailure):
                    peer.validate_selected_pairs(
                        wrong_delegate, wrong_runner, client, daemon
                    )
            with self.assertRaises(peer.local.ProofFailure):
                peer.validate_selected_pairs(
                    delegate, runner, client, base / "other/pueued"
                )

    def test_bundle_precedence_matches_native_before_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            delegate, runner = self.pair(base / "bin", "delegate", "delegate-run")
            path_pair = self.pair(base / "path", "pueue", "pueued")
            libexec_pair = self.pair(base / "libexec", "pueue", "pueued")
            with self.assertRaises(peer.local.ProofFailure):
                peer.validate_selected_pairs(delegate, runner, *path_pair)
            peer.validate_selected_pairs(delegate, runner, *libexec_pair)
            colocated = self.pair(base / "bin", "pueue", "pueued")
            with self.assertRaises(peer.local.ProofFailure):
                peer.validate_selected_pairs(delegate, runner, *libexec_pair)
            peer.validate_selected_pairs(delegate, runner, *colocated)
            colocated[1].unlink()
            with self.assertRaises(FileNotFoundError):
                peer.validate_selected_pairs(delegate, runner, *path_pair)


class OwnedProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository = os.environ.get("DELEGATE_ACCEPTANCE_REPOSITORY")
        if not repository:
            raise unittest.SkipTest(
                "set DELEGATE_ACCEPTANCE_REPOSITORY for maintained owner tests"
            )
        cls.acceptance = peer.local.load_acceptance(Path(repository))
        cls.repository = Path(repository)

    @contextmanager
    def retained_observer(self):
        local_tests = importlib.import_module("test_e2e_local")
        fixture = local_tests.MaintainedFixtureLeaseTests(
            "test_one_handshake_supports_repeated_borrowed_live_checks_then_closes_once"
        )
        fixture.acceptance = self.acceptance
        with fixture.one_shot_writer() as (root, before, _path, _writer):
            owner = object.__new__(peer.Peer)
            owner.root = root
            root.fixture_gate = SimpleNamespace(descriptor=1)
            owner.fixture_snapshot = before
            owner.fixture_observers = ExitStack()
            owner.fixture_observer = None
            owner.interruptions = peer.local.Interruptions()
            owner.finished = False
            owner.fixture_attempts = mock.Mock(
                return_value={
                    "attempted": 1,
                    "rejected_concurrent": 0,
                    "rejected_limit": 0,
                }
            )
            try:
                yield owner
            finally:
                owner.fixture_observers.close()

    def test_repeated_peer_proofs_reuse_one_real_handshake_and_reject_changed_binding(
        self,
    ):
        with self.retained_observer() as owner:
            request = {"operation": "wait_fixture_started", "task_id": "b" * 32}
            acquire = self.acceptance.leases.LiveFIFOLease.acquire
            with mock.patch.object(
                self.acceptance.leases.LiveFIFOLease, "acquire", wraps=acquire
            ) as acquired:
                self.assertTrue(owner.operate(request)["live_lease_proven"])
                snapshot, observation, lease = owner.fixture_observer
                with mock.patch.object(lease, "close", wraps=lease.close) as closed:
                    self.assertTrue(owner.operate(request)["live_lease_proven"])
                    self.assertEqual(lease.pid, observation.pid)
                    self.assertEqual(lease.identity, observation.identity)
                    self.assertEqual(acquired.call_count, 1)
                    with self.assertRaises(peer.local.ProofFailure):
                        owner.operate({**request, "task_id": "c" * 32})
                    owner.fixture_snapshot = peer.local.FixtureExecutionSnapshot(
                        snapshot.root,
                        snapshot.nonce,
                        snapshot.context,
                        snapshot.executions,
                        snapshot.waiters,
                    )
                    with self.assertRaises(peer.local.ProofFailure):
                        owner.operate(request)
                    owner.fixture_snapshot = snapshot
                    owner.root.counter.write_text("execution\n" * 2)
                    with self.assertRaises(peer.local.ProofFailure):
                        owner.operate(request)
                    owner.root.counter.write_text("execution\n")
                    owner.fixture_attempts.return_value["rejected_limit"] = 1
                    with self.assertRaises(peer.local.ProofFailure):
                        owner.operate(request)
                    owner.fixture_attempts.return_value["rejected_limit"] = 0
                    owner.fixture_observers.close()
                    closed.assert_called_once_with()
                    with self.assertRaisesRegex(RuntimeError, "already closed"):
                        owner.operate(request)
                    self.assertEqual(acquired.call_count, 1)

    def test_retained_context_closes_before_cleanup_when_intake_join_fails(self):
        with (
            self.retained_observer() as owner,
            tempfile.TemporaryDirectory() as temporary,
        ):
            owner.operate({"operation": "wait_fixture_started", "task_id": "b" * 32})
            lease = owner.fixture_observer[2]
            owner.base = Path(temporary).resolve()
            owner.root.daemon = None
            owner.root.finish = mock.Mock()
            owner.root.release_fixture_gate = mock.Mock(
                side_effect=lambda: setattr(owner.root.fixture_gate, "descriptor", -1)
            )
            child = mock.Mock(
                argv=["gateway", "connector", "run"], pid=123, result=None
            )
            child.poll.return_value = None
            child.wait.side_effect = RuntimeError("intake join failed")
            owner.processes = mock.Mock(entries=[child])
            owner.ownership = mock.Mock()
            owner.ownership.release.side_effect = lambda: self.assertEqual(
                lease.descriptor, -1
            )
            owner.cleanup_gate_released = False
            owner.accepted_commands = set()
            owner.manifest = SimpleNamespace(allocation=1)
            with mock.patch.object(lease, "close", wraps=lease.close) as closed:
                receipt = owner.finish()
                self.assertFalse(receipt["cleanup_confirmed"])
                closed.assert_called_once_with()
                owner.root.finish.assert_not_called()
                self.assertIs(owner.finish(), receipt)
                closed.assert_called_once_with()

    def test_real_previous_boot_closure_has_no_synthetic_worker_wait(self):
        fixture_module = importlib.import_module(
            "scripts.acceptance.private_cli.tests.test_shutdown"
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = fixture_module.ManagedLifetimeFixture(Path(temporary).resolve())
            fixture.write_task(include_wait=False, termination_cause="previous-boot")
            canonical = self.acceptance.supervisor.read_managed_closure(
                fixture.state, ()
            )
            self.assertIsNone(canonical["tasks"][fixture_module.TASK_ID]["worker_wait"])
            self.assertEqual(
                peer.project_closure(canonical)[fixture_module.TASK_ID],
                {
                    "cause": "previous-boot",
                    "scope_empty": True,
                    "worker_wait": None,
                    "worker_wait_result": None,
                    "deadline": "2026-10-13T00:01:00Z",
                },
            )

    def intent_absence_fixture(self, parent):
        fixture_module = importlib.import_module(
            "scripts.acceptance.private_cli.tests.test_shutdown"
        )
        fixture = fixture_module.ManagedLifetimeFixture(parent)
        fixture.write_task()
        lifetime = fixture.task / "lifetime"
        for name in (
            "registration.json",
            "worker.json",
            "00000000000000000001.launch.json",
            "terminated.json",
        ):
            (lifetime / name).unlink()
        intent_path = lifetime / "intent.json"
        intent = json.loads(intent_path.read_text())
        boot = "linux:11111111-1111-1111-1111-111111111111"
        intent["boot_id"] = boot
        fixture_module.write_record(intent_path, intent)
        fixture_module.write_record(
            lifetime / "worker-wait.json",
            {
                "schema_version": 1,
                "root_id": fixture_module.ROOT_ID,
                "task_id": fixture_module.TASK_ID,
                "registration_sha256": "",
                "child_pid": 0,
                "result": "absent",
                "observed_at": "2026-10-13T00:00:09Z",
                "absence_proof": "unregistered-disposed",
                "observed_boot_id": boot,
                "intent_sha256": fixture_module.evidence_files.digest(intent_path),
            },
        )
        return fixture, fixture_module

    def test_real_intent_only_absence_preserves_recorded_result_without_termination(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, fixture_module = self.intent_absence_fixture(
                Path(temporary).resolve()
            )
            canonical = self.acceptance.supervisor.read_managed_closure(
                fixture.state, ()
            )
            self.assertIsNone(canonical["tasks"][fixture_module.TASK_ID]["termination"])
            self.assertEqual(
                peer.project_closure(canonical)[fixture_module.TASK_ID],
                {
                    "cause": None,
                    "scope_empty": None,
                    "worker_wait": "2026-10-13T00:00:09Z",
                    "worker_wait_result": "absent",
                    "deadline": "2026-10-13T00:01:00Z",
                },
            )

    def test_incomplete_absence_evidence_still_fails_canonical_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, _ = self.intent_absence_fixture(Path(temporary).resolve())
            (fixture.task / "lifetime/worker-wait.json").unlink()
            with self.assertRaises(self.acceptance.supervisor.AcceptanceFailure):
                self.acceptance.supervisor.read_managed_closure(fixture.state, ())

    def nonlaunching_manifest(self):
        # These paths are constructor-only fixtures: initialize is never called
        # here, so no executable role or TLS behavior is claimed by these tests.
        return peer.Manifest(
            run_id="0123456789abcdef",
            gateway=Path(sys.executable),
            delegate=Path(sys.executable),
            delegate_run=Path(sys.executable),
            pueue=Path(sys.executable),
            pueued=Path(sys.executable),
            delegate_repository=self.repository,
            allocation=1,
            ca_pem="public fixture CA",
            device_ca_pem="public fixture device CA",
            gateway_id="fixture-gateway",
            device_id="fixture-device",
            project_alias="fixture-project",
            enrollment_url="https://127.0.0.1:9443/v1/enroll",
            wss_url="wss://127.0.0.1:9444/device",
        )

    def test_capture_opt_in_uses_existing_root_wrapper_for_enrollment_and_tags_receipt(
        self,
    ):
        for capture_native in (False, True):
            with (
                self.subTest(capture_native=capture_native),
                tempfile.TemporaryDirectory(dir=Path.home()) as temporary,
            ):
                home = Path(temporary).resolve()
                manifest = replace(
                    self.nonlaunching_manifest(),
                    delegate=Path("/owned/delegate"),
                    capture_native=capture_native,
                )
                with mock.patch.object(
                    peer.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))
                ):
                    owner = peer.Peer(manifest, peer.local.Interruptions())
                try:
                    self.assertIs(owner.args.capture_native, capture_native)
                    with (
                        mock.patch.object(
                            peer.local.DelegateRoot,
                            "start",
                            autospec=True,
                            side_effect=lambda root: setattr(
                                root,
                                "context",
                                {
                                    "root_token": "fixture-root",
                                    "project_token": "fixture-project",
                                },
                            ),
                        ),
                        mock.patch.object(
                            peer.local,
                            "native_capture_launcher",
                            wraps=peer.local.native_capture_launcher,
                        ) as launcher,
                    ):
                        receipt = owner.initialize()
                    root = owner.root
                    if capture_native:
                        self.assertEqual(
                            receipt["native_control_variant"], "diagnostic_capture"
                        )
                        self.assertEqual(
                            root.connector_executable, root.base / "delegate-capture"
                        )
                        self.assertTrue(root.connector_executable.is_file())
                        self.assertEqual(
                            root.connector_executable.stat().st_mode & 0o777, 0o700
                        )
                        launcher.assert_called_once_with(
                            manifest.delegate,
                            manifest.delegate_repository,
                            root.native_captures,
                        )
                    else:
                        self.assertNotIn("native_control_variant", receipt)
                        self.assertEqual(root.connector_executable, manifest.delegate)
                        launcher.assert_not_called()
                    self.assertNotIn("native_captures", receipt)
                    self.assertNotIn("capture_native", receipt)
                    self.assertNotIn("delegate_executable", receipt)
                    enrollment = {
                        "device_id": manifest.device_id,
                        "token": base64.urlsafe_b64encode(bytes(32))
                        .decode()
                        .rstrip("="),
                        "expires_at": "2030-01-01T00:00:00Z",
                    }
                    with mock.patch.object(owner, "command") as command:
                        self.assertEqual(owner.enroll(enrollment), {"enrolled": True})
                    config = json.loads(owner.connector_config.read_text())
                    self.assertEqual(
                        config["delegate_executable"], str(root.connector_executable)
                    )
                    self.assertEqual(owner.args.delegate, manifest.delegate)
                    self.assertEqual(command.call_args.args[0], manifest.gateway)
                    self.assertEqual(
                        owner.processes.entries,
                        [],
                        "no process or provider was started",
                    )
                finally:
                    owner.fixture_observers.close()
                    pending = owner.processes.drain(timeout=5)
                    if pending:
                        owner.ownership.release()
                        raise RuntimeError(
                            "closure unconfirmed; retained " + str(owner.base)
                        )
                    owner.ownership.rollback()

    def test_known_root_is_exclusive_and_collision_never_adopts_existing_files(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            home = Path(temporary).resolve()
            manifest = self.nonlaunching_manifest()
            with mock.patch.object(
                peer.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))
            ):
                owner = object.__new__(peer.Peer)
                owner.__init__(manifest, peer.local.Interruptions())
                expected = home / "gp-0123456789abcdef"
                self.assertEqual(owner.base, expected)
                identity = expected.stat().st_ino
                marker = expected / "existing-evidence"
                marker.write_text("retain")
                collided = object.__new__(peer.Peer)
                try:
                    with self.assertRaises(FileExistsError):
                        collided.__init__(manifest, peer.local.Interruptions())
                    self.assertFalse(hasattr(collided, "processes"))
                    self.assertEqual(expected.stat().st_ino, identity)
                    self.assertEqual(marker.read_text(), "retain")
                finally:
                    collided.ownership.release()
                    owner.finish()

    def test_initial_publication_loss_leaves_receipt_at_caller_known_locator(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            home = Path(temporary).resolve()
            manifest = self.nonlaunching_manifest()
            expected = home / ("gp-" + manifest.run_id) / "peer-final.json"
            emitted = []

            def publish(value, _interruptions):
                emitted.append(value["event"])
                raise BrokenPipeError("controlled transport loss")

            with (
                mock.patch.object(
                    peer.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))
                ),
                mock.patch.object(
                    peer, "lines", return_value=iter([{"request_id": 1, "payload": {}}])
                ),
                mock.patch.object(peer.Manifest, "parse", return_value=manifest),
                mock.patch.object(peer.Peer, "initialize", return_value={}),
                mock.patch.object(peer.signal, "signal"),
                mock.patch.object(peer, "emit", side_effect=publish),
            ):
                self.assertEqual(peer.main(), 1)
            receipt = json.loads(expected.read_text())
            self.assertTrue(receipt["cleanup_confirmed"])
            self.assertEqual(receipt["base"], str(expected.parent))
            self.assertEqual(receipt["remote_wait_receipts"], [])
            self.assertEqual(emitted, ["initialized", "failed", "final"])

    def test_root_gate_acquisition_before_checkpoint_failure_is_released_and_reported(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = object.__new__(peer.local.DelegateRoot)
            root.owner = SimpleNamespace(acceptance=self.acceptance)
            root.gate = Path(temporary).resolve() / "gate"
            root.fixture_gate = None
            root.fixture_execution_snapshot = mock.Mock(return_value=object())
            owner = object.__new__(peer.Peer)
            owner.root = root
            owner.finished = False
            owner.fixture_observer = None
            owner.interruptions = peer.local.Interruptions()
            owner.cleanup_gate_released = False
            original = root.acquire_fixture_gate

            def acquired():
                result = original()
                owner.interruptions.handle(15, None)
                return result

            with mock.patch.object(root, "acquire_fixture_gate", side_effect=acquired):
                with self.assertRaisesRegex(peer.local.ProofFailure, "interrupted"):
                    owner.operate({"operation": "hold_fixture"})
            self.assertGreaterEqual(root.fixture_gate.descriptor, 0)
            inode = root.gate.stat().st_ino
            owner.release_gate(cleanup=True)
            self.assertTrue(owner.cleanup_gate_released)
            self.assertEqual(root.fixture_gate.descriptor, -1)
            self.assertEqual(root.gate.stat().st_ino, inode)
            owner.release_gate(cleanup=True)
            with self.assertRaises(peer.local.ProofFailure):
                root.acquire_fixture_gate()

    def test_full_output_pipe_cannot_prevent_owned_cleanup(self):
        self.full_output_pipe("initialized")

    def test_final_publication_failure_is_bounded_after_actual_wait(self):
        self.full_output_pipe("final")

    def full_output_pipe(self, blocked_event):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            ownership = self.acceptance.directories.DirectoryOwner()
            processes = self.acceptance.processes.Processes(
                base / "captures",
                environment={"PATH": "/usr/bin:/bin"},
                owner=ownership,
                environment_keys_only=True,
            )
            literal = base / "literal-child"
            marker = base / "ready"
            literal.write_text(
                f"#!{sys.executable}\nimport signal,sys\nfrom pathlib import Path\nsignal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\nPath(sys.argv[-1]).write_text('ready')\nwhile True: signal.pause()\n"
            )
            literal.chmod(0o700)
            child = processes.start("literal-child", [literal, marker], base)
            deadline = time.monotonic() + 5
            while not marker.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            read_fd, write_fd = os.pipe()
            os.set_blocking(write_fd, False)
            while True:
                try:
                    os.write(write_fd, b"x" * 4096)
                except BlockingIOError:
                    break
            os.set_blocking(write_fd, True)
            stream = os.fdopen(write_fd, "w", buffering=1)
            observed = []
            cleanup_entered = threading.Event()
            publication_entered = threading.Event()

            def cleanup():
                cleanup_entered.set()
                child.process.send_signal(peer.signal.SIGTERM)
                child.wait(5, expected=0)
                observed.append("actual_wait")
                return {"cleanup_confirmed": True}

            owner = SimpleNamespace(
                initialize=mock.Mock(return_value={"base": str(base)}),
                finished=False,
                finish=mock.Mock(side_effect=cleanup),
                processes=processes,
                __init__=mock.Mock(),
            )
            result = []
            failures = []

            def run():
                try:
                    result.append(peer.main())
                except BaseException as error:
                    failures.append(error)

            worker = threading.Thread(target=run)
            original_emit = peer.emit

            def publish(value, interruptions):
                if blocked_event == "final" and value["event"] == "initialized":
                    return
                if value["event"] == blocked_event:
                    publication_entered.set()
                return original_emit(value, interruptions)

            try:
                with (
                    mock.patch.object(
                        peer,
                        "lines",
                        return_value=iter([{"request_id": 1, "payload": {}}]),
                    ),
                    mock.patch.object(peer.Manifest, "parse"),
                    mock.patch.object(peer.Peer, "__new__", return_value=owner),
                    mock.patch.object(peer.signal, "signal"),
                    mock.patch.object(peer, "OUTPUT_TIMEOUT", 0.05, create=True),
                    mock.patch.object(sys, "stdout", stream),
                    mock.patch.object(peer, "emit", side_effect=publish),
                ):
                    worker.start()
                    self.assertTrue(
                        publication_entered.wait(6),
                        "publication was not reached after bounded child Wait",
                    )
                    if blocked_event == "initialized":
                        bounded_publication = cleanup_entered.wait(1)
                        worker.join(6 if bounded_publication else 0)
                    else:
                        worker.join(1)
                        bounded_publication = not worker.is_alive()
                    # Release the intentionally blocked old implementation in
                    # finally too, so a genuine pre-fix failure leaks no thread.
                    os.set_blocking(read_fd, False)
                    while True:
                        try:
                            os.read(read_fd, 4096)
                        except BlockingIOError:
                            break
                    worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertTrue(
                    bounded_publication, "stdout backpressure prevented owned cleanup"
                )
                self.assertEqual(failures, [])
                self.assertEqual(result, [1])
                self.assertEqual(observed, ["actual_wait"])
                self.assertTrue(child.result["natural_wait"])
            finally:
                stream.close()
                os.close(read_fd)
                if child.poll() is None:
                    child.process.send_signal(peer.signal.SIGTERM)
                child.wait(5, expected=0)
                ownership.release()

    def test_eof_joins_exact_live_intake_child_before_native_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            owner = object.__new__(peer.Peer)
            owner.base = base
            owner.interruptions = peer.local.Interruptions()
            owner.ownership = self.acceptance.directories.DirectoryOwner()
            owner.processes = self.acceptance.processes.Processes(
                base / "captures",
                environment={"PATH": "/usr/bin:/bin"},
                owner=owner.ownership,
                environment_keys_only=True,
            )
            owner.root = cleanup_root()
            owner.fixture_observers = ExitStack()
            owner.cleanup_gate_released = False
            owner.finished = False
            owner.accepted_commands = set()
            owner.manifest = SimpleNamespace(allocation=1)
            owner.initialize = mock.Mock(return_value={"base": str(base)})
            marker = base / "ready"
            literal = base / "literal-intake"
            literal.write_text(
                f"#!{sys.executable}\nimport signal,sys\nfrom pathlib import Path\nsignal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\nPath(sys.argv[-1]).write_text('ready')\nwhile True: signal.pause()\n"
            )
            literal.chmod(0o700)
            process = owner.processes.start(
                "literal-intake", [literal, "connector", "run", marker], base
            )
            try:
                deadline = time.monotonic() + 5
                while not marker.exists():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                receipts = []
                with (
                    mock.patch.object(
                        peer,
                        "lines",
                        return_value=iter([{"request_id": 1, "payload": {}}]),
                    ),
                    mock.patch.object(peer.Manifest, "parse"),
                    mock.patch.object(peer.Peer, "__new__", return_value=owner),
                    mock.patch.object(peer.Peer, "__init__", return_value=None),
                    mock.patch.object(peer.signal, "signal"),
                    mock.patch.object(
                        peer,
                        "emit",
                        side_effect=lambda value, _: receipts.append(value),
                    ),
                ):
                    self.assertEqual(peer.main(), 0)
                receipt = receipts[-1]
                self.assertTrue(receipt["cleanup_confirmed"])
                self.assertTrue(receipt["cleanup_gate_released"])
                self.assertEqual(
                    receipt["remote_wait_receipts"],
                    [{"pid": process.pid, "natural_wait": True, "exit_code": 0}],
                )
                owner.root.finish.assert_called_once_with()
            finally:
                if process.poll() is None:
                    process.process.send_signal(peer.signal.SIGTERM)
                process.wait(5, expected=0)

    def test_real_owned_literal_children_enforce_allocation_before_exec(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            ownership = self.acceptance.directories.DirectoryOwner()
            processes = self.acceptance.processes.Processes(
                base / "captures",
                environment={"PATH": "/usr/bin:/bin"},
                owner=ownership,
                environment_keys_only=True,
            )
            literal = base / "literal-child"
            literal.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n")
            literal.chmod(0o700)
            wrapper = base / "allocation-owner"
            wrapper.write_text(
                peer.allocation_wrapper(literal, base / "invocations", base, 2)
            )
            wrapper.chmod(0o700)
            try:
                for index, expected in enumerate((0, 0, 73)):
                    processes.run(
                        f"attempt-{index}",
                        [sys.executable, wrapper, "--mode", "literal"],
                        base,
                        expected=expected,
                        timeout=5,
                    )
                self.assertFalse(processes.pending())
                self.assertEqual(
                    (base / "invocations").read_text().splitlines(),
                    ["execution", "execution"],
                )
                observer = object.__new__(peer.Peer)
                observer.base = base
                self.assertEqual(
                    observer.fixture_attempts(),
                    {"attempted": 3, "rejected_concurrent": 0, "rejected_limit": 1},
                )
            finally:
                processes.drain(timeout=5)
                self.assertFalse(processes.pending())
                ownership.release()

    def run_cleanup(self, exit_code):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            owner = object.__new__(peer.Peer)
            owner.base = base
            owner.interruptions = peer.local.Interruptions()
            owner.ownership = self.acceptance.directories.DirectoryOwner()
            owner.processes = self.acceptance.processes.Processes(
                base / "processes",
                environment={"PATH": "/usr/bin:/bin"},
                owner=owner.ownership,
                environment_keys_only=True,
            )
            owner.root = cleanup_root()
            owner.fixture_observers = ExitStack()
            owner.cleanup_gate_released = False
            owner.finished = False
            owner.accepted_commands = set()
            owner.manifest = SimpleNamespace(allocation=1)
            process = owner.processes.start(
                "literal-child",
                [sys.executable, "-c", f"raise SystemExit({exit_code})"],
                base,
            )
            process.wait(5, expected=exit_code)
            receipt = owner.finish()
            self.assertTrue(process.result["natural_wait"])
            self.assertTrue((base / "processes").is_dir())
            self.assertEqual(owner.root.fixture_gate.descriptor, -1)
            self.assertTrue(receipt["cleanup_gate_released"])
            self.assertEqual(receipt["remote_wait_receipts"][0]["exit_code"], exit_code)
            self.assertEqual(owner.root.finish.call_count, int(exit_code == 0))
            self.assertIs(owner.finish(), receipt)
            return receipt

    def test_real_child_success_retains_actual_wait_and_canonical_cleanup_call(self):
        self.assertTrue(self.run_cleanup(0)["cleanup_confirmed"])

    def test_real_child_abnormal_exit_cannot_claim_native_cleanup(self):
        self.assertFalse(self.run_cleanup(2)["cleanup_confirmed"])


if __name__ == "__main__":
    unittest.main()
