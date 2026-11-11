"""Pure recovery acceptance boundary tests. No native workloads start here."""

import unittest
import json
import os
from contextlib import nullcontext
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import e2e_recovery
from e2e_local import FixtureExecutionSnapshot, FixtureLeaseObservation, ProofFailure


def fixture_root():
    return SimpleNamespace(
        device="device-one",
        alias="project-one",
        context={"root_token": "local-root", "project_token": "local-project"},
    )


class RecoveryBoundaryTests(unittest.TestCase):
    def active_restart(self):
        root = fixture_root()
        root.invocations = mock.Mock(return_value=3)
        prepared = {"operation_id": "op", "task_id": "task"}
        before = FixtureExecutionSnapshot(
            Path("/owned/state"), "nonce", ("root", "project"), 2, frozenset()
        )
        live = FixtureLeaseObservation("task", 123, Path("/owned/fifo"), (1, 2))
        lease = mock.Mock(spec=["assert_live", "pid", "path", "identity"])
        lease.pid, lease.path, lease.identity = live.pid, live.path, live.identity
        h = mock.Mock()
        h.assert_fixture_attempts = mock.Mock()
        h.summary = {"stages": []}
        h.until.side_effect = lambda check, *_args: check()
        h.mcp.return_value = {
            **prepared,
            "device_id": root.device,
            "project_alias": root.alias,
            "reserved": True,
            "delivery": "resolved",
            "observation": {"kind": "existing"},
        }
        scenario = e2e_recovery.RecoveryScenario(h)
        scenario.connected = mock.Mock(return_value=True)
        return scenario, root, prepared, before, live, lease

    def test_active_restart_revalidates_borrowed_lease_and_same_public_operation(self):
        scenario, root, prepared, before, live, lease = self.active_restart()
        h = scenario.h
        events = []
        lease.assert_live.side_effect = lambda: events.append("live")
        h.stop_process.side_effect = lambda _process: events.append(
            "old_gateway_joined"
        )
        h.start_gateway.side_effect = lambda: events.append("same_config_started")
        scenario.connected.side_effect = lambda _root: (
            events.append("reconnected") or True
        )
        scenario.restart_while_active(root, prepared, before, live, lease)
        self.assertEqual(
            events,
            [
                "live",
                "old_gateway_joined",
                "live",
                "same_config_started",
                "reconnected",
                "live",
                "live",
            ],
        )
        self.assertEqual(
            h.mcp.call_args_list,
            [
                mock.call("resolve_operation", {"operation_id": "op"}),
                mock.call("dispatch_task", {"operation_id": "op"}),
            ],
        )
        self.assertEqual(
            h.assert_fixture_attempts.call_args_list, [mock.call(3), mock.call(3)]
        )
        self.assertEqual(root.invocations.call_count, 3)
        self.assertEqual(h.summary["restart_while_active"]["provider_pid"], 123)
        self.assertIn(
            "same_registry_gateway_restart_during_live_task", h.summary["stages"]
        )

    def test_active_restart_missing_or_dead_initial_lease_cannot_stop_gateway(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                scenario, root, prepared, before, live, lease = self.active_restart()
                if missing:
                    live = None
                else:
                    lease.assert_live.side_effect = ProofFailure("writer died")
                with self.assertRaises(ProofFailure):
                    scenario.restart_while_active(root, prepared, before, live, lease)
                scenario.h.stop_process.assert_not_called()

    def test_active_restart_rejects_changed_lease_counter_and_public_operation(self):
        for fault in (
            "pid",
            "inode",
            "counter-before",
            "counter-after",
            "operation",
            "prepared",
            "dead-after-restart",
        ):
            with self.subTest(fault=fault):
                scenario, root, prepared, before, live, lease = self.active_restart()
                if fault == "pid":
                    lease.pid = 456
                elif fault == "inode":
                    lease.identity = (1, 3)
                elif fault == "counter-before":
                    root.invocations.return_value = 4
                elif fault == "counter-after":
                    root.invocations.side_effect = [3, 4]
                elif fault == "operation":
                    scenario.h.mcp.return_value["operation_id"] = "another-op"
                elif fault == "prepared":
                    scenario.h.mcp.return_value["delivery"] = "prepared"
                else:
                    lease.assert_live.side_effect = [
                        None,
                        None,
                        ProofFailure("writer died after restart"),
                    ]
                with self.assertRaises(ProofFailure):
                    scenario.restart_while_active(root, prepared, before, live, lease)
                self.assertNotIn("restart_while_active", scenario.h.summary)
                if fault in ("operation", "prepared"):
                    scenario.h.mcp.assert_called_once_with(
                        "resolve_operation", {"operation_id": "op"}
                    )
                if fault == "counter-before":
                    scenario.h.stop_process.assert_not_called()

    def test_restart_requires_same_validated_live_fixture_identity(self):
        before = FixtureLeaseObservation("task", 123, Path("/owned/fifo"), (1, 2))
        e2e_recovery.require_same_live_fixture(before, before)
        for after in (
            None,
            FixtureLeaseObservation("other", 123, before.path, before.identity),
            FixtureLeaseObservation("task", 456, before.path, before.identity),
            FixtureLeaseObservation("task", 123, Path("/other"), before.identity),
            FixtureLeaseObservation("task", 123, before.path, (1, 3)),
        ):
            with self.subTest(after=after), self.assertRaises(ProofFailure):
                e2e_recovery.require_same_live_fixture(before, after)

    def test_restart_reconciles_only_the_original_active_public_operation(self):
        root = fixture_root()
        prepared = {"operation_id": "op", "task_id": "task"}
        valid = {
            **prepared,
            "device_id": root.device,
            "project_alias": root.alias,
            "reserved": True,
            "delivery": "resolved",
            "observation": {
                "kind": "existing",
                "execution_closure_pending": "owner_busy",
            },
        }
        e2e_recovery.require_active_operation(valid, root, prepared)
        for field, value in (
            ("operation_id", "another-op"),
            ("task_id", "another-task"),
            ("device_id", "another-device"),
            ("project_alias", "another-project"),
            ("reserved", False),
            ("delivery", "prepared"),
            ("observation", None),
            ("observation", {"kind": "terminal"}),
            (
                "observation",
                {"kind": "existing", "execution_closure": {"kind": "native"}},
            ),
        ):
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(ProofFailure),
            ):
                e2e_recovery.require_active_operation(
                    {**valid, field: value}, root, prepared
                )

    def test_stale_fifo_cannot_advance_recovery_to_gateway_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = fixture_root()
            root.waiters = Path(directory)
            root.nonce = "nonce"
            os.mkfifo(root.waiters / "nonce-123.fifo", 0o600)
            root.gate = root.waiters / "gate"
            root.acquire_fixture_gate = mock.Mock()
            root.fixture_execution_snapshot = mock.Mock(return_value="before")
            root.fixture_execution_lease = mock.Mock(
                side_effect=ProofFailure("new fixture execution absent")
            )
            h = mock.Mock()
            h.roots = [root]
            h.prepare.return_value = {"operation_id": "op", "task_id": "task"}
            h.until.side_effect = lambda check, *_args: check()
            h.stop_process.side_effect = RuntimeError("stale FIFO advanced to stop")
            scenario = e2e_recovery.RecoveryScenario(h)
            scenario.assert_reserved = mock.Mock()
            with self.assertRaisesRegex(ProofFailure, "new fixture execution absent"):
                scenario.reserved_attributed()
            h.stop_process.assert_not_called()

    def test_offline_recovery_commits_before_listener_start(self):
        h = mock.Mock()
        h.gateway_config = {"database": "/owned/registry.sqlite"}
        scenario = e2e_recovery.RecoveryScenario(h)
        h.command.return_value = {
            "recovery_id": scenario.recovery,
            "kind": "restore",
        }
        scenario.start_recovery()
        self.assertEqual(
            [call[0] for call in h.mock_calls],
            ["stop_process", "command", "start_gateway", "check_auth"],
        )
        arguments = h.command.call_args.args[1]
        self.assertEqual(
            arguments,
            [
                "begin-recovery",
                "--database",
                "/owned/registry.sqlite",
                "--recovery-id",
                scenario.recovery,
            ],
        )
        h.reset_mock()
        h.command.return_value = {"recovery_id": "another-restore", "kind": "restore"}
        with self.assertRaises(ProofFailure):
            scenario.start_recovery()
        h.start_gateway.assert_not_called()

    def test_routing_coverage_retries_frozen_confirmation_after_reconnect(self):
        root = fixture_root()
        h = mock.Mock()
        scenario = e2e_recovery.RecoveryScenario(h)
        target = {
            "device_id": root.device,
            "recovery_id": scenario.recovery,
            "credential": {"device_id": root.device, "epoch": "epoch", "generation": 2},
            "process_boot": "b" * 32,
            "connection": {"boot_epoch": "gateway-boot", "counter": 4},
            "blocked": True,
            "covered": False,
        }
        covered = {**target, "blocked": False, "covered": True}
        reconnected = {
            **covered,
            "connection": {"boot_epoch": "gateway-boot", "counter": 5},
        }
        scenario.routing_target = mock.Mock(side_effect=[target, covered, reconnected])
        h.admin.side_effect = [
            {
                "disposition": "drained",
                "committed": True,
                "connection_status": "joined",
            },
            {
                "disposition": "already_satisfied",
                "committed": False,
                "connection_status": "unchanged",
                "target": reconnected,
            },
        ]

        def until(check, *_args):
            for _ in range(3):
                value = check()
                if value:
                    return value
            self.fail("coverage did not observe the new fenced generation")

        h.until.side_effect = until
        scenario.establish_routing_coverage(root, 2, (0, 0))
        first, repeated = h.admin.call_args_list
        self.assertEqual(first, repeated)
        confirmation = first.args[1]
        self.assertEqual(confirmation["expected_connection"], target["connection"])
        self.assertEqual(confirmation["expected_process_boot"], target["process_boot"])
        self.assertTrue(confirmation["prior_cli_joins_confirmed"])
        self.assertEqual(scenario.routing_target.call_count, 3)

    def test_routing_attestation_requires_actual_prior_connector_joins(self):
        h = mock.Mock()
        scenario = e2e_recovery.RecoveryScenario(h)
        for joins in ((), (0, 3)):
            with self.subTest(joins=joins), self.assertRaises(ProofFailure):
                scenario.establish_routing_coverage(fixture_root(), 2, joins)
        h.admin.assert_not_called()

    def test_complete_fleet_is_covered_before_project_refresh(self):
        roots = [fixture_root(), fixture_root()]
        roots[1].device = "device-two"
        for index, root in enumerate(roots):
            root.base = Path(f"/owned/root-{index}")
            root.connector_config_path = root.base / "connector.json"
            root.env = {}
        started, covered = [], []
        h = mock.Mock()
        h.roots = roots
        h.connectors = [mock.Mock(), mock.Mock()]
        h.stop_process.return_value = 0
        h.start_connector.side_effect = started.append
        h.until.side_effect = lambda check, *_args: check()
        scenario = e2e_recovery.RecoveryScenario(h)
        scenario.establish_routing_coverage = mock.Mock(
            side_effect=lambda root, *_args: covered.append(root)
        )

        def refresh(root):
            self.assertEqual(started, roots)
            self.assertEqual(covered, roots)
            return True

        scenario.connected = refresh
        scenario.replace_credentials("recovery_only", 2)

    def test_missing_registry_spec_uses_exact_native_receipt_before_cancel(self):
        root = fixture_root()
        root.gate = Path("/owned/gate")
        root.state = Path("/owned/state")
        root.waiters = mock.Mock()
        root.waiters.glob.return_value = ["fixture-fifo"]
        root.nonce = "nonce"
        root.tasks = ["task-one"]
        origin = {"operation_id": "original-operation"}
        receipt = {
            "task_id": "task-one",
            "origin": origin,
            "root_token": root.context["root_token"],
            "project_token": root.context["project_token"],
            "spec_sha256": "a" * 64,
        }
        root.command = mock.Mock(
            return_value={"connector": {"resolution": "existing", "receipt": receipt}}
        )
        h = mock.Mock()
        gate = mock.Mock()
        root.acquire_fixture_gate = mock.Mock(return_value=gate)
        root.release_fixture_gate = mock.Mock()
        root.fixture_execution_snapshot = mock.Mock(return_value="before")
        live = FixtureLeaseObservation("task-one", 123, Path("/owned/fifo"), (1, 2))
        lease = mock.Mock()
        root.fixture_execution_lease = mock.Mock(
            return_value=nullcontext((live, lease))
        )
        h.acceptance.leases.LockedReleaseGate.acquire.side_effect = FileExistsError(
            "baseline fixture gate inode is retained"
        )
        h.roots = [root]
        h.prepare.return_value = {
            "operation_id": "original-operation",
            "task_id": "task-one",
        }
        h.operations = {"original-operation": {"cancellation_id": "stable-cancel"}}
        scenario = e2e_recovery.RecoveryScenario(h)
        scenario.restart_while_active = mock.Mock()
        view = {"origin": origin, "key": e2e_recovery.task_key(root, "task-one")}
        scenario.assert_reserved = mock.Mock(return_value=view)
        scenario.native_closure = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            origin_file = Path(directory) / "origin.json"
            origin_file.write_text(json.dumps(origin))
            h.input_file.return_value = origin_file
            with mock.patch.object(e2e_recovery, "require_requested_closure"):
                self.assertEqual(scenario.reserved_attributed(), view)
        calls = root.command.call_args_list
        self.assertEqual(
            calls[0].args[0],
            ["resolve", "task-one", *e2e_recovery.native_guards(root, origin_file)],
        )
        cancellation = calls[1].args[0]
        self.assertEqual(
            cancellation[cancellation.index("--expected-spec-sha256") + 1], "a" * 64
        )
        self.assertEqual(cancellation[cancellation.index("--id") + 1], "stable-cancel")
        root.acquire_fixture_gate.assert_called_once_with()
        root.release_fixture_gate.assert_called_once_with()
        root.fixture_execution_lease.assert_called_once_with("before", "task-one")
        scenario.restart_while_active.assert_called_once_with(
            root, h.prepare.return_value, "before", live, lease
        )
        h.acceptance.leases.LockedReleaseGate.acquire.assert_not_called()
        h.stop_process.assert_called_once_with(h.gateway)

    def test_native_spec_rejects_foreign_or_missing_receipts(self):
        root = fixture_root()
        origin = {"operation_id": "original-operation"}
        receipt = {
            "task_id": "task-one",
            "origin": origin,
            "root_token": root.context["root_token"],
            "project_token": root.context["project_token"],
            "spec_sha256": "a" * 64,
        }
        scenario = e2e_recovery.RecoveryScenario(SimpleNamespace())
        cases = [
            {"task_id": "other-task"},
            {"origin": {"operation_id": "other"}},
            {"root_token": "other-root"},
            {"project_token": "other-project"},
            {"spec_sha256": ""},
            {"spec_sha256": "A" * 64},
        ]
        with tempfile.TemporaryDirectory() as directory:
            origin_file = Path(directory) / "origin.json"
            origin_file.write_text(json.dumps(origin))
            for changed in cases:
                root.command = mock.Mock(
                    return_value={
                        "connector": {
                            "resolution": "existing",
                            "receipt": {**receipt, **changed},
                        }
                    }
                )
                with self.subTest(changed=changed), self.assertRaises(ProofFailure):
                    scenario.native_spec(root, "task-one", origin_file)
                self.assertEqual(root.command.call_args.args[0][0], "resolve")
            root.command = mock.Mock(
                return_value={
                    "connector": {"resolution": "existing", "receipt": receipt}
                }
            )
            with self.assertRaises(ProofFailure):
                scenario.native_spec(root, "task-one", origin_file, "b" * 64)
            for response in (
                {},
                {"connector": []},
                {"connector": {"resolution": "absent"}},
                {"connector": {"receipt": []}},
            ):
                root.command.return_value = response
                with self.subTest(response=response), self.assertRaises(ProofFailure):
                    scenario.native_spec(root, "task-one", origin_file)

    def test_post_recovery_refreshes_and_observes_each_selected_root(self):
        roots = [fixture_root(), fixture_root()]
        roots[1].device = "device-two"
        calls = []

        def admin(action, value):
            calls.append((action, value))

        def mcp(tool, value):
            calls.append((tool, value))
            return {**value, "online": True, "delegate_ready": True}

        def until(check, seconds, _description):
            self.assertEqual(seconds, 10)
            self.assertTrue(check())

        harness = SimpleNamespace(roots=roots, admin=admin, mcp=mcp, until=until)
        e2e_recovery.RecoveryScenario(harness).verify_execution_readiness()
        self.assertEqual(
            calls,
            [
                ("refresh-project", e2e_recovery.root_input(roots[0])),
                (
                    "get_capabilities",
                    {"device_id": "device-one", "project_alias": "project-one"},
                ),
                ("refresh-project", e2e_recovery.root_input(roots[1])),
                (
                    "get_capabilities",
                    {"device_id": "device-two", "project_alias": "project-one"},
                ),
            ],
        )

    def test_post_recovery_not_ready_stays_pending_and_malformed_fails(self):
        root = fixture_root()

        def bounded_pending(check, seconds, _description):
            self.assertEqual(seconds, 10)
            self.assertFalse(check())
            raise ProofFailure("bounded readiness observation expired")

        for change in (
            {"delegate_ready": False},
            {"delegate_ready": "true"},
            {"device_id": "other-device"},
        ):
            value = {
                "device_id": root.device,
                "project_alias": root.alias,
                "online": True,
                "delegate_ready": True,
                **change,
            }
            harness = SimpleNamespace(
                roots=[root],
                admin=mock.Mock(),
                mcp=mock.Mock(return_value=value),
                until=bounded_pending,
            )
            with self.subTest(change=change), self.assertRaises(ProofFailure):
                e2e_recovery.RecoveryScenario(harness).verify_execution_readiness()
            harness.admin.assert_called_once_with(
                "refresh-project", e2e_recovery.root_input(root)
            )
            harness.mcp.assert_called_once_with(
                "get_capabilities",
                {"device_id": root.device, "project_alias": root.alias},
            )

    def test_denial_requires_closed_uncommitted_conflict(self):
        for code in ("pending", "conflict"):
            e2e_recovery.require_denial(409, {"code": code, "committed": False})
        for status, value in (
            (200, {"code": "pending", "committed": False}),
            (500, {"code": "internal_error", "committed": False}),
            (409, {"code": "pending", "committed": True}),
            (409, {"code": "pending", "committed": False, "secret": "unexpected"}),
        ):
            with (
                self.subTest(status=status, value=value),
                self.assertRaises(ProofFailure),
            ):
                e2e_recovery.require_denial(status, value)

    def test_startup_retries_only_named_transient_failures(self):
        harness = SimpleNamespace(admin_socket=Path("/fixture/admin.sock"), summary={})
        scenario = e2e_recovery.RecoveryScenario(harness)
        for status, code in (
            (503, "device_offline"),
            (503, "device_not_ready"),
            (409, "pending"),
        ):
            with mock.patch.object(
                e2e_recovery,
                "private_request",
                return_value=(status, {"code": code, "committed": False}),
            ):
                self.assertFalse(scenario.connected(fixture_root()))
        self.assertEqual(len(harness.summary["recovery_connection_pending"]), 3)
        with (
            mock.patch.object(
                e2e_recovery,
                "private_request",
                return_value=(500, {"code": "internal_error", "committed": False}),
            ),
            self.assertRaises(ProofFailure),
        ):
            scenario.connected(fixture_root())

    def test_connected_requires_exact_context_receipt(self):
        root = fixture_root()
        route = e2e_recovery.root_input(root)
        reply = {
            "alias": root.alias,
            "context": {"root": route["root_guard"], "project": route["project_guard"]},
        }
        scenario = e2e_recovery.RecoveryScenario(SimpleNamespace(admin_socket="owned"))
        with mock.patch.object(
            e2e_recovery, "private_request", return_value=(200, reply)
        ):
            self.assertTrue(scenario.connected(root))
            reply["context"]["project"] = "other-project"
            with self.assertRaises(ProofFailure):
                scenario.connected(root)

    def test_reserved_import_checks_attribution_and_physical_task(self):
        root = fixture_root()
        reply = {
            "key": e2e_recovery.task_key(root, "task-one"),
            "attributed": False,
            "reserved": True,
        }
        harness = SimpleNamespace(admin=mock.Mock(return_value=reply))
        scenario = e2e_recovery.RecoveryScenario(harness)
        self.assertEqual(scenario.assert_reserved(root, "task-one", False), reply)
        with self.assertRaises(ProofFailure):
            scenario.assert_reserved(root, "task-one", True)
        reply["key"]["task_id"] = "other-task"
        with self.assertRaises(ProofFailure):
            scenario.assert_reserved(root, "task-one", False)

    def test_drain_requires_identity_bound_canonical_closure(self):
        root = fixture_root()
        origin = {"operation_id": "original"}
        reply = {
            "key": e2e_recovery.task_key(root, "task-one"),
            "origin": origin,
            "reserved": False,
            "observation": {
                "kind": "terminal",
                "closure": {"kind": "registered-native"},
            },
        }
        scenario = e2e_recovery.RecoveryScenario(
            SimpleNamespace(admin=mock.Mock(return_value=reply))
        )
        scenario.drain(root, "task-one", origin)
        reply["observation"]["closure"] = None
        with self.assertRaises(ProofFailure):
            scenario.drain(root, "task-one", origin)
        reply["observation"]["closure"] = {"kind": "registered-native"}
        with self.assertRaises(ProofFailure):
            scenario.drain(root, "task-one", {"operation_id": "other"})

    def test_wrong_attempt_baseline_cannot_start_recovery_work(self):
        root = SimpleNamespace(invocations=mock.Mock(return_value=3))
        empty = SimpleNamespace(invocations=mock.Mock(return_value=0))
        harness = SimpleNamespace(roots=[root, empty])
        scenario = e2e_recovery.RecoveryScenario(harness)
        with mock.patch.object(scenario, "reserved_attributed") as prepare:
            with self.assertRaises(ProofFailure):
                scenario.run()
            prepare.assert_not_called()

    def test_native_closure_requires_the_exact_frozen_receipt(self):
        root = fixture_root()
        origin = {"operation_id": "original-operation"}
        receipt = {
            "task_id": "task-one",
            "origin": origin,
            "root_token": root.context["root_token"],
            "project_token": root.context["project_token"],
        }
        response = {
            "connector": {
                "receipt": receipt,
                "execution_closure": {"kind": "registered-native"},
            }
        }
        root.command = mock.Mock(return_value=response)
        harness = SimpleNamespace(until=lambda check, *_args: check())
        scenario = e2e_recovery.RecoveryScenario(harness)
        with tempfile.TemporaryDirectory() as directory:
            origin_file = Path(directory) / "origin.json"
            origin_file.write_text(json.dumps(origin))
            self.assertEqual(
                scenario.native_closure(root, "task-one", origin_file),
                response["connector"],
            )
            receipt["task_id"] = "other-task"
            with self.assertRaises(ProofFailure):
                scenario.native_closure(root, "task-one", origin_file)

    def test_private_response_limit_closes_owned_socket(self):
        response = mock.Mock(status=200)
        response.read.return_value = b"x" * (e2e_recovery.MAX_RESPONSE + 1)
        connection = mock.Mock()
        connection.getresponse.return_value = response
        owned = mock.Mock()
        with (
            mock.patch.object(
                e2e_recovery.http.client, "HTTPConnection", return_value=connection
            ),
            mock.patch.object(e2e_recovery.socket, "socket", return_value=owned),
        ):
            with self.assertRaises(ProofFailure):
                e2e_recovery.private_request(
                    "/fixture/admin.sock", "/v1/recovery/finish", {}
                )
        response.close.assert_called_once()
        connection.close.assert_called_once()
        owned.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
