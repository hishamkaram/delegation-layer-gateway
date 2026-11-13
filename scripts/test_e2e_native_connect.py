"""Controller contract regressions; no native or provider process is launched."""

import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import e2e_local
from e2e_native_connect import NativeConnectHarness


class WorkspaceSelectionTests(unittest.TestCase):
    def test_selection_uses_public_workspace_id_not_native_profile_id(self):
        selected = {"workspace_id": "a" * 32, "alias": "work", "policy_revision": 1}
        other = {"workspace_id": "b" * 32, "alias": "other", "policy_revision": 1}
        harness = object.__new__(NativeConnectHarness)
        harness.mcp = mock.Mock(return_value={"workspaces": [other, selected]})
        self.assertEqual(harness.advertised_workspace("device", "a" * 32), selected)
        self.assertIsNone(harness.advertised_workspace("device", "c" * 32))
        harness.mcp.assert_called_with("list_workspaces", {"device_id": "device"})

    def test_empty_advertisement_does_not_invent_an_approval(self):
        harness = object.__new__(NativeConnectHarness)
        harness.mcp = mock.Mock(return_value={"workspaces": []})
        self.assertIsNone(harness.advertised_workspace("device", "a" * 32))


class NativeControllerOwnershipTests(unittest.TestCase):
    @contextlib.contextmanager
    def controller(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = object.__new__(NativeConnectHarness)
            harness.interruptions = e2e_local.Interruptions()
            harness.base = Path(temporary).resolve()
            harness.args = mock.Mock(
                gateway=Path("/fixture/gateway"), delegate=Path("/fixture/delegate")
            )
            harness.summary = {"result": "started"}
            harness.operations = {}
            harness.closed_operations = set()
            harness.connectors = []
            harness.embedded_connector_invocations = []
            harness.gateway = None
            harness.jwks = None
            harness.processes = mock.Mock(entries=[])
            harness.processes.pending.return_value = []
            harness.processes.finished_naturally.return_value = True
            harness.fixture_attempts = mock.Mock(
                return_value={
                    "attempted": 3,
                    "rejected_concurrent": 0,
                    "rejected_limit": 0,
                }
            )
            root = mock.Mock(
                state=harness.base / "state",
                workspace=harness.base / "workspace",
                env={},
                native_captures=None,
            )
            root.finish.return_value = {}
            harness.roots = [root]
            harness.public = "https://fixture.invalid/mcp"
            harness.material = {"ca_file": harness.base / "ca.pem"}
            harness.start_network = mock.Mock()
            harness.start_connectors = mock.Mock()
            harness.task_scenarios = mock.Mock()
            harness.recovery_scenarios = mock.Mock()
            yield harness, root

    def run_controller(self, harness):
        with contextlib.redirect_stdout(io.StringIO()):
            return harness.run()

    def test_late_fourth_attempt_fails_after_all_owned_joins(self):
        for final_count, exit_code in ((3, 0), (4, 1)):
            with (
                self.subTest(final_count=final_count),
                self.controller() as (
                    harness,
                    root,
                ),
            ):

                def closed():
                    harness.fixture_attempts.return_value["attempted"] = final_count
                    return {}

                root.finish.side_effect = closed
                self.assertEqual(self.run_controller(harness), exit_code)
                self.assertTrue(harness.summary["cleanup_confirmed"])
                self.assertEqual(
                    harness.summary["fixture_attempts"]["attempted"], final_count
                )

    def test_original_handle_is_joined_when_start_receipt_fails(self):
        with self.controller() as (harness, root):
            process = mock.Mock(pid=123)
            process.poll.return_value = {"exit_code": 0, "natural_wait": True}
            process.wait.return_value = 0

            def start(_name, argv, _cwd, **options):
                process.argv = list(argv)
                harness.processes.entries.append(process)
                if callback := options.get("on_spawned"):
                    callback(process)
                raise OSError("started.json write failed")

            harness.processes.start.side_effect = start
            harness.start_connectors.side_effect = lambda: (
                harness.start_native_connector(root, harness.base / "token.json")
            )
            self.assertEqual(self.run_controller(harness), 1)
            self.assertEqual(harness.connectors, [process])
            process.wait.assert_called_once_with(45, expected=None)
            root.finish.assert_called_once_with()
            self.assertTrue(harness.summary["cleanup_confirmed"])
            self.assertEqual(harness.summary["failure_kind"], "OSError")

    def test_successful_start_publishes_original_handle_once(self):
        with self.controller() as (harness, root):
            process = mock.Mock()

            def start(_name, argv, _cwd, **options):
                self.assertIsInstance(argv, tuple)
                self.assertEqual(harness.embedded_connector_invocations, [argv])
                harness.processes.entries.append(process)
                options["on_spawned"](process)
                return process

            harness.processes.start.side_effect = start
            harness.start_native_connector(root, harness.base / "token.json")
            self.assertEqual(harness.connectors, [process])
            self.assertIs(harness.connectors[0], harness.processes.entries[0])

    def test_callback_failure_retains_registry_owner_and_blocks_descendant_cleanup(
        self,
    ):
        class UnavailableHandoff(list):
            def append(self, _process):
                raise OSError("connector handoff unavailable")

        with self.controller() as (harness, root):
            harness.connectors = UnavailableHandoff()
            process = mock.Mock(pid=123)
            process.poll.return_value = None

            def start(_name, argv, _cwd, **options):
                process.argv = list(argv)
                harness.processes.entries.append(process)
                options["on_spawned"](process)

            harness.processes.start.side_effect = start
            harness.processes.finished_naturally.return_value = False
            harness.start_connectors.side_effect = lambda: (
                harness.start_native_connector(root, harness.base / "token.json")
            )
            self.assertEqual(self.run_controller(harness), 3)
            root.finish.assert_not_called()
            self.assertIs(harness.processes.entries[0], process)
            process.wait.assert_not_called()
            self.assertTrue(harness.base.exists())
            self.assertFalse(harness.summary["cleanup_confirmed"])

    def test_uncertain_embedded_start_blocks_descendant_cleanup(self):
        with self.controller() as (harness, root):

            def start(_name, argv, _cwd, **_options):
                harness.processes.pending.return_value = [
                    {"pid": None, "argv": list(argv)}
                ]
                raise OSError("Popen returned no original handle")

            harness.processes.start.side_effect = start
            harness.processes.finished_naturally.return_value = False
            harness.start_connectors.side_effect = lambda: (
                harness.start_native_connector(root, harness.base / "token.json")
            )
            self.assertEqual(self.run_controller(harness), 3)
            root.finish.assert_not_called()
            self.assertTrue(harness.base.exists())
            self.assertIn(
                {"stage": "native_connector_start_unconfirmed"},
                harness.summary["cleanup_errors"],
            )

    def test_missing_original_registry_owner_blocks_descendant_cleanup(self):
        with self.controller() as (harness, root):
            harness.processes.start.side_effect = OSError(
                "started child registration unavailable"
            )
            harness.start_connectors.side_effect = lambda: (
                harness.start_native_connector(root, harness.base / "token.json")
            )
            self.assertEqual(self.run_controller(harness), 3)
            self.assertEqual(harness.processes.entries, [])
            self.assertEqual(harness.processes.pending.return_value, [])
            root.finish.assert_not_called()
            self.assertTrue(harness.base.exists())
            self.assertFalse(harness.summary["cleanup_confirmed"])
            self.assertEqual(harness.summary["failure_kind"], "OSError")
            self.assertIn(
                {"stage": "native_connector_owner_unconfirmed"},
                harness.summary["cleanup_errors"],
            )

    def test_unhanded_registry_entry_requires_natural_success_before_root_cleanup(self):
        for result, exit_code, cleanup in (
            ({"exit_code": 0, "natural_wait": True}, 1, True),
            ({"exit_code": 2, "natural_wait": True}, 3, False),
            ({"exit_code": 0, "natural_wait": False}, 3, False),
            (None, 3, False),
        ):
            with self.subTest(result=result), self.controller() as (harness, root):
                process = mock.Mock(pid=123)
                process.poll.return_value = result

                def start(_name, argv, _cwd, **_options):
                    process.argv = list(argv)
                    harness.processes.entries.append(process)
                    raise OSError("higher-level handoff failed")

                harness.processes.start.side_effect = start
                harness.start_connectors.side_effect = lambda: (
                    harness.start_native_connector(root, harness.base / "token.json")
                )
                self.assertEqual(self.run_controller(harness), exit_code)
                self.assertEqual(root.finish.call_count, int(cleanup))
                self.assertEqual(harness.summary["cleanup_confirmed"], cleanup)
                process.process.send_signal.assert_not_called()
                if result is not None and result["exit_code"] != 0:
                    self.assertEqual(
                        harness.summary["process_exit_failures"],
                        [{"pid": 123, "exit_code": 2, "direct_wait_confirmed": True}],
                    )

    def test_retained_resolution_rechecks_the_entire_original_binding(self):
        original = {
            "device_id": "device",
            "request_id": "request",
            "project_alias": "request",
            "workspace": {"workspace_id": "workspace", "guard": "workspace-guard"},
            "context": {"root": "root-guard", "project": "project-guard"},
        }
        fields = (
            ("device_id",),
            ("request_id",),
            ("project_alias",),
            ("workspace", "workspace_id"),
            ("workspace", "guard"),
            ("context", "root"),
            ("context", "project"),
        )
        for field in (None, *fields):
            with self.subTest(field=field), self.controller() as (harness, root):
                harness.summary["stages"] = []
                root.resolved = copy.deepcopy(original)
                root.resolution = {"request_id": "request"}
                root.alias = "request"
                root.device = "device"
                root.approval = {"id": "workspace", "revision": 1}
                root.tasks = ["task"]
                root.command.return_value = {"workspace": {"enabled": False}}
                replay = copy.deepcopy(original)
                if field:
                    parent = replay
                    for key in field[:-1]:
                        parent = parent[key]
                    parent[field[-1]] = "changed"
                harness.mcp = mock.Mock(
                    side_effect=lambda tool, _request: (
                        replay if tool == "resolve_project" else {}
                    )
                )
                harness.prepare = mock.Mock(
                    return_value={"operation_id": "operation", "task_id": "task"}
                )
                harness.operations = {"operation": {"cancellation_id": "cancel"}}
                harness.restart_gateway = mock.Mock()
                harness.until = mock.Mock()
                harness.await_operation = mock.Mock()
                harness.check_canaries = mock.Mock()
                harness.acceptance = mock.Mock()
                harness.acceptance.supervisor.read_managed_closure.return_value = {
                    "tasks": {
                        "task": {
                            "termination": {"cause": "requested", "scope_empty": True},
                            "worker_wait": {"observed_at": "2026-11-13T00:00:00Z"},
                            "intent": {"deadline": "2026-11-13T00:00:30Z"},
                        }
                    }
                }
                if field:
                    with self.assertRaisesRegex(
                        e2e_local.ProofFailure, "retained immutable resolution"
                    ):
                        NativeConnectHarness.recovery_scenarios(harness)
                    harness.await_operation.assert_not_called()
                else:
                    NativeConnectHarness.recovery_scenarios(harness)
                    root.release_fixture_gate.assert_called_once_with()
                    harness.check_canaries.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
