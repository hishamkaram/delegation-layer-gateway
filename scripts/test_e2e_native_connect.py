"""Controller contract regressions; no native or provider process is launched."""

import argparse
import base64
import contextlib
import copy
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import e2e_local
from e2e_native_connect import NativeConnectHarness, configure_arguments


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


class CompactPreparationControllerTests(unittest.TestCase):
    def controller(self, compact):
        harness = object.__new__(NativeConnectHarness)
        harness.args = SimpleNamespace(compact_routes=compact)
        harness.operations = {}
        harness.responses = []
        harness.summary = {"stages": []}
        harness.assert_no_project_pins = mock.Mock()
        harness.mcp = mock.Mock(
            return_value={
                "operation_id": "owned-operation",
                "task_id": "a" * 32,
                "expires_at": "2026-11-21T20:07:30.394671128Z",
            }
        )
        harness.until = lambda check, _seconds, _description: check()
        harness.prepare_selected = lambda request: harness.mcp(
            "prepare_dispatch", request
        )
        root = SimpleNamespace(
            device="owned-device",
            alias="legacy-project",
            tasks=[],
            selection={"scope_id": "public-workspace", "relative_path": "nested"},
            approval={"id": "local-profile-workspace"},
        )
        return harness, root

    def test_compact_preparation_uses_public_scope_and_native_options(self):
        harness, root = self.controller(True)
        harness.prepare(root, "literal fixture brief")
        tool, request = harness.mcp.call_args_list[0].args
        self.assertEqual(tool, "prepare_dispatch")
        self.assertEqual(
            request.get("selection"),
            {"scope_id": "public-workspace", "relative_path": "nested"},
        )
        self.assertEqual(
            request.get("native_options"),
            {
                "provider": "pi:json",
                "permission": "read-only",
                "budget": "30s",
                "model": "openai/gpt-4.1",
            },
        )
        self.assertNotIn("project_alias", request)
        self.assertNotIn("budget_seconds", request)
        self.assertEqual(len(request["request_id"]), 32)
        self.assertEqual(harness.mcp.call_args_list[1], harness.mcp.call_args_list[0])
        self.assertEqual(root.tasks, ["a" * 32])
        self.assertEqual(len(harness.operations), 1)

    def test_legacy_default_keeps_original_preparation_contract(self):
        harness, root = self.controller(False)
        harness.prepare(root, "literal fixture brief")
        harness.mcp.assert_called_once_with(
            "prepare_dispatch",
            {
                "device_id": "owned-device",
                "project_alias": "legacy-project",
                "brief": "literal fixture brief",
                "provider": "pi:json",
                "permission": "read-only",
                "budget_seconds": 30,
                "model": "openai/gpt-4.1",
            },
        )

    def test_compact_replay_rejects_replacement_identity(self):
        harness, root = self.controller(True)
        harness.mcp.side_effect = [
            {
                "operation_id": "owned-operation",
                "task_id": "a" * 32,
                "expires_at": "2026-11-21T20:07:30.394671128Z",
            },
            {
                "operation_id": "replacement-operation",
                "task_id": "b" * 32,
                "expires_at": "2026-11-21T20:07:30.394671128Z",
            },
        ]
        with self.assertRaisesRegex(e2e_local.ProofFailure, "preparation replay"):
            harness.prepare(root, "literal fixture brief")
        self.assertEqual(root.tasks, ["a" * 32])
        self.assertEqual(set(harness.operations), {"owned-operation"})

    def test_preparation_replay_compares_exact_expiry_instant(self):
        for expiry, accepted in (
            ("2026-11-21T20:07:30.394671128Z", True),
            ("2026-11-21T20:07:30.394671129Z", False),
        ):
            with self.subTest(expiry=expiry):
                harness, root = self.controller(True)
                first = {
                    "operation_id": "owned-operation",
                    "task_id": "a" * 32,
                    "expires_at": "2026-11-21T21:07:30.394671128+01:00",
                }
                harness.mcp.side_effect = [first, {**first, "expires_at": expiry}]
                if accepted:
                    self.assertEqual(
                        harness.prepare(root, "literal fixture brief"), first
                    )
                else:
                    with self.assertRaisesRegex(
                        e2e_local.ProofFailure, "preparation replay"
                    ):
                        harness.prepare(root, "literal fixture brief")

    def test_flag_is_explicit_and_help_preserves_legacy_default(self):
        parser = argparse.ArgumentParser()
        configure_arguments(parser)
        self.assertFalse(parser.parse_args([]).compact_routes)
        self.assertTrue(parser.parse_args(["--compact-routes"]).compact_routes)
        self.assertIn("--compact-routes", parser.format_help())

    def test_pending_preparation_keeps_request_identity(self):
        harness, _root = self.controller(True)
        harness.pace_mcp = mock.Mock()
        harness.mcp_input = lambda tool, request: {"tool": tool, "arguments": request}
        prepared = {
            "operation_id": "owned-operation",
            "task_id": "a" * 32,
            "expires_at": "2026-11-21T20:07:30.394671128Z",
        }
        request = {
            "request_id": "b" * 32,
            "selection": {"scope_id": "public-scope", "relative_path": "nested"},
        }
        harness.helper = mock.Mock(
            side_effect=[
                {
                    "isError": True,
                    "structuredContent": {
                        "error": {"code": "pending", "request_id": "b" * 32}
                    },
                },
                {"structuredContent": {"data": prepared}},
            ]
        )
        self.assertIsNone(NativeConnectHarness.prepare_selected(harness, request))
        self.assertEqual(
            NativeConnectHarness.prepare_selected(harness, request), prepared
        )
        self.assertEqual(
            harness.helper.call_args_list[0], harness.helper.call_args_list[1]
        )
        harness.helper.return_value = {
            "isError": True,
            "structuredContent": {"error": {"code": "pending", "request_id": "c" * 32}},
        }
        harness.helper.side_effect = None
        with self.assertRaisesRegex(e2e_local.ProofFailure, "request identity"):
            NativeConnectHarness.prepare_selected(harness, request)

    def test_compact_no_pin_check_allows_existing_operations(self):
        harness, root = self.controller(True)
        root.command = mock.Mock(
            return_value={
                "upgrade": {
                    "phase": "preview",
                    "profile": {"from_version": 3, "to_version": 3, "pins": 0},
                }
            }
        )
        harness.mcp.side_effect = [{"project_budget": {"used": 0}}, {"projects": []}]
        NativeConnectHarness.assert_no_project_pins(harness, root)
        self.assertEqual(
            [call.args[0] for call in harness.mcp.call_args_list],
            ["list_workspaces", "list_projects"],
        )
        root.command.return_value["upgrade"]["profile"]["pins"] = 1
        harness.mcp.reset_mock()
        with self.assertRaisesRegex(e2e_local.ProofFailure, "local pin"):
            NativeConnectHarness.assert_no_project_pins(harness, root)
        harness.mcp.assert_not_called()


class FilesystemControllerFailureTests(unittest.TestCase):
    @contextlib.contextmanager
    def diagnostic_controller(self, *, encoded):
        with tempfile.TemporaryDirectory() as temporary:
            harness = object.__new__(NativeConnectHarness)
            harness.base = Path(temporary)
            harness.args = SimpleNamespace(gateway=Path("/fixture/gateway"))
            harness.summary = {
                "result": "started",
                "cleanup_confirmed": True,
                "cleanup_errors": [],
            }
            harness.filesystem_canary = (
                b"E2E_REQUESTED_FILE_0123456789abcdef0123456789abcdef"
            )
            # The fixture contract requests 17-byte ranges. This expected leak
            # is independent of the checker's range construction.
            fragment = harness.filesystem_canary[17:34]
            leak = base64.b64encode(fragment) if encoded else fragment
            self.assertNotIn(harness.filesystem_canary, leak)
            self.assertNotIn(base64.b64encode(harness.filesystem_canary), leak)
            output = harness.base / "gateway.stdout"
            output.write_bytes(b'{"data":"' + leak + b'"}\n')
            errors = harness.base / "gateway.stderr"
            errors.write_bytes(b"")
            harness.processes = SimpleNamespace(
                entries=[
                    SimpleNamespace(
                        argv=["/fixture/gateway", "serve"],
                        stdout_path=output,
                        stderr_path=errors,
                    )
                ]
            )
            harness.embedded_connector_invocations = []
            yield harness

    def test_middle_range_leak_fails_when_the_whole_canary_is_absent(self):
        for encoded in (False, True):
            with (
                self.subTest(encoded=encoded),
                self.diagnostic_controller(encoded=encoded) as harness,
            ):
                with self.assertRaisesRegex(e2e_local.ProofFailure, "canary escaped"):
                    harness.check_filesystem_diagnostics()

    def test_range_leak_after_join_fails_the_overall_run_and_still_cleans_temp(self):
        with self.diagnostic_controller(encoded=True) as harness:
            harness.interruptions = e2e_local.Interruptions()
            harness.start_network = mock.Mock()
            harness.start_connectors = mock.Mock()
            harness.task_scenarios = mock.Mock()
            harness.recovery_scenarios = mock.Mock()
            harness.filesystem_temp_roots = [object()]
            harness.acceptance = mock.Mock()
            with (
                mock.patch.object(
                    e2e_local.Harness, "_finish_owned", return_value=True
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(harness.run(), 1)
            self.assertEqual(harness.summary["result"], "failed")
            self.assertEqual(
                harness.summary["filesystem_diagnostic_failure"], "ProofFailure"
            )
            self.assertTrue(harness.summary["cleanup_confirmed"])
            harness.acceptance.directories.remove_owned_directory.assert_called_once()

    def test_fresh_profile_pin_check_rejects_a_pin_before_cached_inventory(self):
        harness = object.__new__(NativeConnectHarness)
        harness.mcp = mock.Mock()
        root = mock.Mock()
        root.command.return_value = {
            "upgrade": {
                "phase": "preview",
                "profile": {
                    "from_version": 3,
                    "to_version": 3,
                    "pins": 1,
                },
            }
        }
        with self.assertRaises(e2e_local.ProofFailure):
            harness.require_read_only_state(root)
        root.command.assert_called_once_with(["gateway", "upgrade", "--preview"])
        harness.mcp.assert_not_called()

    def test_repeated_directory_cursor_fails_with_finite_observations(self):
        harness = object.__new__(NativeConnectHarness)
        harness.mcp = mock.Mock(
            return_value={
                "list": {"entries": [{}], "eof": False, "next_cursor": "stuck"}
            }
        )
        with self.assertRaises(e2e_local.ProofFailure):
            harness.directory_pages({}, {b"one", b"two", b"three"})
        self.assertEqual(harness.mcp.call_count, 2)

    def test_empty_nonterminal_file_range_fails_without_retrying(self):
        harness = object.__new__(NativeConnectHarness)
        harness.mcp = mock.Mock(
            return_value={"read": {"offset": 0, "data_base64": "", "eof": False}}
        )
        with self.assertRaises(e2e_local.ProofFailure):
            harness.read_exact_file({}, b"expected bytes")
        self.assertEqual(harness.mcp.call_count, 1)

    def test_temp_cleanup_requires_inherited_join_and_reports_cleanup_failure(self):
        for joined, cleanup_fails, expected in (
            (False, False, False),
            (True, False, True),
            (True, True, False),
        ):
            with (
                self.subTest(joined=joined, cleanup_fails=cleanup_fails),
                tempfile.TemporaryDirectory() as temporary,
            ):
                harness = object.__new__(NativeConnectHarness)
                harness.base = Path(temporary)
                harness.summary = {"cleanup_errors": [], "cleanup_confirmed": joined}
                harness.filesystem_temp_roots = [object()]
                harness.acceptance = mock.Mock()
                harness.check_filesystem_diagnostics = mock.Mock()
                removal = harness.acceptance.directories.remove_owned_directory
                if cleanup_fails:
                    removal.side_effect = OSError("fixture removal failed")
                with mock.patch.object(
                    e2e_local.Harness, "_finish_owned", return_value=joined
                ) as inherited:
                    removal.side_effect = (
                        OSError("fixture removal failed")
                        if cleanup_fails
                        else lambda *_args: self.assertTrue(inherited.called)
                    )
                    self.assertEqual(harness._finish_owned(), expected)
                self.assertEqual(removal.call_count, int(joined))
                self.assertEqual(harness.summary["cleanup_confirmed"], expected)
                self.assertEqual(
                    harness.summary["filesystem_temp_cleanup_confirmed"], expected
                )
                if cleanup_fails:
                    self.assertEqual(
                        harness.summary["cleanup_errors"],
                        [{"stage": "filesystem_temp_cleanup", "kind": "OSError"}],
                    )


class NativeControllerOwnershipTests(unittest.TestCase):
    @contextlib.contextmanager
    def controller(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = object.__new__(NativeConnectHarness)
            harness.interruptions = e2e_local.Interruptions()
            harness.base = Path(temporary).resolve()
            harness.args = mock.Mock(
                compact_routes=False,
                gateway=Path("/fixture/gateway"),
                delegate=Path("/fixture/delegate"),
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
                self.assertEqual(
                    argv,
                    (
                        "/fixture/delegate",
                        "--root",
                        str(root.state),
                        "gateway",
                        "connect",
                        harness.public,
                        "--token-file",
                        str(harness.base / "token.json"),
                        "--foreground",
                        "--ca",
                        str(harness.material["ca_file"]),
                        "--json",
                    ),
                )
                harness.processes.entries.append(process)
                options["on_spawned"](process)
                return process

            harness.processes.start.side_effect = start
            harness.start_native_connector(root, harness.base / "token.json")
            self.assertEqual(harness.connectors, [process])
            self.assertIs(harness.connectors[0], harness.processes.entries[0])

    def test_owner_authority_uses_access_only_before_any_native_start(self):
        class StopBeforeNative(Exception):
            pass

        with self.controller() as (harness, _root):
            harness.gateway_config_path = harness.base / "gateway.json"
            harness.command = mock.Mock()
            with mock.patch(
                "e2e_native_connect.DelegateRoot", side_effect=StopBeforeNative
            ):
                with self.assertRaises(StopBeforeNative):
                    NativeConnectHarness.start_connectors(harness)
            harness.command.assert_called_once_with(
                harness.args.gateway,
                [
                    "users",
                    "allow",
                    "--config",
                    harness.gateway_config_path,
                    "--subject",
                    "local-e2e-subject",
                    "--max-devices",
                    "2",
                ],
            )
            harness.processes.start.assert_not_called()

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
