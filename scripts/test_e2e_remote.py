"""Controller contract tests. Actors are doubles except finite Native-owned Python."""

from contextlib import nullcontext
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import e2e_local as local
import e2e_remote as remote
from e2e_remote_channel import PeerChannel


def target(alias="mac-a"):
    return remote.Target.parse(
        {
            "ssh_alias": alias,
            "expected_home": "/Users/fixture",
            "expected_uid": 501,
            "pueue": "/opt/tools/pueue",
            "pueued": "/opt/tools/pueued",
        }
    )


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.candidates = self.base / "candidates"
        self.candidates.mkdir(mode=0o700)
        files = {}
        for role in ("gateway", "delegate", "delegate-run"):
            path = self.candidates / role
            data = (role + " candidate").encode()
            path.write_bytes(data)
            path.chmod(0o700)
            files[role] = {
                "path": str(path),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "owned_build": True,
            }
        self.receipt = self.base / "build.json"
        self.receipt.write_text(
            json.dumps(
                {
                    "platform": "darwin/arm64",
                    "owned_candidate_root": str(self.candidates),
                    "results": [{"actual_wait": True, "exit_code": 0}] * 3,
                    "files": files,
                }
            )
        )
        self.value = {
            "schema_version": 1,
            "gateway": str(self.candidates / "gateway"),
            "fixture_tool": str(self.candidates / "delegate"),
            "delegate_repository": str(self.base),
            "listen_ip": "192.0.2.10",
            "candidate_directory": str(self.candidates),
            "build_receipt": str(self.receipt),
            "work_parent": str(self.base),
            "peers": [
                dataclasses.asdict(target()),
                dataclasses.asdict(target("mac-b")),
            ],
        }

    def test_exact_config_and_candidate_contents(self):
        config = remote.Config.parse(self.value)
        files = remote.candidate_files(config)
        self.assertEqual(
            [(item.path, item.data, item.executable) for item in files],
            [
                ("bin/gateway", b"gateway candidate", True),
                ("bin/delegate", b"delegate candidate", True),
                ("bin/delegate-run", b"delegate-run candidate", True),
            ],
        )
        self.assertEqual(config.peers[1].ssh_alias, "mac-b")
        harness = SimpleNamespace(summary={"connector_processes": 2})
        with patch.object(
            remote, "installed_ssh", return_value=self.candidates / "gateway"
        ):
            with patch.object(remote, "RemoteHarness", return_value=harness) as factory:
                controller = remote.Controller(config, local.Interruptions())
        self.assertFalse(factory.call_args.args[0].capture_native)
        self.assertEqual(controller.targets, tuple(enumerate(config.peers)))
        self.assertEqual(
            harness.summary["category"], "physical two-Mac zero-cost fixture"
        )
        self.assertEqual(harness.summary["fixture_task_limit"], 4)
        self.assertNotIn("connector_processes", harness.summary)
        self.assertEqual(harness.summary["expected_connector_targets"], 2)
        self.assertEqual(harness.summary["physical_device_acceptance"], "unverified")

    def test_diagnostic_target_selection_is_explicit_and_precedes_resource_creation(
        self,
    ):
        config = remote.Config.parse(self.value)
        self.assertEqual(
            remote.target_roster(config, None), tuple(enumerate(config.peers))
        )
        self.assertEqual(remote.target_roster(config, "mac-b"), ((1, config.peers[1]),))
        with (
            patch.object(remote, "installed_ssh") as ssh,
            patch.object(remote, "RemoteHarness") as harness,
        ):
            for invalid in ("missing", "mac-b ", ""):
                with (
                    self.subTest(invalid=invalid),
                    self.assertRaises(local.ProofFailure),
                ):
                    remote.Controller(config, local.Interruptions(), invalid)
            ssh.assert_not_called()
            harness.assert_not_called()
        path = self.base / "configuration.json"
        path.write_text(json.dumps(self.value))
        with (
            patch.object(remote, "Controller") as constructor,
            patch.object(remote.signal, "signal"),
            patch("sys.stdout", io.StringIO()),
        ):
            self.assertEqual(
                remote.main(
                    [
                        "--run-remote-fixtures",
                        "--config",
                        str(path),
                        "--diagnose-native-target",
                        "missing",
                    ]
                ),
                1,
            )
            constructor.assert_not_called()
        defaults = remote.arguments(["--run-remote-fixtures", "--config", str(path)])
        self.assertIsNone(defaults.diagnose_native_target)
        selected = remote.arguments(
            [
                "--run-remote-fixtures",
                "--config",
                str(path),
                "--diagnose-native-target",
                "mac-b",
            ]
        )
        self.assertEqual(selected.diagnose_native_target, "mac-b")

    def test_unknown_config_same_target_and_public_candidate_refused(self):
        for change in (
            {"unexpected": 1},
            {"peers": [self.value["peers"][0]] * 2},
            {"listen_ip": "127.0.0.1"},
        ):
            with self.subTest(change=change), self.assertRaises(local.ProofFailure):
                remote.Config.parse({**self.value, **change})
        self.candidates.chmod(0o755)
        with self.assertRaisesRegex(local.ProofFailure, "private"):
            remote.Config.parse(self.value)

    def test_symlink_rejected_before_any_candidate_hash(self):
        config = remote.Config.parse(self.value)
        path = self.candidates / "delegate-run"
        path.unlink()
        path.symlink_to(self.candidates / "delegate")
        with patch.object(
            remote.hashlib,
            "sha256",
            side_effect=AssertionError("hash before validation"),
        ):
            with self.assertRaisesRegex(local.ProofFailure, "symlink"):
                remote.candidate_files(config)

    def test_build_without_exact_wait_refused_before_hash(self):
        config = remote.Config.parse(self.value)
        receipt = json.loads(self.receipt.read_text())
        receipt["results"][0]["actual_wait"] = False
        self.receipt.write_text(json.dumps(receipt))
        with patch.object(
            remote.hashlib,
            "sha256",
            side_effect=AssertionError("hash before validation"),
        ):
            with self.assertRaisesRegex(local.ProofFailure, "Wait"):
                remote.candidate_files(config)

    def test_target_shell_injection_and_noncanonical_paths_rejected(self):
        valid = dataclasses.asdict(target())
        for alias in ("-option", "a b", "a;id", "$(id)", "a\n", "a@host"):
            with self.subTest(alias=alias), self.assertRaises(local.ProofFailure):
                remote.Target.parse({**valid, "ssh_alias": alias})
        for home in ("/Users/../fixture", "/Users//fixture", "/Users/fixture/"):
            with self.subTest(home=home), self.assertRaises(local.ProofFailure):
                remote.Target.parse({**valid, "expected_home": home})

    def test_ssh_shell_program_static_and_alias_after_separator(self):
        first = remote.ssh_argv(Path(sys.executable).resolve(), target())
        second = remote.ssh_argv(Path(sys.executable).resolve(), target("192.0.2.11"))
        self.assertEqual(first[:-2], second[:-2])
        self.assertEqual(first[-1], second[-1])
        self.assertEqual(first[-3], "--")
        self.assertEqual(first[-2], "mac-a")
        self.assertIn("-oStrictHostKeyChecking=yes", first)
        self.assertIn("-oClearAllForwardings=yes", first)
        self.assertNotIn(target().expected_home, first[-1])

    def test_installed_ssh_resolved_once_without_reading_binary_contents(self):
        selected = self.candidates / "gateway"
        alias = self.base / "ssh"
        alias.symlink_to(selected)
        with patch.object(remote.shutil, "which", return_value=str(alias)) as lookup:
            with patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("installed executable read"),
            ):
                executable = remote.installed_ssh()
                argv = remote.ssh_argv(executable, target())
        lookup.assert_called_once_with("ssh")
        self.assertEqual(executable, selected)
        self.assertEqual(argv[0], str(selected))
        with patch.object(remote.shutil, "which", return_value=None):
            with self.assertRaisesRegex(local.ProofFailure, "unavailable"):
                remote.installed_ssh()
        with self.assertRaisesRegex(local.ProofFailure, "absolute"):
            remote.ssh_argv(Path("ssh"), target())

    def test_explicit_launch_flag_required(self):
        with patch("sys.stderr"), self.assertRaises(SystemExit):
            remote.arguments(["--config", "/tmp/unused"])


class DiagnosticDriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        ca = self.base / "ca.pem"
        ca.write_text("fixture public CA standin")
        self.calls = []
        self.manifests = []
        self.refresh_fails = False
        self.ssh_exit = 0
        self.attempts = 0
        self.config = SimpleNamespace(
            gateway=self.base / "gateway",
            fixture_tool=self.base / "fixture",
            delegate_repository=self.base / "native",
            candidate_directory=self.base / "candidate",
            work_parent=self.base,
            listen_ip="192.0.2.10",
            peers=(target(), target("mac-b")),
        )
        self.h = SimpleNamespace(
            base=self.base,
            summary={"stages": [], "result": "started"},
            processes=SimpleNamespace(finished_naturally=lambda: True),
            acceptance=SimpleNamespace(processes=object()),
            roots=[],
            operations={},
            closed_operations=set(),
            gateway=None,
            jwks=None,
            material={"ca_file": str(ca), "device_ca": {"certificate": str(ca)}},
            gateway_id="gateway",
            public="https://192.0.2.10:1234",
            device_url="wss://192.0.2.10:1235/device",
            principal="principal",
            ownership=SimpleNamespace(
                release=lambda: self.calls.append(("release_owner",))
            ),
        )
        self.h.admin = self.admin
        self.h.start_network = lambda **kwargs: self.calls.append(("network", kwargs))
        self.h.capability_online = lambda device, alias: (
            self.calls.append(("capabilities", device, alias)) or True
        )
        self.h.until = lambda check, *_args: check()
        self.h.mcp = unittest.mock.Mock(
            side_effect=AssertionError("diagnostic task MCP forbidden")
        )
        self.h.grant_root = unittest.mock.Mock(
            side_effect=AssertionError("diagnostic task grant forbidden")
        )

    def admin(self, action, value, output=None):
        self.calls.append(("admin", action, value))
        if action == "issue-enrollment-token":
            return {
                "token": "private enrollment standin",
                "device_id": value["device_id"],
            }
        if action == "refresh-project":
            if self.refresh_fails:
                raise local.ProofFailure("fresh inspection failed")
            return {
                "alias": value["project_alias"],
                "context": {
                    "root": value["root_guard"],
                    "project": value["project_guard"],
                },
            }
        if action not in ("register-device", "register-project", "put-grant"):
            raise AssertionError(
                "diagnostic origin/task operation forbidden: " + action
            )
        return {}

    def harness(self, args, interruptions):
        self.h.args = args
        self.h.interruptions = interruptions
        self.h.pump_peers = lambda: None
        return self.h

    def channel(self, _native, argv):
        owner = self

        class Link:
            failure = None
            process = SimpleNamespace(poll=lambda: None)
            capture = SimpleNamespace(close=lambda: None)

            def __init__(self):
                self.argv = argv
                self.base = None

            def send_json(self, value, **_kwargs):
                owner.calls.append(("peer", value["operation"]))

            def expect(self, event, **_kwargs):
                return {
                    "event": event,
                    "base": self.base,
                    "cleanup_confirmed": True,
                    "attempts": {
                        "attempted": owner.attempts,
                        "rejected_concurrent": 0,
                        "rejected_limit": 0,
                    },
                }

            def close_input(self):
                owner.calls.append(("eof",))

            def join(self, **_kwargs):
                owner.calls.append(("ssh_wait",))
                return {"exit_code": owner.ssh_exit, "natural_wait": True}

        return Link()

    def bootstrap(self, root, _h, _source, _files, manifest, _pump):
        self.manifests.append(manifest)
        root.channel.base = root.base
        root.context = {
            "root_token": "private-root",
            "project_token": "private-project",
        }
        root.workspace = root.base + "/d/project-canary"
        root.initialized = True

    def patches(self):
        from contextlib import ExitStack

        stack = ExitStack()
        stack.enter_context(
            patch.object(remote, "RemoteHarness", side_effect=self.harness)
        )
        stack.enter_context(
            patch.object(
                remote, "installed_ssh", return_value=Path(sys.executable).resolve()
            )
        )
        stack.enter_context(
            patch.object(remote, "freeze_sources", return_value=(b"source", ()))
        )
        stack.enter_context(
            patch.object(remote, "PeerChannel", side_effect=self.channel)
        )
        stack.enter_context(
            patch.object(remote, "bootstrap_peer", side_effect=self.bootstrap)
        )
        stack.enter_context(
            patch.object(
                remote,
                "fixture_scenarios",
                side_effect=AssertionError("diagnostic task scenarios forbidden"),
            )
        )
        return stack

    def test_selected_capture_path_has_one_fresh_refresh_and_no_task_or_origin_mutation(
        self,
    ):
        with self.patches():
            controller = remote.Controller(self.config, local.Interruptions(), "mac-b")
            controller.run()
            self.assertEqual(self.h.summary["result"], "diagnostic_rpc_completed")
            self.assertNotIn("fixture_tasks_executed", self.h.summary)
            self.assertTrue(controller.finish())
        self.assertEqual(
            [root.target.ssh_alias for root in controller.roots], ["mac-b"]
        )
        self.assertEqual(controller.roots[0].device, "fixture-device-2")
        self.assertTrue(self.h.args.capture_native)
        self.assertTrue(self.manifests[0]["capture_native"])
        self.assertEqual(self.h.summary["expected_connector_targets"], 1)
        self.assertEqual(self.h.summary["fixture_task_limit"], 0)
        self.assertEqual(self.h.summary["max_active_fixture_tasks"], 0)
        self.assertEqual(self.h.summary["fixture_tasks_executed"], 0)
        self.assertEqual(self.h.summary["result"], "diagnostic_completed")
        for key in (
            "physical_device_acceptance",
            "real_provider_acceptance",
            "cloud_client_acceptance",
        ):
            self.assertEqual(self.h.summary[key], "unverified")
        admin = [row for row in self.calls if row[0] == "admin"]
        self.assertEqual(
            [row[1] for row in admin],
            [
                "register-device",
                "register-project",
                "put-grant",
                "issue-enrollment-token",
                "refresh-project",
            ],
        )
        self.assertEqual(admin[-1][2], admin[1][2])
        self.assertEqual(
            admin[2][2],
            {
                "principal_id": "principal",
                "device_id": "fixture-device-2",
                "project_alias": "fixture-project",
                "scopes": ["inventory:read"],
                "providers": ["pi:json"],
                "permissions": ["read-only"],
                "max_budget_seconds": 30,
            },
        )
        self.assertEqual(
            [row[1] for row in self.calls if row[0] == "peer"],
            ["enroll", "start_connector", "shutdown"],
        )
        self.assertEqual(self.calls.count(("ssh_wait",)), 1)
        self.assertEqual(self.h.operations, {})
        self.h.mcp.assert_not_called()
        self.h.grant_root.assert_not_called()

    def test_public_diagnostic_result_requires_rpc_success_and_cleanup(self):
        for failure in ("none", "rpc", "ssh", "attempt"):
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as directory:
                    self.h.base = Path(directory)
                    self.h.summary = {"stages": [], "result": "started"}
                    self.h.roots = []
                    self.refresh_fails = failure == "rpc"
                    self.ssh_exit = 255 if failure == "ssh" else 0
                    self.attempts = 1 if failure == "attempt" else 0
                    config_path = Path(directory) / "configuration.json"
                    config_path.write_text("{}")
                    public = io.StringIO()
                    with (
                        self.patches(),
                        patch.object(remote.Config, "parse", return_value=self.config),
                        patch.object(remote.signal, "signal"),
                        patch("sys.stdout", public),
                    ):
                        code = remote.main(
                            [
                                "--run-remote-fixtures",
                                "--config",
                                str(config_path),
                                "--diagnose-native-target",
                                "mac-b",
                            ]
                        )
                    self.assertEqual(code, 0 if failure == "none" else 1)
                    report = json.loads(public.getvalue())
                    self.assertEqual(report["category"], "diagnostic_native_capture")
                    self.assertEqual(
                        report["result"],
                        "diagnostic_completed" if failure == "none" else "failed",
                    )
                    self.assertEqual(
                        self.h.summary["physical_device_acceptance"], "unverified"
                    )


class FailureEvidenceTests(unittest.TestCase):
    def test_private_failure_trace_contains_only_bounded_locations_without_secret_message(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            config = base / "config.json"
            config.write_text("{}")
            private_secret = "PRIVATE_ERROR_VALUE_never_publish"
            summary = {"category": "physical two-Mac zero-cost fixture"}

            class FailedController:
                h = SimpleNamespace(summary=summary)

                def run(self):
                    raise local.ProofFailure(private_secret)

                def finish(self):
                    remote.durable_record(base / "summary.json", summary)
                    return True

            public = io.StringIO()
            with patch.object(
                remote,
                "arguments",
                return_value=SimpleNamespace(
                    config=config, diagnose_native_target=None
                ),
            ):
                with patch.object(
                    remote.Config,
                    "parse",
                    return_value=SimpleNamespace(peers=(target(), target("mac-b"))),
                ):
                    with patch.object(
                        remote, "Controller", return_value=FailedController()
                    ):
                        with (
                            patch.object(remote.signal, "signal"),
                            patch("sys.stdout", public),
                        ):
                            self.assertEqual(remote.main([]), 1)
            saved = json.loads((base / "summary.json").read_text())
            trace = saved["failure_trace"]
            self.assertTrue(1 <= len(trace) <= 8)
            for frame in trace:
                self.assertEqual(set(frame), {"file", "function", "line"})
                self.assertEqual(Path(frame["file"]).name, frame["file"])
                self.assertGreater(frame["line"], 0)
            self.assertNotIn(private_secret, json.dumps(saved))
            self.assertNotIn(str(base), json.dumps(saved))
            self.assertNotIn("failure_trace", json.loads(public.getvalue()))
            self.assertNotIn(private_secret, public.getvalue())


class FakeChannel:
    def __init__(self, frames):
        self.frames = iter(frames)
        self.written = []
        self.sent = []
        self.starts = 0

    def start(self, *_args):
        self.starts += 1

    def write_bytes(self, data, **_kwargs):
        self.written.append(data)

    def expect(self, event, **_kwargs):
        frame = next(self.frames)
        if frame["event"] != event:
            raise remote.local.ProofFailure("unexpected event")
        return frame

    def send_json(self, value, **_kwargs):
        self.sent.append(value)


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.h = SimpleNamespace(base=self.base, processes=object())

    def root(self, failed=False):
        run_id = "a" * 16
        ready = {
            "event": "bootstrap_ready",
            "schema_version": 1,
            "run_id": run_id,
            "home": "/Users/fixture",
            "uid": 501,
            "stage": "/Users/fixture/gs-" + run_id,
            "python_executable": "/opt/python3",
            "python_version": [3, 12, 1],
        }
        initialized = {
            "event": "initialized",
            "base": "/Users/fixture/gp-" + run_id,
            "state": "/Users/fixture/gp-" + run_id + "/d/s",
            "allocation": 2,
            "project_alias": "fixture-project",
            "providers": [
                {
                    "provider": "pi:json",
                    "models": ["openai/gpt-4.1"],
                    "max_budget_seconds": 30,
                }
            ],
            "context": {"root_token": "root", "project_token": "project"},
            "workspace": "/Users/fixture/gp-" + run_id + "/d/project-canary",
        }
        link = FakeChannel(
            [ready, {"event": "bootstrap_failed"} if failed else initialized]
        )
        return remote.RemoteRoot(target(), run_id, link, "device")

    def test_source_header_exact_files_then_ready_then_peer_manifest(self):
        root = self.root()
        manifest = {"peer": "data"}
        remote.bootstrap_peer(
            root,
            self.h,
            b"trusted source",
            (remote.TransferFile("bin/gateway", b"candidate", True),),
            manifest,
        )
        wire = b"".join(root.channel.written)
        self.assertEqual(wire[:4], struct.pack("!I", 14))
        self.assertEqual(wire[4:18], b"trusted source")
        size = struct.unpack("!I", wire[18:22])[0]
        header = json.loads(wire[22 : 22 + size])
        self.assertEqual(
            header["files"],
            [
                {
                    "path": "bin/gateway",
                    "size": 9,
                    "sha256": hashlib.sha256(b"candidate").hexdigest(),
                    "executable": True,
                }
            ],
        )
        self.assertEqual(wire[22 + size :], b"candidate")
        self.assertEqual(root.channel.sent, [manifest])
        receipt = json.loads(
            (self.base / (root.run_id + "-resources.json")).read_text()
        )
        self.assertEqual(receipt["peer_final"], root.base + "/peer-final.json")
        self.assertEqual(
            (self.base / (root.run_id + "-resources.json")).stat().st_mode & 0o777,
            0o600,
        )
        self.assertTrue(root.initialized)

    def test_diagnostic_handoff_requires_capture_variant_without_changing_default(self):
        for capture_tag in (None, "diagnostic_capture", "direct"):
            with self.subTest(capture_tag=capture_tag):
                root = self.root()
                original = root.channel.expect

                def tagged(event, **kwargs):
                    frame = original(event, **kwargs)
                    if event == "initialized" and capture_tag is not None:
                        frame["native_control_variant"] = capture_tag
                    return frame

                with tempfile.TemporaryDirectory() as directory:
                    harness = SimpleNamespace(base=Path(directory), processes=object())
                    with patch.object(root.channel, "expect", side_effect=tagged):
                        if capture_tag == "diagnostic_capture":
                            remote.bootstrap_peer(
                                root, harness, b"source", (), {"capture_native": True}
                            )
                            self.assertTrue(root.initialized)
                        else:
                            with self.assertRaisesRegex(
                                local.ProofFailure, "capture variant"
                            ):
                                remote.bootstrap_peer(
                                    root,
                                    harness,
                                    b"source",
                                    (),
                                    {"capture_native": True},
                                )
                            self.assertFalse(root.initialized)

    def test_initialized_delay_uses_manifest_send_anchor(self):
        root = self.root()
        original = root.channel.expect
        clock = [20.0]

        def delayed(event, **kwargs):
            frame = original(event, **kwargs)
            if event == "initialized":
                clock[0] += 40
            return frame

        with patch.object(root.channel, "expect", side_effect=delayed):
            with patch.object(remote.time, "monotonic", side_effect=lambda: clock[0]):
                remote.bootstrap_peer(root, self.h, b"source", (), {})
        self.assertEqual(clock[0], 60)
        self.assertEqual(root.last_activity, 20)

    def test_ready_then_failed_retains_locator_without_relaunch(self):
        root = self.root(failed=True)
        with self.assertRaises(local.ProofFailure):
            remote.bootstrap_peer(root, self.h, b"source", (), {})
        self.assertFalse(root.initialized)
        self.assertEqual(root.channel.starts, 1)
        self.assertTrue((self.base / (root.run_id + "-resources.json")).exists())
        with self.assertRaises(FileExistsError):
            remote.bootstrap_peer(root, self.h, b"source", (), {})
        self.assertEqual(root.channel.starts, 1)

    def test_operation_budget_fails_before_send(self):
        root = self.root()
        root.initialized = True
        root.operations = 32
        with self.assertRaises(local.ProofFailure):
            root.operate("inspect_closure")
        self.assertEqual(root.channel.sent, [])


class ScenarioRoot:
    def __init__(self, device, ledger):
        self.device = device
        self.alias = "fixture-project"
        self.tasks = []
        self.ledger = ledger
        self.started = False
        self.attempted = 0
        self.closed = set()
        self.operations = []

    def operate(self, operation, **fields):
        self.operations.append((operation, fields))
        self.ledger.append((self.device, operation))
        if operation == "wait_fixture_started":
            if not self.started:
                raise AssertionError("fixture not started")
            return {
                "task_id": fields["task_id"],
                "live_lease_proven": True,
                "attempts": {
                    "attempted": self.attempted,
                    "rejected_concurrent": 0,
                    "rejected_limit": 0,
                },
            }
        if operation == "inspect_closure":
            return {
                "closure_confirmed": True,
                "tasks": {
                    task: {
                        "cause": "requested",
                        "scope_empty": True,
                        "worker_wait": "2030-01-01T00:00:10Z",
                        "worker_wait_result": "success",
                        "deadline": "2030-01-01T00:00:30Z",
                    }
                    for task in self.closed
                },
            }
        if operation == "release_fixture" and self.tasks[-1] not in self.closed:
            raise AssertionError("gate released before task closure")
        return {}


class ScenarioHarness:
    def __init__(self):
        self.ledger = []
        self.roots = [
            ScenarioRoot("device-a", self.ledger),
            ScenarioRoot("device-b", self.ledger),
        ]
        self.operations = {}
        self.prepared = {}
        self.calls = []
        self.closed_operations = set()
        self.summary = {"stages": []}
        self.revoked = False
        self.revocation_error = "not_found"
        self.restarts = 0

    def prepare(self, root, brief):
        operation = str(len(self.prepared))
        value = {
            "operation_id": operation,
            "task_id": str(len(self.prepared)).zfill(32),
        }
        self.prepared[operation] = (root, value, brief)
        root.tasks.append(value["task_id"])
        self.operations[operation] = {"cancellation_id": "cancel-" + operation}
        return value

    def mcp(self, tool, value, failure=False):
        self.calls.append((tool, value, failure))
        if tool == "get_capabilities":
            if self.revoked and value["device_id"] == "device-a":
                if not failure:
                    raise local.ProofFailure(
                        "MCP operation failed: revoked device not_found"
                    )
                return {"code": self.revocation_error}
            if failure:
                raise AssertionError(
                    "expected capability denial but got authorized device"
                )
            return {"online": True}
        if failure:
            if tool != "prepare_dispatch":
                raise AssertionError("unexpected denial")
            return {"code": "denied"}
        if tool == "list_devices":
            return {
                "devices": [
                    {"device_id": r.device, "online": True}
                    for r in self.roots
                    if not (self.revoked and r.device == "device-a")
                ]
            }
        root, prepared, brief = self.prepared[value["operation_id"]]
        if tool == "dispatch_task":
            if not any(
                row == (root.device, prepared["task_id"]) for row in self.ledger
            ):
                root.attempted += 1
                self.ledger.append((root.device, prepared["task_id"]))
            if brief == "DELEGATE_PRIVATE_SILENCE_WAIT":
                root.started = True
            return {
                **prepared,
                "device_id": root.device,
                "project_alias": root.alias,
                "reserved": True,
                "delivery": "resolved",
            }
        if tool == "resolve_operation":
            return {
                **prepared,
                "device_id": root.device,
                "project_alias": root.alias,
                "reserved": True,
                "delivery": "resolved",
                "observation": {"kind": "existing", "execution_closure": None},
            }
        if tool == "read_result_chunk":
            return {"data_base64": "cHJpdmF0ZSBzdXBlcnZpc29yIGFjY2VwdGFuY2UgcGFzc2Vk"}
        if tool == "cancel_task":
            return {"cancellation_id": value["cancellation_id"]}
        raise AssertionError(tool)

    def await_operation(self, operation, result=False):
        root, prepared, _ = self.prepared[operation]
        self.closed_operations.add(operation)
        root.closed.add(prepared["task_id"])
        return {
            "observation": {
                "result": {
                    "sha256": "981282aa7875565f33c7d9ca84eae82548361beb9d765fdfd5a40b3e5c25e202",
                    "length": 36,
                }
            }
        }

    def restart_gateway(self):
        self.restarts += 1
        if self.restarts == 1 and not all(r.started for r in self.roots):
            raise AssertionError("restart without overlap")

    def capability_online(self, device, alias):
        return self.mcp(
            "get_capabilities", {"device_id": device, "project_alias": alias}
        )["online"]

    def until(self, check, _seconds, _description):
        if not check():
            raise AssertionError("condition did not pass")

    def check_canaries(self):
        self.ledger.append(("canaries", "checked"))

    def admin(self, action, value):
        if action != "revoke-device" or value != {
            "device_id": "device-a",
            "revoked": True,
        }:
            raise AssertionError("unexpected administrative call")
        if len(self.closed_operations) != 4:
            raise AssertionError("credential revoked before task closure")
        self.revoked = True


class ScenarioTests(unittest.TestCase):
    def test_fixed_four_attempt_schedule_restart_same_bindings_and_revoke_after_closure(
        self,
    ):
        h = ScenarioHarness()
        remote.fixture_scenarios(h, h.roots)
        self.assertEqual(len(h.prepared), 4)
        self.assertEqual([root.attempted for root in h.roots], [2, 2])
        self.assertEqual(h.restarts, 2)
        dispatches = [
            value["operation_id"]
            for tool, value, _ in h.calls
            if tool == "dispatch_task"
        ]
        self.assertEqual(dispatches, ["0", "1", "2", "3", "2", "3"])
        cancellations = [value for tool, value, _ in h.calls if tool == "cancel_task"]
        self.assertEqual(
            cancellations,
            [
                {"operation_id": "2", "cancellation_id": "cancel-2"},
                {"operation_id": "2", "cancellation_id": "cancel-2"},
                {"operation_id": "3", "cancellation_id": "cancel-3"},
                {"operation_id": "3", "cancellation_id": "cancel-3"},
            ],
        )
        self.assertEqual(sum(failure for _, _, failure in h.calls), 5)
        self.assertTrue(h.revoked)
        denied = [
            (tool, value)
            for tool, value, failure in h.calls
            if failure and tool == "get_capabilities"
        ]
        self.assertEqual(
            denied,
            [
                (
                    "get_capabilities",
                    {"device_id": "device-a", "project_alias": "fixture-project"},
                )
            ]
            * 2,
        )
        self.assertEqual(
            h.summary["revocation_acceptance"],
            "public_authorization_and_inventory_visibility",
        )
        self.assertEqual(
            h.summary["revoked_certificate_reconnect_denial"], "unverified"
        )
        self.assertEqual(h.summary["fixture_tasks_executed"], 4)
        self.assertEqual(
            [
                [operation for operation, _ in r.operations].count(
                    "wait_fixture_started"
                )
                for r in h.roots
            ],
            [3, 3],
        )

    def test_revocation_rejects_any_error_other_than_required_not_found(self):
        for code in ("forbidden", "internal_error", "pending"):
            with self.subTest(code=code):
                h = ScenarioHarness()
                h.revocation_error = code
                with self.assertRaisesRegex(
                    local.ProofFailure, "required authorization denial"
                ):
                    remote.fixture_scenarios(h, h.roots)
                self.assertNotIn("revocation_acceptance", h.summary)
                self.assertEqual(h.restarts, 1)

    def test_revocation_requires_hidden_revoked_device_and_other_online(self):
        invalid_pages = [
            [
                {"device_id": "device-a", "online": True},
                {"device_id": "device-b", "online": True},
            ],
            [{"device_id": "device-b", "online": False}],
            [],
        ]
        for rows in invalid_pages:
            with self.subTest(rows=rows):
                h = ScenarioHarness()
                original = h.mcp

                def mcp(tool, value, failure=False):
                    if h.revoked and tool == "list_devices":
                        return {"devices": rows}
                    return original(tool, value, failure)

                with patch.object(h, "mcp", side_effect=mcp):
                    with self.assertRaisesRegex(
                        local.ProofFailure, "inventory visibility"
                    ):
                        remote.fixture_scenarios(h, h.roots)
                self.assertNotIn("revocation_acceptance", h.summary)

    def test_overrun_never_claims_cancellation_or_revokes_authority(self):
        h = ScenarioHarness()
        with patch.object(remote.time, "monotonic", side_effect=[0, 26]):
            with self.assertRaisesRegex(local.ProofFailure, "finite budget"):
                remote.fixture_scenarios(h, h.roots)
        self.assertFalse(h.revoked)
        self.assertFalse(any(tool == "cancel_task" for tool, _, _ in h.calls))

    def test_actual_wait_dispositions_only_and_before_deadline(self):
        record = {
            "cause": "requested",
            "scope_empty": True,
            "worker_wait": "2030-01-01T00:00:10Z",
            "worker_wait_result": "success",
            "deadline": "2030-01-01T00:00:30Z",
        }
        for disposition in (
            "success",
            "exit-error",
            "wait-error",
            "not-started",
            "absent",
            None,
        ):
            with self.subTest(disposition=disposition):
                result = {
                    "closure_confirmed": True,
                    "tasks": {"task": {**record, "worker_wait_result": disposition}},
                }
                root = SimpleNamespace(operate=lambda _operation: result)
                if disposition in ("success", "exit-error"):
                    remote.require_closed(root, "task")
                else:
                    with self.assertRaises(local.ProofFailure):
                        remote.require_closed(root, "task")
        result = {
            "closure_confirmed": True,
            "tasks": {"task": {**record, "worker_wait": record["deadline"]}},
        }
        with self.assertRaises(local.ProofFailure):
            remote.require_closed(
                SimpleNamespace(operate=lambda _operation: result), "task"
            )


class CleanupTests(unittest.TestCase):
    def test_remote_cleanup_receipt_with_broken_ssh_never_confirms_cleanup(self):
        self.check_cleanup(exit_code=255, protocol_failure=False, expected=False)

    def test_protocol_failure_still_closes_input_and_joins_without_relaunch(self):
        self.check_cleanup(exit_code=0, protocol_failure=True, expected=False)

    def test_exact_ssh_wait_and_bound_final_receipt_confirm_cleanup_but_retain_paths(
        self,
    ):
        self.check_cleanup(exit_code=0, protocol_failure=False, expected=True)

    def test_pre_join_refresh_failure_is_recorded_without_skipping_current_wait(self):
        self.check_cleanup(
            exit_code=0, protocol_failure=False, expected=False, refresh_failure=True
        )

    def test_budget_exhausted_closing_root_is_not_reopened_and_still_joined(self):
        with tempfile.TemporaryDirectory() as directory:
            events = []
            root = remote.RemoteRoot(
                target(),
                "a" * 16,
                None,
                "a",
                initialized=True,
                operations=remote.peer.MAX_OPERATIONS,
            )
            controller = remote.Controller.__new__(remote.Controller)
            controller.roots = [root]

            class Link:
                failure = None
                process = SimpleNamespace(poll=lambda: None)
                capture = SimpleNamespace(close=lambda: None)

                def send_json(self, *_args, **_kwargs):
                    events.append("unexpected_input")

                def close_input(self):
                    events.append("eof")

                def join(self, **_kwargs):
                    controller.pump_peers(force=True)
                    events.append("natural_wait")
                    return {"exit_code": 0, "natural_wait": True}

            root.channel = Link()
            controller.h = SimpleNamespace(
                base=Path(directory),
                operations={},
                closed_operations=set(),
                gateway=None,
                jwks=None,
                summary={},
                interruptions=SimpleNamespace(
                    cleanup=nullcontext, finalize_cleanup=lambda: False
                ),
                processes=SimpleNamespace(finished_naturally=lambda: True),
                ownership=SimpleNamespace(release=lambda: None),
            )
            self.assertFalse(
                controller.finish()
            )  # Missing final receipt remains unconfirmed.
            self.assertEqual(events, ["eof", "natural_wait"])
            self.assertTrue(root.closing)
            self.assertTrue(root.wait["natural_wait"])

    def test_two_peer_cleanup_refreshes_after_final_before_long_join(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = [0.0]
            received = {"a": [0.0], "b": [0.0]}
            late = []
            joins = []

            class Link:
                failure = None
                process = SimpleNamespace(poll=lambda: None)
                capture = SimpleNamespace(close=lambda: None)

                def __init__(self, name, base):
                    self.name = name
                    self.base = base

                def send_json(self, _value, **_kwargs):
                    clock[0] += 10
                    gap = clock[0] - received[self.name][-1]
                    received[self.name].append(clock[0])
                    if gap >= 120:
                        late.append((self.name, gap))
                        raise local.ProofFailure("peer input idle deadline exceeded")

                def expect(self, event, **_kwargs):
                    clock[0] += {"inspect_closure": 15, "shutdown": 40, "final": 10}[
                        event
                    ]
                    return {
                        "event": event,
                        "base": self.base,
                        "cleanup_confirmed": True,
                    }

                def close_input(self):
                    pass

                def join(self, **_kwargs):
                    joins.append(self.name)
                    clock[0] += 45
                    return {"exit_code": 0, "natural_wait": True}

            roots = [
                remote.RemoteRoot(
                    target(), "a" * 16, None, "a", initialized=True, last_activity=0
                ),
                remote.RemoteRoot(
                    target("mac-b"),
                    "b" * 16,
                    None,
                    "b",
                    initialized=True,
                    last_activity=0,
                ),
            ]
            for root in roots:
                root.channel = Link(root.device, root.base)
            controller = remote.Controller.__new__(remote.Controller)
            controller.roots = roots
            controller.h = SimpleNamespace(
                base=Path(directory),
                operations={},
                closed_operations=set(),
                gateway=None,
                jwks=None,
                summary={},
                interruptions=SimpleNamespace(
                    cleanup=nullcontext, finalize_cleanup=lambda: False
                ),
                processes=SimpleNamespace(finished_naturally=lambda: True),
                ownership=SimpleNamespace(release=lambda: None),
            )
            with patch.object(remote.time, "monotonic", side_effect=lambda: clock[0]):
                confirmed = controller.finish()
            self.assertEqual(late, [])
            self.assertTrue(confirmed)
            self.assertEqual(joins, ["a", "b"])
            self.assertEqual(received, {"a": [0.0, 35], "b": [0.0, 10, 95, 165]})
            self.assertTrue(all(root.wait["natural_wait"] for root in roots))

    def check_cleanup(
        self, *, exit_code, protocol_failure, expected, refresh_failure=False
    ):
        with tempfile.TemporaryDirectory() as directory:
            events = []
            root = remote.RemoteRoot(target(), "a" * 16, None, "device")
            receipt = {"base": root.base, "cleanup_confirmed": True}

            class Link:
                failure = "protocol_fault" if protocol_failure else None
                process = SimpleNamespace(poll=lambda: None)
                capture = SimpleNamespace(close=lambda: events.append("capture_close"))

                def send_json(self, value, **_kwargs):
                    events.append(value["operation"])

                def expect(self, event, **_kwargs):
                    return {"event": event, **receipt}

                def close_input(self):
                    events.append("eof")

                def join(self, **_kwargs):
                    events.append("wait")
                    return {"exit_code": exit_code, "natural_wait": True}

            root.channel = Link()
            root.initialized = True
            controller = remote.Controller.__new__(remote.Controller)
            controller.roots = [root]
            controller.h = SimpleNamespace(
                base=Path(directory),
                operations={},
                closed_operations=set(),
                gateway=None,
                jwks=None,
                summary={},
                interruptions=SimpleNamespace(
                    cleanup=nullcontext, finalize_cleanup=lambda: False
                ),
                processes=SimpleNamespace(finished_naturally=lambda: True),
                ownership=SimpleNamespace(release=lambda: events.append("release")),
            )
            original_pump = controller.pump_peers

            def pump(**kwargs):
                if refresh_failure and kwargs.get("exclude") is root:
                    raise local.ProofFailure("sibling refresh failed")
                return original_pump(**kwargs)

            with patch.object(controller, "pump_peers", side_effect=pump):
                self.assertEqual(controller.finish(), expected)
            self.assertEqual(events.count("wait"), 1)
            self.assertLess(events.index("eof"), events.index("wait"))
            self.assertNotIn("start", events)
            summary = json.loads((Path(directory) / "summary.json").read_text())
            self.assertFalse(summary["paths_removed"])
            self.assertEqual(summary["cleanup_confirmed"], expected)
            if not expected:
                self.assertEqual(summary["physical_device_acceptance"], "unverified")
            if refresh_failure:
                self.assertEqual(
                    summary["cleanup_errors"],
                    [{"stage": "pre_join_peer_refresh", "kind": "ProofFailure"}],
                )


class PumpTests(unittest.TestCase):
    def harness(self, callback):
        harness = remote.RemoteHarness.__new__(remote.RemoteHarness)
        harness.peer_pump = callback
        harness._pumping = False
        harness.interruptions = local.Interruptions()
        return harness

    def test_every_local_blocking_boundary_pumps_before_and_after_including_failure(
        self,
    ):
        calls = (
            ("command", (Path("/bin/tool"), [])),
            ("admin", ("action", {})),
            ("mcp", ("tool", {})),
            ("stop_process", (object(),)),
            ("check_auth", ()),
        )
        for method, args in calls:
            for failed in (False, True):
                with self.subTest(method=method, failed=failed):
                    events = []
                    harness = self.harness(lambda: events.append("pump"))

                    def control(*_args, **_kwargs):
                        events.append("control")
                        if failed:
                            raise local.ProofFailure("control failed")
                        return "result"

                    with patch.object(local.Harness, method, side_effect=control):
                        if failed:
                            with self.assertRaisesRegex(
                                local.ProofFailure, "control failed"
                            ):
                                getattr(harness, method)(*args)
                        else:
                            self.assertEqual(getattr(harness, method)(*args), "result")
                    self.assertEqual(events, ["pump", "control", "pump"])

    def test_until_services_every_check_without_changing_original_timeout(self):
        events = []
        harness = self.harness(lambda: events.append("pump"))
        checks = iter((False, False, True))

        def check():
            events.append("check")
            return next(checks)

        with patch.object(local.time, "sleep") as sleep:
            self.assertTrue(harness.until(check, 10, "finite condition"))
        self.assertEqual(events, ["pump", "check", "pump"] * 3)
        self.assertEqual(sleep.call_args_list, [unittest.mock.call(0.2)] * 2)

    def test_reentrant_pump_suppressed_and_guard_restored_after_fault(self):
        events = []
        harness = self.harness(None)

        def callback():
            events.append("pump")
            harness.pump_peers()
            raise local.ProofFailure("heartbeat failed")

        harness.peer_pump = callback
        for _ in range(2):
            with self.assertRaisesRegex(local.ProofFailure, "heartbeat failed"):
                harness.pump_peers()
        self.assertEqual(events, ["pump", "pump"])
        self.assertFalse(harness._pumping)

    def test_sibling_heartbeat_then_two_direct_operations_service_other_peer_first(
        self,
    ):
        clock = [34.99]
        received = {"a": [0.0], "b": [0.0]}

        class Link:
            failure = None
            process = SimpleNamespace(poll=lambda: None)

            def __init__(self, name):
                self.name = name

            def send_json(self, _value, **_kwargs):
                clock[0] += 10
                arrival = (
                    clock[0] + 0.02
                )  # Finite wire delay beyond local send completion.
                gap = arrival - received[self.name][-1]
                if gap >= 120:
                    raise AssertionError("peer " + self.name + " idle gap " + str(gap))
                received[self.name].append(arrival)

            def expect(self, _event, **_kwargs):
                clock[0] += 15
                return {}

        roots = [
            remote.RemoteRoot(
                target(), "a" * 16, Link("a"), "a", initialized=True, last_activity=0
            ),
            remote.RemoteRoot(
                target("mac-b"),
                "b" * 16,
                Link("b"),
                "b",
                initialized=True,
                last_activity=-1,
            ),
        ]
        controller = remote.Controller.__new__(remote.Controller)
        controller.roots = roots
        harness = self.harness(controller.pump_peers)
        for root in roots:
            root.before_operation = harness.pump_peers
        with patch.object(remote.time, "monotonic", side_effect=lambda: clock[0]):
            harness.pump_peers()  # Skips A at age34.99, refreshes due B.
            roots[1].operate("inspect_closure")
            roots[1].operate("release_fixture")
            roots[0].operate("inspect_closure")
        for actual, expected in zip(received["a"], (0, 70.01, 120.01, 170.01)):
            self.assertAlmostEqual(actual, expected)
        for actual, expected in zip(received["b"], (0, 45.01, 95.01, 145.01)):
            self.assertAlmostEqual(actual, expected)
        self.assertEqual([len(received[name]) for name in ("a", "b")], [4, 4])
        self.assertTrue(all(not root.in_operation for root in roots))

    def test_delayed_reply_two_peers_and_local_join_never_overstate_idle_freshness(
        self,
    ):
        clock = [0.0]
        received = {"a": [0.0], "b": [0.0]}

        class Link:
            failure = None
            process = SimpleNamespace(poll=lambda: None)

            def __init__(self, name):
                self.name = name
                self.first = name == "a"

            def send_json(self, _value, **_kwargs):
                clock[0] += 0 if self.first else 10
                self.first = False
                gap = clock[0] - received[self.name][-1]
                if gap >= 120:
                    raise AssertionError("peer " + self.name + " idle gap " + str(gap))
                received[self.name].append(clock[0])

            def expect(self, _event, **_kwargs):
                clock[0] += 15
                return {}

        roots = [
            remote.RemoteRoot(
                target(), "a" * 16, Link("a"), "a", initialized=True, last_activity=0
            ),
            remote.RemoteRoot(
                target("mac-b"),
                "b" * 16,
                Link("b"),
                "b",
                initialized=True,
                last_activity=0,
            ),
        ]
        controller = remote.Controller.__new__(remote.Controller)
        controller.roots = roots
        harness = self.harness(controller.pump_peers)

        def join(*_args, **_kwargs):
            clock[0] += 45

        with patch.object(remote.time, "monotonic", side_effect=lambda: clock[0]):
            roots[0].operate("inspect_closure")
            self.assertEqual(clock[0], 15)
            clock[0] = 49  # 34s after A's delayed reply, 49s after A's input.
            with patch.object(local.Harness, "stop_process", side_effect=join):
                harness.stop_process(object())
        self.assertEqual(received, {"a": [0.0, 0.0, 59, 154], "b": [0.0, 84, 179]})
        self.assertEqual([root.last_activity for root in roots], [144, 169])
        self.assertEqual([root.operations for root in roots], [3, 2])

    def test_failed_request_keeps_previous_send_anchor_and_releases_busy_guard(self):
        for phase in ("before_operation", "response"):
            with self.subTest(phase=phase):
                root = remote.RemoteRoot(
                    target(),
                    "a" * 16,
                    FakeChannel([{"event": "failed"}]),
                    "device",
                    initialized=True,
                    last_activity=7,
                )
                if phase == "before_operation":

                    def fail_hook():
                        self.assertTrue(root.in_operation)
                        raise local.ProofFailure("sibling refresh failed")

                    root.before_operation = fail_hook
                with patch.object(remote.time, "monotonic", return_value=100):
                    with self.assertRaises(local.ProofFailure):
                        root.operate("inspect_closure")
                self.assertEqual(root.last_activity, 7)
                self.assertFalse(root.in_operation)
                if phase == "before_operation":
                    self.assertEqual(root.channel.sent, [])

    def test_nested_admin_command_pumps_at_both_owned_boundaries(self):
        events = []
        harness = self.harness(lambda: events.append("pump"))

        def admin(*_args, **_kwargs):
            events.append("admin_start")
            value = harness.command(Path("/bin/tool"), [])
            events.append("admin_end")
            return value

        def command(*_args, **_kwargs):
            events.append("command")
            return {}

        with patch.object(local.Harness, "admin", side_effect=admin):
            with patch.object(local.Harness, "command", side_effect=command):
                self.assertEqual(harness.admin("action", {}), {})
        self.assertEqual(
            events,
            ["pump", "admin_start", "pump", "command", "pump", "admin_end", "pump"],
        )

    def test_consecutive_slow_controls_keep_idle_bounded_and_skip_pending_peers(self):
        clock = [0.0]
        requests = []

        class Link:
            failure = None
            process = SimpleNamespace(poll=lambda: None)

            def send_json(self, value, **_kwargs):
                requests.append((clock[0], value["operation"]))

            def expect(self, _event, **_kwargs):
                return {}

        root = remote.RemoteRoot(
            target(), "a" * 16, Link(), "device", initialized=True, last_activity=0
        )
        harness = self.harness(root.heartbeat)

        def slow_control(*_args, **_kwargs):
            clock[0] += 40
            return {}

        with patch.object(remote.time, "monotonic", side_effect=lambda: clock[0]):
            with patch.object(local.Harness, "command", side_effect=slow_control):
                for _ in range(4):
                    harness.command(Path("/bin/tool"), [])
            root.in_operation = True
            clock[0] += 40
            harness.pump_peers()
            root.in_operation = False
            root.channel.failure = "fault"
            harness.pump_peers()
        self.assertEqual(
            requests,
            [
                (40.0, "inspect_closure"),
                (80.0, "inspect_closure"),
                (120.0, "inspect_closure"),
                (160.0, "inspect_closure"),
            ],
        )
        self.assertEqual(root.operations, 4)
        self.assertTrue(
            all(
                after[0] - before[0] < 120
                for before, after in zip([(0.0, "start"), *requests], requests)
            )
        )


class NativeLoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository = os.environ.get("DELEGATE_ACCEPTANCE_REPOSITORY")
        if repository is None:
            raise unittest.SkipTest(
                "DELEGATE_ACCEPTANCE_REPOSITORY is required for Native child tests"
            )
        cls.repository = Path(repository)
        cls.acceptance = local.load_acceptance(cls.repository)

    def test_freeze_real_pinned_namespace_sources_joins_git_without_fabricated_initializer(
        self,
    ):
        owner = self.acceptance.directories.DirectoryOwner()
        base = Path(tempfile.mkdtemp(prefix="remote-freeze-source-")).resolve()
        owner.adopt_created("pinned Native source freeze test", base, base.parent)
        candidates = base / "candidates"
        candidates.mkdir(mode=0o700)
        metadata = {}
        for name in ("gateway", "delegate", "delegate-run"):
            data = (name + " owned candidate standin").encode()
            path = candidates / name
            path.write_bytes(data)
            path.chmod(0o700)
            metadata[name] = {
                "path": str(path),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "owned_build": True,
            }
        receipt = base / "build.json"
        receipt.write_text(
            json.dumps(
                {
                    "platform": "darwin/arm64",
                    "owned_candidate_root": str(candidates),
                    "results": [{"actual_wait": True, "exit_code": 0}] * 3,
                    "files": metadata,
                }
            )
        )
        config = SimpleNamespace(
            candidate_directory=candidates,
            build_receipt=receipt,
            delegate_repository=self.repository,
        )
        book = self.acceptance.processes.Processes(
            base / "processes", environment={}, owner=owner
        )
        try:
            self.assertFalse((self.repository / "scripts/__init__.py").exists())
            source, files = remote.freeze_sources(
                config, SimpleNamespace(processes=book, base=base)
            )
            staged = {item.path: item.data for item in files}
            self.assertNotIn("native/scripts/__init__.py", staged)
            self.assertEqual(
                staged["native/scripts/acceptance/__init__.py"],
                (self.repository / "scripts/acceptance/__init__.py").read_bytes(),
            )
            self.assertIn("native/scripts/acceptance/processes/operations.py", staged)
            self.assertIn("native/scripts/acceptance/private_cli/fixtures.py", staged)
            self.assertTrue(all(remote.bootstrap.allowed_path(path) for path in staged))
            self.assertTrue(source.startswith(b"#!/usr/bin/env python3"))
            stage = base / "stage"
            stage.mkdir(mode=0o700)
            for item in files:
                if item.path in remote.bootstrap.CANDIDATES:
                    continue  # Only SOURCE/data is needed to test fresh imports.
                path = stage / item.path
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes(item.data)
                path.chmod(0o600)
            probe = """import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
assert 'scripts.acceptance.evidence.json_decoder' not in sys.modules
import e2e_remote_peer as peer
native=Path(sys.argv[2]).resolve()
acceptance=peer.local.load_acceptance(native)
assert Path(acceptance.processes.__file__).is_relative_to(native)
assert not (native/'scripts/__init__.py').exists()
from scripts.acceptance.evidence.json_decoder import unique_object
from scripts.acceptance.evidence.validation import AcceptanceFailure
try:
 unique_object([('K',1),('\u212a',2)])
except AcceptanceFailure:
 pass
else:
 raise AssertionError('Go SimpleFold alias accepted')
assert unique_object([('\u00df',1),('ss',2)])=={'\u00df':1,'ss':2}
print(json.dumps({'staged_import':True,'simple_fold_alias_rejected':True,'multi_rune_fold_distinct':True}))
"""
            child = book.run(
                "fresh-staged-source-import",
                [
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-c",
                    probe,
                    str(stage / "gateway/scripts"),
                    str(stage / "native"),
                ],
                base,
                timeout=10,
                expected={0, 1},
            )
            missing_data = b"unicode-simple-fold.json" in child.stderr_path.read_bytes()
            self.assertEqual(
                child.result["exit_code"],
                0,
                "isolated staged import missing Unicode data"
                if missing_data
                else "isolated staged import failed",
            )
            self.assertEqual(
                child.json(),
                {
                    "staged_import": True,
                    "simple_fold_alias_rejected": True,
                    "multi_rune_fold_distinct": True,
                },
            )
            self.assertEqual(
                staged["native/scripts/_data/unicode-simple-fold.json"],
                (
                    self.repository / "scripts/_data/unicode-simple-fold.json"
                ).read_bytes(),
            )
        finally:
            unresolved = book.drain(timeout=5)
            try:
                self.assertEqual(len(book.entries), 2)
                self.assertTrue(
                    all(process.result["natural_wait"] for process in book.entries)
                )
                self.assertEqual(book.entries[0].result["exit_code"], 0)
            finally:
                if unresolved:
                    owner.release()
                    raise RuntimeError("retained unresolved tracked-source Git child")
                owner.rollback()

    def test_selected_absolute_ssh_argv_admitted_by_native_with_finite_standin(self):
        owner = self.acceptance.directories.DirectoryOwner()
        base = Path(tempfile.mkdtemp(prefix="remote-ssh-argv-")).resolve()
        owner.adopt_created("SSH argv standin test", base, base.parent)
        executable = base / "ssh-standin"
        executable.write_text(
            "#!"
            + str(Path(sys.executable).resolve())
            + "\nimport json,sys\nassert sys.argv[-2] == 'mac-a'\nprint(json.dumps({'event':'bootstrap_ready','selected':sys.argv[0]}),flush=True)\n"
        )
        executable.chmod(0o700)
        with patch.object(remote.shutil, "which", return_value=str(executable)):
            argv = remote.ssh_argv(remote.installed_ssh(), target())
        link = PeerChannel(self.acceptance.processes, argv)
        book = self.acceptance.processes.Processes(
            base / "processes",
            environment={},
            owner=owner,
            stdout_capture_factory=link.capture_factory,
        )
        try:
            link.start(book, "ssh-standin", base)
            self.assertEqual(
                link.expect("bootstrap_ready", timeout=3),
                {"event": "bootstrap_ready", "selected": str(executable)},
            )
            link.close_input()
            result = link.join(timeout=3)
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(result["natural_wait"])
            invocation = json.loads(
                (link.process.directory / "invocation.json").read_text()
            )
            self.assertEqual(invocation["executable"], str(executable))
            self.assertEqual(invocation["argv"], list(argv))
        finally:
            link.close_input()
            unresolved = book.drain(timeout=5)
            link.capture.close()
            if unresolved:
                owner.release()
                raise RuntimeError("retained unresolved SSH standin child")
            owner.rollback()

    def test_raw_loader_reads_exact_source_and_preserves_following_input(self):
        owner = self.acceptance.directories.DirectoryOwner()
        base = Path(tempfile.mkdtemp(prefix="remote-loader-")).resolve()
        owner.adopt_created("loader test", base, base.parent)
        link = PeerChannel(
            self.acceptance.processes,
            (str(Path(sys.executable).resolve()), "-I", "-c", remote.RAW_LOADER),
        )
        book = self.acceptance.processes.Processes(
            base / "processes",
            environment={},
            owner=owner,
            stdout_capture_factory=link.capture_factory,
        )
        try:
            link.start(book, "loader", base)
            source = b'import os,json; print(json.dumps({"event":"bootstrap_ready","tail":os.read(0,4).decode()}),flush=True)'
            link.write_bytes(
                struct.pack("!I", len(source)) + source + b"TAIL", timeout=3
            )
            self.assertEqual(
                link.expect("bootstrap_ready", timeout=3),
                {"event": "bootstrap_ready", "tail": "TAIL"},
            )
            link.close_input()
            result = link.join(timeout=3)
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(result["natural_wait"])
        finally:
            link.close_input()
            unresolved = book.drain(timeout=5)
            link.capture.close()
            if unresolved:
                owner.release()
                raise RuntimeError("retained unresolved loader child")
            owner.rollback()

    def test_closing_peer_heartbeat_sends_no_input_before_separate_native_wait(self):
        owner = self.acceptance.directories.DirectoryOwner()
        base = Path(tempfile.mkdtemp(prefix="remote-closing-peer-")).resolve()
        owner.adopt_created("closing peer EOF test", base, base.parent)
        source = "import os,select,sys\nif not select.select([0],[],[],3)[0]: sys.exit(9)\nsys.exit(0 if os.read(0,1)==b'' else 8)\n"
        link = PeerChannel(
            self.acceptance.processes,
            (str(Path(sys.executable).resolve()), "-I", "-c", source),
        )
        root = remote.RemoteRoot(
            target(),
            "a" * 16,
            link,
            "device",
            initialized=True,
            last_activity=0,
            closing=True,
        )
        book = self.acceptance.processes.Processes(
            base / "processes",
            environment={},
            owner=owner,
            stdout_capture_factory=link.capture_factory,
        )
        try:
            link.start(book, "closing-peer", base)
            root.heartbeat(force=True)
            self.assertEqual(root.operations, 0)
            self.assertIsNone(link.failure)
            link.close_input()
            result = link.join(timeout=3)
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(result["natural_wait"])
            self.assertTrue(book.finished_naturally())
        finally:
            link.close_input()
            unresolved = book.drain(timeout=5)
            link.capture.close()
            if unresolved:
                owner.release()
                raise RuntimeError("retained unresolved closing peer child")
            owner.rollback()

    def test_interrupted_source_frame_eof_gets_exact_native_wait_on_failure(self):
        owner = self.acceptance.directories.DirectoryOwner()
        base = Path(tempfile.mkdtemp(prefix="remote-loader-eof-")).resolve()
        owner.adopt_created("loader interrupted input test", base, base.parent)
        link = PeerChannel(
            self.acceptance.processes,
            (str(Path(sys.executable).resolve()), "-I", "-c", remote.RAW_LOADER),
        )
        book = self.acceptance.processes.Processes(
            base / "processes",
            environment={},
            owner=owner,
            stdout_capture_factory=link.capture_factory,
        )
        try:
            link.start(book, "interrupted-loader", base)
            link.write_bytes(struct.pack("!I", 128) + b"incomplete", timeout=3)
            link.close_input()
            with self.assertRaisesRegex(RuntimeError, "channel_response_eof"):
                link.expect("bootstrap_ready", timeout=3)
            result = link.join(timeout=3)
            self.assertEqual(result["exit_code"], 14)
            self.assertTrue(result["natural_wait"])
            self.assertTrue(book.finished_naturally())
        finally:
            link.close_input()
            unresolved = book.drain(timeout=5)
            link.capture.close()
            if unresolved:
                owner.release()
                raise RuntimeError("retained unresolved interrupted loader child")
            owner.rollback()


if __name__ == "__main__":
    unittest.main()
