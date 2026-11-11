"""Pure wrapper checks. Literal child fixtures use no Delegate/provider accounts."""

import io
import json
from pathlib import Path
import subprocess
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import e2e_native_capture as capture


class LiteralProcesses:
    """Test double for the maintained registry, with an actual waited literal child."""

    def __init__(self, directory, environment, **_options):
        self.directory = directory
        self.environment = environment
        self.entries = []

    def start(self, _name, argv, cwd):
        self.directory.mkdir(mode=0o700)
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=self.environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
        stdout = self.directory / "stdout"
        stderr = self.directory / "stderr"
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        receipt = {
            "exit_code": result.returncode,
            "natural_wait": result.returncode >= 0,
            "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
        }
        process = SimpleNamespace(
            stdout_path=stdout,
            stderr_path=stderr,
            poll=lambda: receipt,
        )
        self.entries.append(process)
        return process

    def finished_naturally(self):
        return all(entry.poll()["natural_wait"] for entry in self.entries)


class NativeCaptureTests(unittest.TestCase):
    def test_only_closed_bounded_metadata_survives(self):
        source = {
            "schema_version": 1,
            "command": "dispatch",
            "task_record": "not_created",
            "error": "PRIVATE-CANARY",
            "failure": {
                "code": "resource_pressure",
                "stage": "PRIVATE-CANARY",
                "next_action": "retry_later",
                "recovery_command": "PRIVATE-CANARY",
            },
            "resource_admission": {
                "status": "pressure",
                "warnings": [{"metric": "host_cpu", "message": "PRIVATE-CANARY"}],
                "diagnostics": {
                    "host_cpu": {"busy_percent": 98.5, "path": "PRIVATE-CANARY"}
                },
            },
        }
        output = capture.closed_metadata(json.dumps(source).encode())
        self.assertEqual(
            output["failure"],
            {"code": "resource_pressure", "next_action": "retry_later"},
        )
        self.assertEqual(
            output["resource_admission"]["diagnostics"]["host_cpu"],
            {"busy_percent": 98.5},
        )
        self.assertNotIn("PRIVATE-CANARY", json.dumps(output))

    def test_malformed_or_unknown_envelopes_produce_no_metadata(self):
        for data in (
            b"not-json",
            b"[]",
            b'{"schema_version":1,"command":[]}',
            b'{"schema_version":true,"command":"dispatch"}',
            b'{"schema_version":1,"command":"PRIVATE-CANARY"}',
        ):
            with self.subTest(data=data):
                self.assertEqual(capture.closed_metadata(data), {})
        self.assertEqual(
            capture.resource_metadata(
                {"busy_percent": float("nan"), "total_bytes": -1, "usage_bytes": True}
            ),
            {},
        )

    def test_argument_boundary_requires_explicit_separator(self):
        args = capture.arguments(
            [
                "--delegate",
                "/real/cli",
                "--repository",
                "/repo",
                "--capture-root",
                "/private",
                "--",
                "resolve",
                "task",
                "--json",
            ]
        )
        self.assertEqual(args.arguments, ["resolve", "task", "--json"])
        with mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            capture.arguments(
                [
                    "--delegate",
                    "/real/cli",
                    "--repository",
                    "/repo",
                    "--capture-root",
                    "/private",
                ]
            )

    def test_literal_child_output_argv_and_exit_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "literal.py"
            executable.write_text(
                '#!/usr/bin/python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\nsys.stderr.buffer.write(b"literal stderr\\x00")\nraise SystemExit(2)\n'
            )
            executable.chmod(0o700)
            args = SimpleNamespace(
                delegate=executable,
                repository=root,
                capture_root=root,
                arguments=["literal argument", "$(must-not-run)"],
            )
            output, errors = io.BytesIO(), io.BytesIO()
            with mock.patch.object(
                capture, "load_owners", return_value=(mock.Mock, LiteralProcesses)
            ):
                self.assertEqual(capture.capture(args, output, errors), 2)
            self.assertEqual(json.loads(output.getvalue()), args.arguments)
            self.assertEqual(errors.getvalue(), b"literal stderr\x00")
            report = json.loads(next(root.glob("native-*/metadata.json")).read_text())
            self.assertEqual(report["child_exit_code"], 2)
            self.assertTrue(report["direct_wait_confirmed"])
            self.assertTrue(report["cleanup_confirmed"])
            self.assertFalse(report["interrupted"])

    def test_output_overflow_retains_private_files_and_returns_three(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(
                delegate=Path("/usr/bin/printf"),
                repository=root,
                capture_root=root,
                arguments=["123456789"],
            )
            output, errors = io.BytesIO(), io.BytesIO()
            with (
                mock.patch.object(
                    capture, "load_owners", return_value=(mock.Mock, LiteralProcesses)
                ),
                mock.patch.object(capture, "MAX_STDOUT", 8),
            ):
                self.assertEqual(capture.capture(args, output, errors), 3)
            self.assertEqual(output.getvalue(), b"")
            self.assertEqual(
                next(root.glob("native-*/processes/stdout")).read_bytes(), b"123456789"
            )
            report = json.loads(next(root.glob("native-*/metadata.json")).read_text())
            self.assertFalse(report["output_within_limits"])
            self.assertEqual(report["child_exit_code"], 0)

    def test_negative_and_interrupted_exits_keep_diagnostic_failure(self):
        for mode in ("negative", "interrupted"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = SimpleNamespace(
                    delegate=Path("/usr/bin/printf"),
                    repository=root,
                    capture_root=root,
                    arguments=["literal"],
                )

                class FaultProcesses(LiteralProcesses):
                    def start(self, name, argv, cwd):
                        process = super().start(name, argv, cwd)
                        if mode == "negative":
                            receipt = dict(
                                process.poll(), exit_code=-15, natural_wait=False
                            )
                            process.poll = lambda: receipt
                        else:
                            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                        return process

                output, errors = io.BytesIO(), io.BytesIO()
                with mock.patch.object(
                    capture, "load_owners", return_value=(mock.Mock, FaultProcesses)
                ):
                    self.assertEqual(capture.capture(args, output, errors), 3)
                self.assertEqual(output.getvalue(), b"")
                report = json.loads(
                    next(root.glob("native-*/metadata.json")).read_text()
                )
                self.assertTrue(report["direct_wait_confirmed"])
                self.assertEqual(
                    report["child_exit_code"], -15 if mode == "negative" else 0
                )
                self.assertEqual(report["interrupted"], mode == "interrupted")

    def test_public_capture_directory_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            args = SimpleNamespace(
                delegate=Path("/usr/bin/printf"),
                repository=root,
                capture_root=root,
                arguments=[],
            )
            with (
                self.assertRaises(ValueError),
                mock.patch.object(capture, "load_owners") as owners,
            ):
                capture.capture(args, io.BytesIO(), io.BytesIO())
            owners.assert_not_called()


if __name__ == "__main__":
    unittest.main()
