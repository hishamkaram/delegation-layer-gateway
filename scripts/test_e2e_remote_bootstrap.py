"""Bootstrap fixture proof only: no peer, Delegate, provider, SSH or device."""

from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

import e2e_remote_bootstrap as bootstrap


RUN_ID = "0123456789abcdef"
BENIGN = b"# harmless source; never executed by bootstrap tests\n"


def manifest(home, entries=None):
    if entries is None:
        entries = [(bootstrap.PEER, BENIGN)]
    return {
        "schema_version": 1,
        "run_id": RUN_ID,
        "expected_home": str(home),
        "expected_uid": os.getuid(),
        "files": [
            {
                "path": path,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "executable": path in bootstrap.CANDIDATES,
            }
            for path, data in entries
        ],
    }


def frame(value, data=BENIGN):
    header = json.dumps(value).encode()
    return struct.pack("!I", len(header)) + header + data


@contextmanager
def input_pipe(data, *, connected=False):
    reader, writer = os.pipe()
    try:
        os.write(writer, data)
        if not connected:
            os.close(writer)
            writer = None
        yield reader
    finally:
        os.close(reader)
        if writer is not None:
            os.close(writer)


class BootstrapTests(unittest.TestCase):
    def test_valid_staging_fixture_accepts_a_symlinked_temporary_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            physical = base / "physical"
            physical.mkdir()
            alias = base / "alias"
            alias.symlink_to(physical, target_is_directory=True)
            case = BootstrapTests(
                "test_exact_frame_handoff_preserves_peer_input_and_exec_contract"
            )
            result = unittest.TestResult()
            with mock.patch.object(tempfile, "tempdir", str(alias)):
                case.run(result)
            self.assertEqual(result.testsRun, 1)
            self.assertEqual(result.skipped, [])
            self.assertEqual(result.failures + result.errors, [])

    def invoke(self, home, payload, *, execve=None, deadline=None, connected=False):
        with (
            input_pipe(payload, connected=connected) as reader,
            tempfile.TemporaryFile() as output,
            mock.patch.object(
                bootstrap, "actual_account", return_value=(home, os.getuid())
            ),
        ):
            result = bootstrap.bootstrap(
                reader, output.fileno(), execve=execve or mock.Mock(), deadline=deadline
            )
            output.seek(0)
            events = [json.loads(line) for line in output]
            return result, events

    def test_exact_frame_handoff_preserves_peer_input_and_exec_contract(self):
        entries = [(bootstrap.PEER, BENIGN), ("bin/gateway", b"owned candidate")]
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            observed = []
            peer_input = b'{"next":"peer manifest"}\n'
            with input_pipe(
                frame(manifest(home, entries), BENIGN + b"owned candidate") + peer_input
            ) as reader:

                def fake_exec(executable, argv, environment):
                    observed.append(
                        (executable, argv, environment, os.read(reader, 4096))
                    )
                    raise OSError("sensitive error must not leak")

                with (
                    tempfile.TemporaryFile() as output,
                    mock.patch.object(
                        bootstrap, "actual_account", return_value=(home, os.getuid())
                    ),
                    mock.patch.dict(os.environ, {"SECRET_CREDENTIAL": "never inherit"}),
                ):
                    self.assertEqual(
                        bootstrap.bootstrap(reader, output.fileno(), execve=fake_exec),
                        1,
                    )
                    output.seek(0)
                    events = [json.loads(line) for line in output]
            self.assertEqual(
                [e["event"] for e in events], ["bootstrap_ready", "bootstrap_failed"]
            )
            self.assertEqual(events[-1]["kind"], "bootstrap_io_failed")
            executable, argv, environment, remaining = observed[0]
            stage = home / ("gs-" + RUN_ID)
            self.assertEqual(remaining, peer_input)
            self.assertEqual(executable, sys.executable)
            self.assertEqual(
                argv,
                [
                    sys.executable,
                    "-I",
                    "-c",
                    bootstrap.LAUNCHER,
                    str(stage / "gateway/scripts"),
                    str(stage / bootstrap.PEER),
                ],
            )
            self.assertEqual(
                environment,
                {
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                    "LANG": "C",
                    "PYTHONIOENCODING": "utf-8",
                },
            )
            self.assertEqual(
                events[0],
                {
                    "event": "bootstrap_ready",
                    "schema_version": 1,
                    "python_executable": sys.executable,
                    "python_version": list(sys.version_info[:3]),
                    "run_id": RUN_ID,
                    "stage": str(stage),
                    "home": str(home),
                    "uid": os.getuid(),
                },
            )
            for path, data in entries:
                self.assertEqual((stage / path).read_bytes(), data)
                mode = 0o700 if path in bootstrap.CANDIDATES else 0o600
                self.assertEqual(stat.S_IMODE((stage / path).stat().st_mode), mode)
            for path in (
                stage,
                stage / "gateway",
                stage / "gateway/scripts",
                stage / "bin",
            ):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_allowlist_rejects_traversal_hidden_arbitrary_binary_and_sources(self):
        valid = [
            *bootstrap.CANDIDATES,
            *bootstrap.GATEWAY_SOURCES,
            *bootstrap.NATIVE_DATA_SOURCES,
            "native/scripts/__init__.py",
            "native/scripts/acceptance/__init__.py",
            "native/scripts/acceptance/private_cli/fixtures.py",
        ]
        invalid = [
            "/bin/gateway",
            "bin/../bin/gateway",
            "bin/pueue",
            "bin/gateway/evil",
            "gateway/scripts/e2e_recovery.py",
            "native/scripts/acceptance/.hidden.py",
            "native/scripts/acceptance/a-b.py",
            "native/scripts/acceptance/../x.py",
            "native/scripts/acceptance/x\x00.py",
            "native/scripts/acceptance/a.so",
            "native/scripts/acceptance//a.py",
            "native/scripts/acceptance/.x/a.py",
            "native/scripts/_data/other.json",
            "native/scripts/_data/unicode-simple-fold.json.bak",
            "native/scripts/acceptance/table.json",
            "native/scripts/_data/../unicode-simple-fold.json",
        ]
        for path in valid:
            with self.subTest(path=path):
                self.assertTrue(bootstrap.allowed_path(path))
        for path in invalid:
            with self.subTest(path=path):
                self.assertFalse(bootstrap.allowed_path(path))

    def test_exact_native_data_source_is_private_nonexecutable_and_integrity_checked(
        self,
    ):
        data_path = "native/scripts/_data/unicode-simple-fold.json"
        # A tiny fixture exercises transfer; it does not replace the Native table.
        data = b'{"fixture":"versioned source data"}\n'
        entries = [(bootstrap.PEER, BENIGN), (data_path, data)]
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            value = manifest(home, entries)
            execute = mock.Mock()
            result, events = self.invoke(
                home, frame(value, BENIGN + data), execve=execute
            )
            self.assertEqual(result, 1)
            self.assertEqual(events[0]["event"], "bootstrap_ready")
            self.assertEqual(events[-1]["kind"], "exec_returned")
            execute.assert_called_once()
            staged = home / ("gs-" + RUN_ID) / data_path
            self.assertEqual(staged.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o600)
            value["files"][-1]["executable"] = True
            with self.assertRaisesRegex(
                bootstrap.BootstrapFailure, "invalid_executable"
            ):
                bootstrap.validate_manifest(value, home, os.getuid())
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            execute = mock.Mock()
            result, events = self.invoke(
                home,
                frame(manifest(home, entries), BENIGN + b"x" * len(data)),
                execve=execute,
            )
            self.assertEqual(result, 1)
            self.assertEqual(events[0]["kind"], "hash_mismatch")
            self.assertTrue((home / ("gs-" + RUN_ID) / data_path).is_file())
            execute.assert_not_called()

    def test_invalid_metadata_never_creates_stage(self):
        mutations = [
            lambda m: m.update(expected_uid=True),
            lambda m: m.update(expected_uid=os.getuid() + 1),
            lambda m: m.update(expected_home=m["expected_home"] + "/other"),
            lambda m: m.update(schema_version=True),
            lambda m: m.update(run_id="../escape"),
            lambda m: m.update(files=[]),
            lambda m: m["files"].append(dict(m["files"][0])),
            lambda m: m["files"][0].update(path="../escape"),
            lambda m: m["files"][0].update(size=-1),
            lambda m: m["files"][0].update(size=True),
            lambda m: m["files"][0].update(size=bootstrap.MAX_FILE_BYTES + 1),
            lambda m: m["files"][0].update(executable=True),
            lambda m: m["files"][0].update(sha256="z" * 64),
            lambda m: m["files"][0].update(type="symlink"),
        ]
        for mutate in mutations:
            with (
                self.subTest(mutate=mutate),
                tempfile.TemporaryDirectory() as temporary,
            ):
                home = Path(temporary).resolve()
                value = manifest(home)
                mutate(value)
                execute = mock.Mock()
                result, events = self.invoke(home, frame(value), execve=execute)
                self.assertEqual(result, 1)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["event"], "bootstrap_failed")
                self.assertEqual(list(home.iterdir()), [])
                execute.assert_not_called()

    def test_total_and_file_count_bounds(self):
        value = manifest(Path("/home/example"))
        value["files"] *= bootstrap.MAX_FILES + 1
        with self.assertRaisesRegex(bootstrap.BootstrapFailure, "invalid_file_count"):
            bootstrap.validate_manifest(value, Path("/home/example"), os.getuid())
        value = manifest(Path("/home/example"), [(bootstrap.PEER, b"")])
        for path in bootstrap.CANDIDATES:
            value["files"].append(
                {
                    "path": path,
                    "size": bootstrap.MAX_FILE_BYTES,
                    "sha256": "0" * 64,
                    "executable": True,
                }
            )
        value["files"][0]["size"] = 1
        with self.assertRaisesRegex(bootstrap.BootstrapFailure, "total_size_exceeded"):
            bootstrap.validate_manifest(value, Path("/home/example"), os.getuid())

    def test_preexisting_stage_or_symlink_is_never_adopted(self):
        for symlink in (False, True):
            with (
                self.subTest(symlink=symlink),
                tempfile.TemporaryDirectory() as temporary,
            ):
                home = Path(temporary).resolve()
                stage = home / ("gs-" + RUN_ID)
                target = home / "existing"
                target.mkdir()
                marker = target / "marker"
                marker.write_bytes(b"unchanged")
                if symlink:
                    stage.symlink_to(target, target_is_directory=True)
                else:
                    stage.mkdir()
                result, events = self.invoke(home, frame(manifest(home)))
                self.assertEqual(result, 1)
                self.assertEqual(events[0]["kind"], "bootstrap_io_failed")
                self.assertEqual(marker.read_bytes(), b"unchanged")
                self.assertFalse((stage / "gateway").exists())

    def test_digest_or_truncation_retains_partial_stage_without_exec(self):
        for data, kind in [
            (b"x" * len(BENIGN), "hash_mismatch"),
            (b"short", "truncated_frame"),
        ]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                execute = mock.Mock()
                result, events = self.invoke(
                    home, frame(manifest(home), data), execve=execute
                )
                self.assertEqual(result, 1)
                self.assertEqual(events[0]["kind"], kind)
                self.assertEqual(len(events), 1)
                self.assertEqual(
                    (home / ("gs-" + RUN_ID) / bootstrap.PEER).read_bytes(), data
                )
                execute.assert_not_called()

    def test_header_eof_oversize_duplicate_keys_and_bad_json(self):
        duplicate = b'{"run_id":"a","run_id":"b"}'
        inputs = [
            b"",
            b"\x00\x00",
            struct.pack("!I", bootstrap.MAX_HEADER + 1),
            struct.pack("!I", len(duplicate)) + duplicate,
            struct.pack("!I", 1) + b"{",
            struct.pack("!I", 2) + b"\xff\xff",
        ]
        for data in inputs:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                result, events = self.invoke(home, data)
                self.assertEqual(result, 1)
                self.assertEqual(len(events), 1)
                self.assertLess(len(json.dumps(events[0])), bootstrap.MAX_EVENT)
                self.assertEqual(list(home.iterdir()), [])

    def test_connected_incomplete_input_has_one_finite_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            start = time.monotonic()
            result, events = self.invoke(
                home, frame(manifest(home), b""), connected=True, deadline=start + 0.03
            )
            self.assertEqual(result, 1)
            self.assertLess(time.monotonic() - start, 2)
            self.assertEqual(events[0]["kind"], "input_deadline")
            self.assertTrue((home / ("gs-" + RUN_ID)).is_dir())
        with input_pipe(b"ready") as reader:
            with self.assertRaisesRegex(bootstrap.BootstrapFailure, "input_deadline"):
                bootstrap.read_exact(reader, 1, deadline=5, clock=lambda: 6)

    def test_symlink_parent_and_file_overwrites_rejected_under_fd_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outside = root / "outside"
            outside.mkdir()
            stage = root / "stage"
            stage.mkdir()
            (stage / "gateway").symlink_to(outside, target_is_directory=True)
            parsed = bootstrap.validate_manifest(manifest(root), root, os.getuid())
            fd = bootstrap.open_directory(stage)
            try:
                with (
                    input_pipe(BENIGN) as reader,
                    ExitStack() as stack,
                    self.assertRaises(FileExistsError),
                ):
                    bootstrap.stage_files(
                        parsed, fd, reader, time.monotonic() + 2, directory_stack=stack
                    )
                self.assertEqual(list(outside.iterdir()), [])
            finally:
                os.close(fd)

    def test_observed_directory_replacement_before_ready_or_exec_refuses_handoff(self):
        for phase in ("after_staging", "during_ready"):
            for boundary in ("home", "stage", "gateway", "scripts"):
                with (
                    self.subTest(phase=phase, boundary=boundary),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    base = Path(temporary).resolve()
                    home = base / "home"
                    home.mkdir()
                    stage = home / ("gs-" + RUN_ID)
                    marker = base / "replacement-program-marker"
                    retained = base / "original-evidence"
                    replaced = {
                        "home": home,
                        "stage": stage,
                        "gateway": stage / "gateway",
                        "scripts": stage / "gateway/scripts",
                    }[boundary]
                    suffix = {
                        "home": Path("gs-" + RUN_ID) / bootstrap.PEER,
                        "stage": Path(bootstrap.PEER),
                        "gateway": Path("scripts/e2e_remote_peer.py"),
                        "scripts": Path("e2e_remote_peer.py"),
                    }[boundary]
                    replacement = b"# foreign replacement must never be selected\n"

                    def replace():
                        replaced.rename(retained)
                        peer = replaced / suffix
                        peer.parent.mkdir(parents=True)
                        peer.write_bytes(replacement)

                    actual_stage_files = bootstrap.stage_files
                    actual_emit = bootstrap.emit

                    def stage_then_replace(*args, **kwargs):
                        result = actual_stage_files(*args, **kwargs)
                        if phase == "after_staging":
                            replace()
                        return result

                    def replace_during_ready(fd, event, **kwargs):
                        if (
                            phase == "during_ready"
                            and event["event"] == "bootstrap_ready"
                        ):
                            replace()
                        return actual_emit(fd, event, **kwargs)

                    def would_select_replacement(*_args):
                        if (stage / bootstrap.PEER).read_bytes() == replacement:
                            marker.write_text("replacement selected")
                        raise OSError("test exec boundary")

                    execute = mock.Mock(side_effect=would_select_replacement)
                    with (
                        mock.patch.object(
                            bootstrap, "stage_files", side_effect=stage_then_replace
                        ),
                        mock.patch.object(
                            bootstrap, "emit", side_effect=replace_during_ready
                        ),
                    ):
                        result, events = self.invoke(
                            home, frame(manifest(home)), execve=execute
                        )
                    self.assertEqual(result, 1)
                    execute.assert_not_called()
                    self.assertFalse(marker.exists())
                    self.assertEqual((retained / suffix).read_bytes(), BENIGN)
                    self.assertEqual((replaced / suffix).read_bytes(), replacement)
                    self.assertEqual(events[-1]["kind"], "staging_binding_changed")
                    expected = (
                        ["bootstrap_failed"]
                        if phase == "after_staging"
                        else ["bootstrap_ready", "bootstrap_failed"]
                    )
                    self.assertEqual([event["event"] for event in events], expected)

    def test_file_replacement_or_rewrite_at_handoff_refuses_exec(self):
        for phase in ("after_staging", "during_ready"):
            for mutation in ("replace", "rewrite"):
                with (
                    self.subTest(phase=phase, mutation=mutation),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    home = Path(temporary).resolve()
                    peer = home / ("gs-" + RUN_ID) / bootstrap.PEER
                    retained = home / "retained-original-peer.py"
                    marker = home / "replacement-marker"
                    changed = b"x" * len(BENIGN)
                    actual_stage_files, actual_emit = (
                        bootstrap.stage_files,
                        bootstrap.emit,
                    )

                    def mutate():
                        if mutation == "replace":
                            peer.rename(retained)
                        peer.write_bytes(changed)

                    def stage_then_mutate(*args, **kwargs):
                        result = actual_stage_files(*args, **kwargs)
                        if phase == "after_staging":
                            mutate()
                        return result

                    def emit_then_mutate(fd, event, **kwargs):
                        result = actual_emit(fd, event, **kwargs)
                        if (
                            phase == "during_ready"
                            and event["event"] == "bootstrap_ready"
                        ):
                            mutate()
                        return result

                    def would_select_modified(*_args):
                        marker.write_text("modified peer selected")
                        raise OSError("test exec boundary")

                    execute = mock.Mock(side_effect=would_select_modified)
                    with (
                        mock.patch.object(
                            bootstrap, "stage_files", side_effect=stage_then_mutate
                        ),
                        mock.patch.object(
                            bootstrap, "emit", side_effect=emit_then_mutate
                        ),
                    ):
                        result, events = self.invoke(
                            home, frame(manifest(home)), execve=execute
                        )
                    self.assertEqual(result, 1)
                    execute.assert_not_called()
                    self.assertFalse(marker.exists())
                    self.assertEqual(peer.read_bytes(), changed)
                    if mutation == "replace":
                        self.assertEqual(retained.read_bytes(), BENIGN)
                    self.assertEqual(events[-1]["kind"], "staging_binding_changed")

    def test_unlisted_source_or_bytecode_before_ready_or_handoff_refuses_exec(self):
        for phase in ("after_staging", "during_ready"):
            for name in ("json.py", "__pycache__/e2e_local.cpython-312.pyc"):
                with (
                    self.subTest(phase=phase, name=name),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    home = Path(temporary).resolve()
                    stage = home / ("gs-" + RUN_ID)
                    unexpected = stage / "gateway/scripts" / name
                    marker = home / "unlisted-code-marker"
                    actual_stage_files, actual_emit = (
                        bootstrap.stage_files,
                        bootstrap.emit,
                    )

                    def plant():
                        unexpected.parent.mkdir(exist_ok=True)
                        unexpected.write_bytes(b"unlisted fixture bytes")

                    def stage_then_plant(*args, **kwargs):
                        result = actual_stage_files(*args, **kwargs)
                        if phase == "after_staging":
                            plant()
                        return result

                    def emit_then_plant(fd, event, **kwargs):
                        result = actual_emit(fd, event, **kwargs)
                        if (
                            phase == "during_ready"
                            and event["event"] == "bootstrap_ready"
                        ):
                            plant()
                        return result

                    def would_load_unlisted(*_args):
                        marker.write_text("unlisted code reachable")
                        raise OSError("test exec boundary")

                    execute = mock.Mock(side_effect=would_load_unlisted)
                    with (
                        mock.patch.object(
                            bootstrap, "stage_files", side_effect=stage_then_plant
                        ),
                        mock.patch.object(
                            bootstrap, "emit", side_effect=emit_then_plant
                        ),
                    ):
                        result, events = self.invoke(
                            home, frame(manifest(home)), execve=execute
                        )
                    self.assertEqual(result, 1)
                    execute.assert_not_called()
                    self.assertFalse(marker.exists())
                    self.assertEqual((stage / bootstrap.PEER).read_bytes(), BENIGN)
                    self.assertEqual(unexpected.read_bytes(), b"unlisted fixture bytes")
                    self.assertEqual(events[-1]["kind"], "staging_binding_changed")

    def test_mutation_during_final_rehash_refuses_exec(self):
        for mutation in ("same_size_rewrite", "stage_replace"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                home = Path(temporary).resolve()
                stage = home / ("gs-" + RUN_ID)
                peer = stage / bootstrap.PEER
                retained = home / "retained-original-stage"
                armed = False
                changed = False
                read_original_chunk = False
                actual_read, actual_emit = os.read, bootstrap.emit

                def arm_after_ready(fd, event, **kwargs):
                    nonlocal armed
                    result = actual_emit(fd, event, **kwargs)
                    if event["event"] == "bootstrap_ready":
                        armed = True
                    return result

                def mutate_after_read(fd, count):
                    nonlocal changed, read_original_chunk
                    chunk = actual_read(fd, count)
                    if armed and not changed:
                        info, selected = os.fstat(fd), peer.stat()
                        if (info.st_dev, info.st_ino) == (
                            selected.st_dev,
                            selected.st_ino,
                        ):
                            self.assertEqual(chunk, BENIGN)
                            read_original_chunk = True
                            changed = True
                            if mutation == "same_size_rewrite":
                                peer.write_bytes(b"x" * len(BENIGN))
                                # Force an independently distinct timestamp even on coarse filesystems.
                                os.utime(
                                    peer,
                                    ns=(
                                        selected.st_atime_ns,
                                        selected.st_mtime_ns + 1_000_000_000,
                                    ),
                                )
                            else:
                                stage.rename(retained)
                                peer.parent.mkdir(parents=True)
                                peer.write_bytes(b"foreign replacement source")
                    return chunk

                execute = mock.Mock()
                with (
                    mock.patch.object(
                        bootstrap.os, "read", side_effect=mutate_after_read
                    ),
                    mock.patch.object(bootstrap, "emit", side_effect=arm_after_ready),
                ):
                    result, events = self.invoke(
                        home, frame(manifest(home)), execve=execute
                    )
                self.assertEqual(result, 1)
                self.assertTrue(read_original_chunk)
                execute.assert_not_called()
                self.assertEqual(events[-1]["kind"], "staging_binding_changed")
                self.assertEqual(
                    [event["event"] for event in events],
                    ["bootstrap_ready", "bootstrap_failed"],
                )
                if mutation == "stage_replace":
                    self.assertEqual((retained / bootstrap.PEER).read_bytes(), BENIGN)
                    self.assertEqual(peer.read_bytes(), b"foreign replacement source")
                else:
                    self.assertEqual(peer.read_bytes(), b"x" * len(BENIGN))

    def test_every_owned_candidate_is_rechecked_for_content_mode_and_links(self):
        candidate_data = b"owned fixture candidate"
        for mutation in ("content", "mode", "hardlink", "symlink"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                home = Path(temporary).resolve()
                candidate = home / ("gs-" + RUN_ID) / "bin/delegate"
                entries = [(bootstrap.PEER, BENIGN), ("bin/delegate", candidate_data)]
                actual_stage_files = bootstrap.stage_files

                def mutate(*args, **kwargs):
                    result = actual_stage_files(*args, **kwargs)
                    if mutation == "content":
                        candidate.write_bytes(b"x" * len(candidate_data))
                    elif mutation == "mode":
                        candidate.chmod(0o600)
                    elif mutation == "hardlink":
                        os.link(candidate, home / "retained-link")
                    else:
                        retained = home / "retained-candidate"
                        candidate.rename(retained)
                        candidate.symlink_to(retained)
                    return result

                execute = mock.Mock()
                with mock.patch.object(bootstrap, "stage_files", side_effect=mutate):
                    result, events = self.invoke(
                        home,
                        frame(manifest(home, entries), BENIGN + candidate_data),
                        execve=execute,
                    )
                self.assertEqual(result, 1)
                self.assertEqual(events[0]["kind"], "staging_binding_changed")
                self.assertTrue(os.path.lexists(candidate))
                execute.assert_not_called()

    def test_handoff_rechecks_share_the_original_finite_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            expired = False
            actual_emit = bootstrap.emit

            def expire_during_ready(fd, event, **kwargs):
                nonlocal expired
                result = actual_emit(fd, event, **kwargs)
                if event["event"] == "bootstrap_ready":
                    expired = True
                return result

            execute = mock.Mock()
            with (
                input_pipe(frame(manifest(home))) as source,
                tempfile.TemporaryFile() as output,
                mock.patch.object(
                    bootstrap, "actual_account", return_value=(home, os.getuid())
                ),
                mock.patch.object(bootstrap, "emit", side_effect=expire_during_ready),
            ):
                result = bootstrap.bootstrap(
                    source,
                    output.fileno(),
                    execve=execute,
                    deadline=100,
                    clock=lambda: 101 if expired else 0,
                )
                output.seek(0)
                events = [json.loads(line) for line in output]
            self.assertEqual(result, 1)
            self.assertEqual(events[-1]["kind"], "handoff_deadline")
            self.assertEqual(
                (home / ("gs-" + RUN_ID) / bootstrap.PEER).read_bytes(), BENIGN
            )
            execute.assert_not_called()

    def test_unsupported_python_is_reported_before_staging_or_account_access(self):
        execute = mock.Mock()
        with (
            tempfile.TemporaryFile() as output,
            mock.patch.object(bootstrap.sys, "version_info", (3, 11, 9)),
            mock.patch.object(bootstrap, "actual_account") as account,
        ):
            self.assertEqual(
                bootstrap.bootstrap(output_fd=output.fileno(), execve=execute), 1
            )
            output.seek(0)
            event = json.loads(output.read())
        self.assertEqual(
            event,
            {
                "event": "bootstrap_failed",
                "schema_version": 1,
                "kind": "unsupported_python",
                "python_executable": sys.executable,
                "python_version": [3, 11, 9],
            },
        )
        account.assert_not_called()
        execute.assert_not_called()

    def test_visible_launcher_symlink_is_refused_without_adopting_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            stage = home / ("gs-" + RUN_ID)
            retained = home / "retained-original-gateway"
            actual_stage_files = bootstrap.stage_files

            def replace_with_alias(*args, **kwargs):
                result = actual_stage_files(*args, **kwargs)
                (stage / "gateway").rename(retained)
                (stage / "gateway").symlink_to(retained, target_is_directory=True)
                return result

            execute = mock.Mock()
            with mock.patch.object(
                bootstrap, "stage_files", side_effect=replace_with_alias
            ):
                result, events = self.invoke(
                    home, frame(manifest(home)), execve=execute
                )
            self.assertEqual(result, 1)
            self.assertEqual(events[0]["kind"], "staging_binding_changed")
            self.assertTrue((stage / "gateway").is_symlink())
            self.assertEqual(
                (retained / "scripts/e2e_remote_peer.py").read_bytes(), BENIGN
            )
            execute.assert_not_called()

    def test_home_symlink_loop_is_a_bounded_binding_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            home = base / "home"
            home.mkdir()
            retained = base / "retained-home"
            actual_stage_files = bootstrap.stage_files

            def replace_with_loop(*args, **kwargs):
                result = actual_stage_files(*args, **kwargs)
                home.rename(retained)
                home.symlink_to(home, target_is_directory=True)
                return result

            execute = mock.Mock()
            with mock.patch.object(
                bootstrap, "stage_files", side_effect=replace_with_loop
            ):
                result, events = self.invoke(
                    home, frame(manifest(home)), execve=execute
                )
            self.assertEqual(result, 1)
            self.assertEqual(events[0]["kind"], "staging_binding_changed")
            self.assertTrue(home.is_symlink())
            self.assertEqual(
                (retained / ("gs-" + RUN_ID) / bootstrap.PEER).read_bytes(), BENIGN
            )
            execute.assert_not_called()

    def test_publication_restores_borrowed_flags_and_types_partial_output_faults(self):
        for blocking in (False, True):
            with self.subTest(blocking=blocking):
                reader, writer = os.pipe()
                try:
                    os.set_blocking(writer, blocking)
                    actual_write = os.write
                    with mock.patch.object(
                        bootstrap.os,
                        "write",
                        side_effect=lambda fd, data: actual_write(fd, data[:3]),
                    ):
                        bootstrap.emit(writer, {"event": "small"})
                    self.assertEqual(os.read(reader, 4096), b'{"event":"small"}\n')
                    self.assertEqual(os.get_blocking(writer), blocking)
                    with mock.patch.object(bootstrap.os, "write", return_value=0):
                        with self.assertRaisesRegex(
                            bootstrap.BootstrapFailure, "publication_no_progress"
                        ):
                            bootstrap.emit(writer, {"event": "small"})
                    self.assertEqual(os.get_blocking(writer), blocking)
                    os.close(reader)
                    reader = None
                    with self.assertRaisesRegex(
                        bootstrap.BootstrapFailure, "publication_io_failed"
                    ):
                        bootstrap.emit(writer, {"event": "small"})
                    self.assertEqual(os.get_blocking(writer), blocking)
                finally:
                    if reader is not None:
                        os.close(reader)
                    os.close(writer)

    def test_account_resolution_rejects_symlink_home_and_effective_uid_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            alias = home / "alias"
            alias.symlink_to(home, target_is_directory=True)
            with mock.patch.object(
                bootstrap.pwd, "getpwuid", return_value=mock.Mock(pw_dir=str(alias))
            ):
                with self.assertRaisesRegex(
                    bootstrap.BootstrapFailure, "noncanonical_home"
                ):
                    bootstrap.actual_account()
            with mock.patch.object(
                bootstrap.os, "geteuid", return_value=os.getuid() + 1
            ):
                with self.assertRaisesRegex(
                    bootstrap.BootstrapFailure, "account_mismatch"
                ):
                    bootstrap.actual_account()

    def test_streams_multiple_chunks_and_fsync_failure_prevents_handoff(self):
        data = b"owned candidate chunk\x00" * 8192
        entries = [(bootstrap.PEER, BENIGN), ("bin/delegate", data)]
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
                source.write(frame(manifest(home, entries), BENIGN + data))
                source.seek(0)
                execute = mock.Mock(side_effect=OSError("private exec fault"))
                with mock.patch.object(
                    bootstrap, "actual_account", return_value=(home, os.getuid())
                ):
                    self.assertEqual(
                        bootstrap.bootstrap(
                            source.fileno(), output.fileno(), execve=execute
                        ),
                        1,
                    )
                self.assertEqual(
                    (home / ("gs-" + RUN_ID) / "bin/delegate").read_bytes(), data
                )
                execute.assert_called_once()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            execute = mock.Mock()
            with mock.patch.object(
                bootstrap.os, "fsync", side_effect=OSError("private disk fault")
            ):
                result, events = self.invoke(
                    home, frame(manifest(home)), execve=execute
                )
            self.assertEqual(result, 1)
            self.assertEqual([event["event"] for event in events], ["bootstrap_failed"])
            self.assertEqual(
                (home / ("gs-" + RUN_ID) / bootstrap.PEER).read_bytes(), BENIGN
            )
            execute.assert_not_called()


class MaintainedProcessTests(unittest.TestCase):
    def test_full_output_pipe_bounds_publication_without_exec_and_retains_stage(self):
        repository = os.environ.get("DELEGATE_ACCEPTANCE_REPOSITORY")
        if not repository:
            self.skipTest(
                "set DELEGATE_ACCEPTANCE_REPOSITORY for maintained process owner"
            )
        import e2e_local

        acceptance = e2e_local.load_acceptance(Path(repository))
        root = Path(tempfile.mkdtemp(prefix="bootstrap-full-output-test-")).resolve()
        processes = acceptance.processes.Processes(
            root / "captures", environment={"PATH": "/usr/bin:/bin"}
        )
        try:
            home = root / "home"
            home.mkdir()
            wrapper = root / "standin.py"
            wrapper.write_text(
                "import json,os,signal,sys,time\nfrom pathlib import Path\n"
                "sys.path.insert(0,sys.argv[1])\nimport e2e_remote_bootstrap as b\n"
                "home=Path(sys.argv[2])\n"
                "b.actual_account=lambda:(home,os.getuid())\n"
                "b.OUTPUT_TIMEOUT=0.03\n"
                "reader,writer=os.pipe()\nos.set_blocking(writer,False)\n"
                "try:\n"
                "    while True: os.write(writer,b'x'*4096)\n"
                "except BlockingIOError: pass\n"
                "os.set_blocking(writer,True)\n"
                # Test-only watchdog makes the old blocking implementation finite.
                # It owns no child and never signals another process.
                "def watchdog(*_): raise SystemExit(4)\n"
                "signal.signal(signal.SIGALRM,watchdog)\nsignal.alarm(2)\n"
                "calls=[]\n"
                "def fake_exec(*args): calls.append(args)\n"
                "start=time.monotonic()\n"
                "try:\n"
                "    result=b.bootstrap(output_fd=writer,execve=fake_exec)\n"
                "    restored=os.get_blocking(writer)\n"
                "finally:\n"
                "    signal.alarm(0)\n    os.close(writer)\n    os.close(reader)\n"
                "stage=home/('gs-'+sys.argv[3])\n"
                "print(json.dumps({'result':result,'elapsed':time.monotonic()-start,"
                "'restored':restored,'exec_calls':len(calls),'stage':str(stage)}))\n"
            )
            process = processes.start(
                "bootstrap-full-output",
                [
                    sys.executable,
                    "-I",
                    wrapper,
                    Path(__file__).resolve().parent,
                    home,
                    RUN_ID,
                ],
                root,
                stdin=frame(manifest(home)),
            )
            process.wait(5, expected=0)
            report = json.loads(process.stdout_path.read_bytes())
            self.assertEqual(report["result"], 1)
            self.assertLess(report["elapsed"], 1)
            self.assertTrue(report["restored"])
            self.assertEqual(report["exec_calls"], 0)
            self.assertEqual(report["stage"], str(home / ("gs-" + RUN_ID)))
            self.assertEqual(
                (Path(report["stage"]) / bootstrap.PEER).read_bytes(), BENIGN
            )
        finally:
            pending = processes.drain(timeout=5)
            if not pending and processes.finished_naturally():
                shutil.rmtree(root)
            else:
                self.fail("owned child closure unconfirmed; retained " + str(root))

    def test_finite_bootstrap_standin_is_owned_and_waited_without_executing_peer(self):
        repository = os.environ.get("DELEGATE_ACCEPTANCE_REPOSITORY")
        if not repository:
            self.skipTest(
                "set DELEGATE_ACCEPTANCE_REPOSITORY for maintained process owner"
            )
        import e2e_local

        acceptance = e2e_local.load_acceptance(Path(repository))
        root = Path(tempfile.mkdtemp(prefix="bootstrap-test-")).resolve()
        processes = acceptance.processes.Processes(
            root / "captures", environment={"PATH": "/usr/bin:/bin"}
        )
        try:
            home = root / "home"
            home.mkdir()
            wrapper = root / "standin.py"
            wrapper.write_text(
                "import os,sys,time\nfrom pathlib import Path\n"
                "sys.path.insert(0,sys.argv[1])\nimport e2e_remote_bootstrap as b\n"
                "b.actual_account=lambda:(Path(sys.argv[2]),os.getuid())\n"
                "def fake_exec(*args):\n"
                "    assert os.read(0,4096)==b'peer-next\\n'\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(b.bootstrap(execve=fake_exec,deadline=time.monotonic()+1))\n"
            )
            process = processes.start(
                "bootstrap-standin",
                [sys.executable, "-I", wrapper, Path(__file__).resolve().parent, home],
                root,
                stdin=frame(manifest(home)) + b"peer-next\n",
            )
            process.wait(5, expected=0)
            events = [
                json.loads(line)
                for line in process.stdout_path.read_bytes().splitlines()
            ]
            self.assertEqual([event["event"] for event in events], ["bootstrap_ready"])
            self.assertEqual(
                (home / ("gs-" + RUN_ID) / bootstrap.PEER).read_bytes(), BENIGN
            )
        finally:
            pending = processes.drain(timeout=5)
            # Remove only this creator's paths after every owned child was Waited.
            if not pending and processes.finished_naturally():
                shutil.rmtree(root)
            else:
                self.fail("owned child closure unconfirmed; retained " + str(root))


if __name__ == "__main__":
    unittest.main()
