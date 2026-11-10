"""Protect source provenance and owned-child cleanup without running browsers."""

from __future__ import annotations

import json
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

import render_diagrams as render


class SourceGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.source = Path(directory.name)
        (self.source / "archify").mkdir()
        (self.source / "archify/package.json").write_text(
            json.dumps({"version": "3.2.0"})
        )
        self.patch = self.source / "maintained.patch"
        self.patch.write_text("maintained patch\n")
        self.observed = {
            "revision": render.REVISION,
            "origin": render.REMOTE,
            "changed": "\n".join(render.PATCHED),
            "untracked": "",
            "patch": self.patch.read_text(),
        }
        self.addCleanup(patch.stopall)
        patch.object(render, "SOURCE", self.source).start()
        patch.object(render, "PATCH", self.patch).start()
        patch.object(render, "run", side_effect=self.command).start()

    def command(self, args: list[str], **_kwargs: object) -> str:
        if args[0] == "node":
            return ""
        if args[1] == "rev-parse":
            return self.observed["revision"]
        if args[1] == "remote":
            return self.observed["origin"]
        if args[1] == "ls-files":
            return self.observed["untracked"]
        if "--name-only" in args:
            return self.observed["changed"]
        return self.observed["patch"]

    def test_matching_owned_source_is_accepted(self) -> None:
        self.assertEqual(render.candidate(), self.source / "archify/bin/archify.mjs")

    def test_wrong_or_ambiguous_source_is_rejected(self) -> None:
        for field, bad in {
            "revision": "wrong",
            "origin": "https://attacker.invalid/source",
            "changed": "unrelated.js",
            "untracked": "unreviewed.js",
            "patch": "extra edits",
        }.items():
            with self.subTest(field=field):
                original = self.observed[field]
                self.observed[field] = bad
                with self.assertRaises(RuntimeError):
                    render.candidate()
                self.observed[field] = original


class ChildCleanupTests(unittest.TestCase):
    def test_signal_during_child_handle_acquisition_is_deferred_until_cleanup(
        self,
    ) -> None:
        render.adopt_owned_orphans()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "started"
            wrapper = """
import os,pathlib,signal,sys
sys.path.insert(0,sys.argv[1])
import render_diagrams as r
original=r.subprocess.Popen
def spawn(*args,**kwargs):
    child=original(*args,**kwargs)
    pathlib.Path(sys.argv[2]).write_text(str(child.pid))
    os.kill(os.getpid(),signal.SIGTERM)
    return child
r.subprocess.Popen=spawn
signal.signal(signal.SIGTERM,r.interrupted)
r.run([sys.executable,'-c','import time; time.sleep(300)'])
"""
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    wrapper,
                    str(render.ROOT / "scripts"),
                    str(marker),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                process.communicate(timeout=10)
                self.assertTrue(marker.exists(), "Start boundary was not exercised")
                self.assertNotEqual(process.returncode, 0)
                self.assertFalse(
                    render.group_exists(int(marker.read_text())),
                    "interruption escaped child acquisition without joining it",
                )
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=10)
                if marker.exists():
                    group = int(marker.read_text())
                    try:
                        os.killpg(group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    render.reap_group(group, wait=True)

    def test_interruption_at_normal_reaping_still_joins_group(self) -> None:
        child = MagicMock()
        child.pid = 123
        child.communicate.return_value = ("", "")
        with (
            patch.object(render.subprocess, "Popen") as popen,
            patch.object(render, "reap_group", side_effect=[KeyboardInterrupt, None]),
            patch.object(render, "group_exists", return_value=False),
            patch.object(render.os, "killpg") as kill,
            patch.object(render.time, "sleep"),
        ):
            popen.return_value = child
            with self.assertRaises(KeyboardInterrupt):
                render.run(["owned-child"])
        self.assertEqual(
            [call.args[1] for call in kill.call_args_list],
            [signal.SIGTERM, signal.SIGKILL],
        )
        self.assertEqual(child.communicate.call_count, 2)

    def test_normal_cli_exit_cannot_hide_a_stubborn_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant"
            descendant = "import os,pathlib,signal,sys; signal.signal(signal.SIGTERM,signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text(str(os.getpid())+' '+str(os.getpgrp())); signal.pause()"
            leader = "import pathlib,subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nwhile not pathlib.Path(sys.argv[2]).exists(): time.sleep(.01)\n"
            try:
                self.assertEqual(
                    render.run([sys.executable, "-c", leader, descendant, str(marker)]),
                    "",
                )
                pid, _group = marker.read_text().split()
                deadline = time.monotonic() + 5
                state = ""
                while time.monotonic() < deadline:
                    state = subprocess.run(
                        ["ps", "-o", "stat=", "-p", pid],
                        capture_output=True,
                        text=True,
                        timeout=2,
                        check=False,
                    ).stdout.strip()
                    if not state or state.startswith("Z"):
                        break
                    time.sleep(0.01)
                self.assertTrue(
                    not state,
                    "normal-exit descendant survived",
                )
            finally:
                if marker.exists():
                    _pid, group = marker.read_text().split()
                    try:
                        os.killpg(int(group), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_real_sigterm_joins_child_before_releasing_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, stopped = root / "ready", root / "stopped"
            child_code = (
                "import os,pathlib,signal,sys; "
                "ready,stopped=map(pathlib.Path,sys.argv[1:]); "
                "signal.signal(signal.SIGTERM,lambda *_:(stopped.write_text('closed'),sys.exit(0))); "
                "ready.write_text(str(os.getpid())); signal.pause()"
            )
            wrapper = (
                "import pathlib,sys; "
                "sys.path.insert(0,sys.argv[1]); import render_diagrams as r; "
                "r.ROOT=pathlib.Path(sys.argv[2]); "
                "r.render=lambda:r.run([sys.executable,'-c',sys.argv[3],sys.argv[4],sys.argv[5]]); "
                "r.main()"
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    wrapper,
                    str(render.ROOT / "scripts"),
                    directory,
                    child_code,
                    str(ready),
                    str(stopped),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(
                    ready.exists(), "owned child failed to reach ready gate"
                )
                lease = root / ".local/render-diagrams.lock"
                with lease.open("a") as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    process.terminate()
                    process.communicate(timeout=10)
                    self.assertTrue(
                        stopped.exists(), "wrapper exited without joining owned child"
                    )
                    self.assertNotEqual(process.returncode, -signal.SIGTERM)
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                if process.poll() is None:
                    process.kill()
                if ready.exists() and not stopped.exists():
                    try:
                        os.killpg(int(ready.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.communicate(timeout=10)

    def test_terminal_signal_uses_interruption_path(self) -> None:
        for terminating_signal in (signal.SIGTERM, signal.SIGHUP):
            with self.assertRaises(KeyboardInterrupt):
                render.interrupted(terminating_signal, None)

    def test_interrupted_child_is_terminated_and_joined(self) -> None:
        child = MagicMock()
        child.pid = 123
        child.communicate.side_effect = [KeyboardInterrupt, ("", "")]
        with (
            patch.object(render.subprocess, "Popen") as popen,
            patch.object(render.os, "killpg") as kill,
            patch.object(render.time, "sleep"),
            patch.object(render, "group_exists", return_value=False),
            patch.object(render, "reap_group"),
        ):
            popen.return_value = child
            with self.assertRaises(KeyboardInterrupt):
                render.run(["owned-child"])
        self.assertEqual(
            [call.args[1] for call in kill.call_args_list],
            [signal.SIGTERM, signal.SIGKILL],
        )
        self.assertEqual(child.communicate.call_count, 2)

    def test_failed_graceful_stop_escalates_and_joins(self) -> None:
        child = MagicMock()
        child.pid = 123
        child.communicate.side_effect = [
            subprocess.TimeoutExpired("owned-child", 300),
            ("", ""),
        ]
        with (
            patch.object(render.subprocess, "Popen") as popen,
            patch.object(render.os, "killpg") as kill,
            patch.object(render.time, "sleep"),
            patch.object(render, "group_exists", return_value=False),
            patch.object(render, "reap_group"),
        ):
            popen.return_value = child
            with self.assertRaises(subprocess.TimeoutExpired):
                render.run(["owned-child"])
        self.assertEqual(
            [call.args[1] for call in kill.call_args_list],
            [signal.SIGTERM, signal.SIGKILL],
        )
        self.assertEqual(child.communicate.call_count, 2)

    def test_cleanup_blocks_repeated_interrupts_until_join(self) -> None:
        child = MagicMock()
        child.pid = 123
        with (
            patch.object(render.os, "killpg"),
            patch.object(render.time, "sleep"),
            patch.object(render.signal, "pthread_sigmask") as mask,
            patch.object(render, "group_exists", return_value=False),
            patch.object(render, "reap_group"),
        ):
            mask.return_value = set()
            render.stop_owned_group(child)
        self.assertEqual(mask.call_args_list[0].args[0], signal.SIG_BLOCK)
        self.assertEqual(mask.call_args_list[-1].args[0], signal.SIG_SETMASK)
        child.communicate.assert_called_once()

    def test_stubborn_descendant_with_closed_pipes_is_killed(self) -> None:
        render.adopt_owned_orphans()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant"
            descendant = "import os,pathlib,signal,sys; signal.signal(signal.SIGTERM,signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); signal.pause()"
            leader = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(300)"
            child = subprocess.Popen(
                [sys.executable, "-c", leader, descendant, str(marker)],
                start_new_session=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists())
                render.stop_owned_group(child)
                pid = marker.read_text()
                deadline = time.monotonic() + 5
                state = ""
                while time.monotonic() < deadline:
                    state = subprocess.run(
                        ["ps", "-o", "stat=", "-p", pid],
                        capture_output=True,
                        text=True,
                        timeout=2,
                        check=False,
                    ).stdout.strip()
                    if not state or state.startswith("Z"):
                        break
                    time.sleep(0.01)
                self.assertTrue(
                    not state or state.startswith("Z"),
                    f"owned descendant survived: {state}",
                )
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
