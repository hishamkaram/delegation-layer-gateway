"""Protect source provenance and owned-child cleanup without running browsers."""

from __future__ import annotations

from builtins import BaseExceptionGroup
from collections.abc import Iterator
from contextlib import contextmanager

import json
import errno
from types import SimpleNamespace
import fcntl
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

import render_diagrams as render


@contextmanager
def actor_directory() -> Iterator[str]:
    """Remove actor evidence only after the complete test proves closure."""
    directory = Path(tempfile.mkdtemp(prefix="renderer-actor-"))
    try:
        yield str(directory)
    except BaseException as error:
        error.add_note(
            "Actor evidence retained; closure may be unknown: " + str(directory)
        )
        raise
    else:
        shutil.rmtree(directory)


class ActorDirectoryTests(unittest.TestCase):
    def test_failed_scope_retains_evidence_and_original_error(self):
        failure = RuntimeError("controlled sentinel failure; no actor started")
        with self.assertRaises(RuntimeError) as caught:
            with actor_directory() as directory:
                retained = Path(directory)
                # This regression owns only an ordinary file, so removing it
                # after proof cannot discard evidence for an unresolved actor.
                self.addCleanup(shutil.rmtree, retained)
                (retained / "sentinel").write_text("evidence")
                raise failure
        self.assertIs(caught.exception, failure)
        self.assertEqual((retained / "sentinel").read_text(), "evidence")
        self.assertIn(str(retained), " ".join(failure.__notes__))

    def test_successful_scope_removes_evidence(self):
        with actor_directory() as directory:
            removed = Path(directory)
            (removed / "sentinel").write_text("no actor started")
        self.assertFalse(removed.exists())


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
        with actor_directory() as directory:
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
                    render.reap_group(group)

    def test_normal_cli_exit_cannot_hide_a_stubborn_descendant(self) -> None:
        with actor_directory() as directory:
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
                    render.reap_group(int(group))

    def test_real_sigterm_joins_child_before_releasing_lease(self) -> None:
        with actor_directory() as directory:
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
                # The wrapper owns its child group. Its PID anchor may already
                # be released here, so never signal a saved descendant number.
                process.communicate(timeout=10)

    def test_terminal_signal_uses_interruption_path(self) -> None:
        for terminating_signal in (signal.SIGTERM, signal.SIGHUP):
            with self.assertRaises(KeyboardInterrupt):
                render.interrupted(terminating_signal, None)

    def test_stubborn_descendant_with_closed_pipes_is_killed(self) -> None:
        render.adopt_owned_orphans()
        with actor_directory() as directory:
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
            cleanup_attempted = False
            try:
                deadline = time.monotonic() + 10
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists())
                cleanup_attempted = True
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
                if not cleanup_attempted:
                    render.stop_owned_group(child)
                if child.returncode is None:
                    raise RuntimeError("owned fixture child closure unknown")
                child.communicate(timeout=10)


class OwnershipBoundaryTests(unittest.TestCase):
    def child(self):
        child = MagicMock()
        child.pid = 123
        child.args = ["owned-child"]
        child.returncode = None

        def joined(**_kwargs):
            child.returncode = 0
            return 0

        child.wait.side_effect = joined
        return child

    def test_real_text_input_output_newlines_and_nonzero_exit(self):
        source = "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read()+b'\\r\\ntail\\r');sys.stderr.write('error')"
        self.assertEqual(
            render.run([sys.executable, "-c", source], stdin="input\n"),
            "input\n\ntail\n",
        )
        with self.assertRaisesRegex(RuntimeError, r"failed \(7\).*diagnostic"):
            render.run(
                [
                    sys.executable,
                    "-c",
                    "import sys;sys.stderr.write('diagnostic');sys.exit(7)",
                ]
            )

    def test_private_stdio_files_preserve_actual_text_behavior(self):
        spawn = render.subprocess.Popen

        def checked_spawn(*args, **kwargs):
            for name in ("stdin", "stdout", "stderr"):
                self.assertEqual(os.fstat(kwargs[name].fileno()).st_mode & 0o777, 0o600)
            return spawn(*args, **kwargs)

        with patch.object(render.subprocess, "Popen", side_effect=checked_spawn):
            self.assertEqual(
                render.run(
                    [sys.executable, "-c", "import sys;print(sys.stdin.read(),end='')"],
                    stdin="private",
                ),
                "private",
            )

    def test_wait_failure_never_reenters_group_mutation(self):
        child = self.child()
        child.wait.side_effect = subprocess.TimeoutExpired("owned-child", 5)
        with (
            patch.object(render.os, "killpg") as kill,
            patch.object(render.time, "sleep"),
        ):
            with self.assertRaises(BaseExceptionGroup):
                render.stop_owned_group(child)
        self.assertEqual(
            [call.args[1] for call in kill.call_args_list],
            [signal.SIGTERM, signal.SIGKILL],
        )
        child.wait.assert_called_once()

    def test_group_mutations_precede_exact_wait_and_esrch_latches(self):
        for absent_on_term in (False, True):
            with self.subTest(absent_on_term=absent_on_term):
                child = self.child()
                order = []

                def signal_group(_pid, number):
                    order.append(number)
                    if absent_on_term or number == 0:
                        raise ProcessLookupError(errno.ESRCH, "absent")

                def joined(**_kwargs):
                    order.append("wait")
                    child.returncode = 0
                    return 0

                child.wait.side_effect = joined
                with (
                    patch.object(render.os, "killpg", side_effect=signal_group),
                    patch.object(render.time, "sleep"),
                    patch.object(render, "reap_group"),
                ):
                    render.stop_owned_group(child)
                self.assertEqual(
                    order,
                    [signal.SIGTERM, "wait"]
                    if absent_on_term
                    else [signal.SIGTERM, signal.SIGKILL, "wait", 0],
                )
                child.wait.assert_called_once()

    def test_signal_fault_cannot_skip_wait_and_prior_fault_is_preserved(self):
        child = self.child()
        with (
            patch.object(
                render.os,
                "killpg",
                side_effect=[
                    OSError(errno.EIO, "signal fault"),
                    None,
                    ProcessLookupError(),
                ],
            ),
            patch.object(render.time, "sleep"),
            patch.object(render, "reap_group"),
        ):
            with self.assertRaisesRegex(OSError, "signal fault"):
                render.stop_owned_group(child)
        child.wait.assert_called_once()

    def test_permission_fault_resolves_only_with_wait_and_group_absence(self):
        child = self.child()
        with (
            patch.object(
                render.os,
                "killpg",
                side_effect=[
                    PermissionError(errno.EPERM, "term"),
                    PermissionError(errno.EPERM, "kill"),
                    ProcessLookupError(),
                ],
            ),
            patch.object(render.time, "sleep"),
            patch.object(render, "reap_group"),
        ):
            diagnostics = render.stop_owned_group(child)
        self.assertEqual(len(diagnostics), 2)
        child.wait.assert_called_once()
        child = self.child()
        with (
            patch.object(
                render.os,
                "killpg",
                side_effect=PermissionError(errno.EPERM, "persistent"),
            ),
            patch.object(render.time, "sleep"),
            patch.object(render.time, "monotonic", side_effect=[0, 0, 0, 6]),
            patch.object(render, "reap_group"),
        ):
            with self.assertRaises(BaseExceptionGroup) as caught:
                render.stop_owned_group(child)
        self.assertIn("closure unknown", str(caught.exception.exceptions[-1]))
        child.wait.assert_called_once()

    def test_identity_loss_forbids_numeric_group_signals(self):
        child = self.child()
        with patch.object(render.os, "killpg") as kill:
            with self.assertRaisesRegex(RuntimeError, "closure unknown"):
                render.stop_owned_group(child, identity_lost=True)
        kill.assert_not_called()
        child.wait.assert_called_once()

    def test_observer_fault_enters_cleanup_once_and_closes_watcher(self):
        child = self.child()
        observer = MagicMock()
        observer.wait.side_effect = OSError(errno.EIO, "observer fault")
        with (
            patch.object(render, "ExitObserver", return_value=observer),
            patch.object(render.subprocess, "Popen", return_value=child),
            patch.object(render, "stop_owned_group") as cleanup,
        ):
            with self.assertRaisesRegex(OSError, "observer fault"):
                render.run(["owned-child"])
        cleanup.assert_called_once_with(child, identity_lost=False)
        observer.close.assert_called_once()

    def test_echild_observation_enters_safe_cleanup(self):
        child = self.child()
        observer = MagicMock()
        observer.wait.side_effect = ChildProcessError(errno.ECHILD, "already reaped")
        with (
            patch.object(render, "ExitObserver", return_value=observer),
            patch.object(render.subprocess, "Popen", return_value=child),
            patch.object(render, "stop_owned_group") as cleanup,
        ):
            with self.assertRaises(ChildProcessError):
                render.run(["owned-child"])
        cleanup.assert_called_once_with(child, identity_lost=True)

    def test_cleanup_and_watcher_faults_preserve_primary(self):
        child = self.child()
        observer = MagicMock()
        observer.wait.side_effect = KeyboardInterrupt()
        observer.close.side_effect = OSError("watcher close")
        with (
            patch.object(render, "ExitObserver", return_value=observer),
            patch.object(render.subprocess, "Popen", return_value=child),
            patch.object(
                render, "stop_owned_group", side_effect=RuntimeError("cleanup")
            ) as cleanup,
        ):
            with self.assertRaises(BaseExceptionGroup) as caught:
                render.run(["owned-child"])
        self.assertIsInstance(caught.exception.exceptions[0], KeyboardInterrupt)
        self.assertEqual(
            [str(error) for error in caught.exception.exceptions[1:]],
            ["cleanup", "watcher close"],
        )
        cleanup.assert_called_once()

    def test_sigchld_policy_refused_before_spawn(self):
        for policy in (signal.SIG_IGN, lambda *_: None):
            with (
                patch.object(render.signal, "getsignal", return_value=policy),
                patch.object(render.subprocess, "Popen") as spawn,
            ):
                with self.assertRaisesRegex(RuntimeError, "default SIGCHLD"):
                    render.run(["owned-child"])
            spawn.assert_not_called()

    def test_default_sigchld_reinstalled_before_spawn(self):
        child = self.child()
        observer = MagicMock()
        with (
            patch.object(render.signal, "signal", wraps=signal.signal) as installed,
            patch.object(render, "ExitObserver", return_value=observer),
            patch.object(render.subprocess, "Popen", return_value=child) as spawn,
            patch.object(render, "stop_owned_group"),
        ):

            def started(*_args, **_kwargs):
                self.assertEqual(
                    installed.call_args_list[0].args, (signal.SIGCHLD, signal.SIG_DFL)
                )
                return child

            spawn.side_effect = started
            render.run(["owned-child"])

    def test_command_failure_preserved_alongside_cleanup_fault(self):
        original = render.os.killpg

        def signal_group(pid, number):
            if number == signal.SIGTERM:
                raise OSError(errno.EIO, "injected TERM fault")
            return original(pid, number)

        with patch.object(render.os, "killpg", side_effect=signal_group):
            with self.assertRaises(BaseExceptionGroup) as caught:
                render.run([sys.executable, "-c", "import sys;sys.exit(7)"])
        self.assertIn("injected TERM fault", str(caught.exception.exceptions[0]))
        self.assertIn("failed (7)", str(caught.exception.exceptions[1]))

    def test_real_timeout_uses_bounded_cleanup(self):
        with patch.object(render, "RUN_SECONDS", 0.05):
            with self.assertRaises(subprocess.TimeoutExpired):
                render.run([sys.executable, "-c", "import time;time.sleep(300)"])

    def test_cleanup_restoration_fault_preserved_after_wait(self):
        child = self.child()
        with (
            patch.object(render.os, "killpg", side_effect=ProcessLookupError()),
            patch.object(
                render.signal,
                "pthread_sigmask",
                side_effect=[set(), OSError("mask restore")],
            ),
        ):
            with self.assertRaisesRegex(OSError, "mask restore"):
                render.stop_owned_group(child)
        child.wait.assert_called_once()

    def test_main_thread_required_before_spawn(self):
        with (
            patch.object(render.threading, "current_thread", return_value=object()),
            patch.object(render.subprocess, "Popen") as spawn,
        ):
            with self.assertRaisesRegex(RuntimeError, "main thread"):
                render.run(["owned-child"])
        spawn.assert_not_called()

    def test_darwin_registration_esrch_is_exit_not_group_absence(self):
        watcher = MagicMock()
        watcher.control.side_effect = ProcessLookupError(errno.ESRCH, "exited")
        constants = {
            "kqueue": MagicMock(return_value=watcher),
            "kevent": MagicMock(),
            "KQ_FILTER_PROC": -5,
            "KQ_NOTE_EXIT": 0x80000000,
            "KQ_EV_ADD": 1,
            "KQ_EV_ONESHOT": 16,
            "KQ_EV_ERROR": 0x4000,
        }
        with (
            patch.object(render.sys, "platform", "darwin"),
            patch.multiple(render.select, create=True, **constants),
        ):
            observer = render.ExitObserver()
            try:
                observer.wait(self.child(), 1)
                self.assertEqual(watcher.control.call_args.args[1:], (0, 0))
            finally:
                observer.close()
        watcher.close.assert_called_once()

    def test_darwin_validates_exit_event_and_registration_errors(self):
        constants = {
            "kqueue": MagicMock(),
            "kevent": MagicMock(),
            "KQ_FILTER_PROC": -5,
            "KQ_NOTE_EXIT": 0x80000000,
            "KQ_EV_ADD": 1,
            "KQ_EV_ONESHOT": 16,
            "KQ_EV_ERROR": 0x4000,
        }
        good = SimpleNamespace(ident=123, filter=-5, flags=0, fflags=0x80000000)
        bad = SimpleNamespace(ident=123, filter=-5, flags=0x4000, fflags=0x80000000)
        for event in (good, bad, OSError(errno.EIO, "registration")):
            watcher = MagicMock()
            constants["kqueue"].return_value = watcher
            watcher.control.side_effect = (
                event if isinstance(event, OSError) else [[], [event]]
            )
            with (
                patch.object(render.sys, "platform", "darwin"),
                patch.multiple(render.select, create=True, **constants),
            ):
                observer = render.ExitObserver()
                try:
                    if event is good:
                        observer.wait(self.child(), 1)
                    else:
                        with self.assertRaises((OSError, RuntimeError)):
                            observer.wait(self.child(), 1)
                finally:
                    observer.close()
            watcher.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
