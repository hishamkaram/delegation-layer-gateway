"""Connector child ownership only; no devices, providers, task roots or credentials."""

import importlib
from contextlib import redirect_stdout
import json
import os
import signal
import struct
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from types import MethodType
from unittest import mock

import e2e_connector_hold as hold
import e2e_local as local
import e2e_remote_peer as peer
from e2e_native_capture import load_owners
from e2e_remote_channel import PeerChannel


NATIVE = Path(os.environ.get("DELEGATE_ACCEPTANCE_REPOSITORY", ".ci-native")).resolve()
CHILD = """#!/usr/bin/env python3
import json,signal,sys,time
from pathlib import Path
assert sys.argv[1:4] == ['connector','run','--config']
config=Path(sys.argv[4]); json.loads(config.read_text())
stopped=[False]
signal.signal(signal.SIGTERM,lambda *_:stopped.__setitem__(0,True))
(config.parent/'child-ready').write_text('ready')
deadline=time.monotonic()+8
while not stopped[0] and time.monotonic()<deadline:
 time.sleep(.01)
"""


class HoldTests(unittest.TestCase):
    def setUp(self):
        self.owner = None
        self.channels = []
        self.books = []
        self.test_owners = []
        self.controllers = []
        DirectoryOwner, _ = load_owners(NATIVE)
        self.root_owner = DirectoryOwner()
        self.base = Path(tempfile.mkdtemp(prefix="gateway-hold-test-")).resolve()
        self.root_owner.adopt_created(
            "connector hold test", self.base, self.base.parent
        )
        self.addCleanup(self.cleanup)
        self.gateway = self.base / "gateway"
        self.gateway.write_text(CHILD)
        self.gateway.chmod(0o700)
        self.identity = self.base / "identity"
        self.identity.mkdir(mode=0o700)
        self.config = self.base / "connector.json"
        self.document = {
            "schema_version": 1,
            "gateway_id": "gateway",
            "expected_device_id": "device",
            "identity_directory": str(self.identity),
        }
        self.write_config(self.document)
        self.payload = {
            "schema_version": 1,
            "mode": "connector_hold",
            "run_id": "0123456789abcdef",
            "gateway": str(self.gateway),
            "config": str(self.config),
            "delegate_repository": str(NATIVE),
            "receipt_directory": str(self.base / "gh-0123456789abcdef"),
            "hold_seconds": 8,
            "device_id": "device",
            "gateway_id": "gateway",
        }

    def write_config(self, value):
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)

    def make_owner(self):
        with mock.patch.object(
            local,
            "load_acceptance",
            side_effect=AssertionError("fixture load forbidden"),
        ):
            self.owner = hold.ConnectorHold(
                hold.HoldManifest.parse(self.payload), local.Interruptions()
            )
        return self.owner

    def wait_ready(self):
        deadline = time.monotonic() + 3
        while not (self.base / "child-ready").exists():
            self.assertLess(time.monotonic(), deadline, "finite child did not start")
            time.sleep(0.01)

    def cleanup(self):
        faults = []
        if self.owner is not None:
            try:
                self.owner.finish()
                self.assertFalse(self.owner.processes.pending())
            except Exception as error:
                faults.append(type(error).__name__)
        for controller in self.controllers:
            try:
                controller.finish()
                self.assertFalse(controller.processes.pending())
            except Exception as error:
                faults.append(type(error).__name__)
        for channel in self.channels:
            try:
                channel.close_input()
            except Exception as error:
                faults.append(type(error).__name__)
            try:
                if channel.process is not None:
                    channel.join(timeout=10)
                channel.capture.close()
            except Exception as error:
                faults.append(type(error).__name__)
        for book in self.books:
            try:
                self.assertFalse(book.pending())
            except Exception as error:
                faults.append(type(error).__name__)
        for owner in self.test_owners:
            try:
                owner.release()
            except Exception as error:
                faults.append(type(error).__name__)
        if faults:
            self.root_owner.release()
            raise RuntimeError("test cleanup unconfirmed; retained " + str(self.base))
        self.root_owner.rollback()

    def local_peer(self, seconds=8, *, script=None, repository=NATIVE):
        DirectoryOwner, Processes = load_owners(NATIVE)
        ownership = DirectoryOwner()
        self.test_owners.append(ownership)
        operations = importlib.import_module("scripts.acceptance.processes.operations")
        argv = (sys.executable, str(script or Path(peer.__file__).resolve()))
        channel = PeerChannel(operations, argv)
        book = Processes(
            self.base / "controller-processes",
            environment={
                **os.environ,
                "DELEGATION_GATEWAY_ACCEPTANCE_MODE": "connector_hold",
            },
            environment_keys_only=True,
            stdout_capture_factory=channel.capture_factory,
            owner=ownership,
        )
        self.channels.append(channel)
        self.books.append(book)
        channel.start(book, "local-peer", self.base)
        channel.send_json(
            {
                **self.payload,
                "hold_seconds": seconds,
                "delegate_repository": str(repository),
            },
            expected_event="initialized",
        )
        response = channel.expect("initialized", timeout=5)
        self.assertEqual(response["mode"], "connector_hold")
        channel.send_json(
            {"operation": "start_connector"}, expected_event="start_connector"
        )
        started = channel.expect("start_connector", timeout=5)
        self.assertTrue(started["started"])
        self.assertNotIn("online", started)
        self.wait_ready()
        return channel, book

    def bootstrapped_peer(self, environment):
        """Exercise staging and actual execve into the real peer, without SSH."""
        import e2e_remote_bootstrap as bootstrap

        home = self.base / "bootstrap-home"
        home.mkdir(mode=0o700)
        _, files = hold.source_snapshot(NATIVE)
        target = hold.Target(
            "local",
            str(home),
            os.getuid(),
            self.payload["run_id"],
            str(self.gateway),
            str(self.config),
            str(home / ("gh-" + self.payload["run_id"])),
            8,
            "device",
            "gateway",
        )
        wrapper = self.base / "bootstrap-wrapper.py"
        wrapper.write_text(
            "import os,sys\nfrom pathlib import Path\n"
            "sys.path.insert(0,sys.argv[1])\nimport e2e_remote_bootstrap as b\n"
            # Isolate filesystem staging while retaining the real account HOME.
            "b.actual_account=lambda:(Path(sys.argv[2]),os.getuid())\n"
            "raise SystemExit(b.bootstrap())\n"
        )
        DirectoryOwner, Processes = load_owners(NATIVE)
        ownership = DirectoryOwner()
        self.test_owners.append(ownership)
        operations = importlib.import_module("scripts.acceptance.processes.operations")
        channel = PeerChannel(
            operations,
            (
                sys.executable,
                "-I",
                str(wrapper),
                str(Path(bootstrap.__file__).resolve().parent),
                str(home),
            ),
        )
        book = Processes(
            self.base / "bootstrap-processes",
            environment=environment,
            environment_keys_only=True,
            stdout_capture_factory=channel.capture_factory,
            owner=ownership,
        )
        self.channels.append(channel)
        self.books.append(book)
        channel.start(book, "bootstrap-peer", self.base)
        header = json.dumps(hold.bootstrap_header(target, files)).encode()
        channel.write_bytes(struct.pack("!I", len(header)) + header, timeout=10)
        for item in files:
            channel.write_bytes(item.data, timeout=10)
        ready = channel.expect("bootstrap_ready", timeout=10)
        self.assertEqual(ready["stage"], target.stage)
        channel.send_json(target.setup(), expected_event="initialized")
        self.assertEqual(
            channel.expect("initialized", timeout=5)["mode"], "connector_hold"
        )
        channel.send_json(
            {"operation": "start_connector"}, expected_event="start_connector"
        )
        self.assertTrue(channel.expect("start_connector", timeout=5)["started"])
        self.wait_ready()
        return channel, book

    def test_manifest_rejects_identity_mode_unknown_fields_and_noncanonical_paths_before_start(
        self,
    ):
        for patch in (
            {"hold_seconds": True},
            {"hold_seconds": 901},
            {"mode": "fixture"},
            {"extra": "field"},
            {"device_id": "other"},
            {"gateway_id": "other"},
            {"receipt_directory": 1},
            {"receipt_directory": str(self.identity / "gh-0123456789abcdef")},
            {"config": str(self.base / ".." / self.base.name / "connector.json")},
        ):
            with (
                self.subTest(patch=patch),
                mock.patch.object(hold, "load_owners") as load,
            ):
                with self.assertRaises((local.ProofFailure, ValueError)):
                    hold.HoldManifest.parse({**self.payload, **patch})
                load.assert_not_called()
        self.config.chmod(0o644)
        with self.assertRaises(local.ProofFailure):
            hold.HoldManifest.parse(self.payload)
        self.config.chmod(0o600)
        self.identity.chmod(0o755)
        with self.assertRaises(local.ProofFailure):
            hold.HoldManifest.parse(self.payload)
        self.assertFalse(Path(self.payload["receipt_directory"]).exists())

    def test_nonfinite_config_json_is_rejected_before_owners_or_start(self):
        for number in ("NaN", "1e999"):
            with (
                self.subTest(number=number),
                mock.patch.object(hold, "load_owners") as load,
            ):
                self.config.write_text(
                    json.dumps(self.document)[:-1] + ', "invalid":' + number + "}"
                )
                with self.assertRaises(ValueError):
                    hold.HoldManifest.parse(self.payload)
                load.assert_not_called()
        self.assertFalse(Path(self.payload["receipt_directory"]).exists())

    def test_unknown_operation_and_changed_config_or_identity_do_not_start(self):
        owner = self.make_owner()
        with self.assertRaises(local.ProofFailure):
            owner.operate({"operation": "dispatch_task"})
        self.assertFalse(owner.start_attempted)
        self.write_config({**self.document, "expected_device_id": "rebound"})
        with self.assertRaises(local.ProofFailure):
            owner.operate({"operation": "start_connector"})
        self.assertEqual(owner.processes.entries, [])
        self.assertFalse(owner.start_attempted)

    def test_identity_directory_replacement_does_not_adopt_or_start(self):
        owner = self.make_owner()
        self.identity.rename(self.base / "previous-identity")
        self.identity.mkdir(mode=0o700)
        with self.assertRaisesRegex(local.ProofFailure, "identity directory changed"):
            owner.operate({"operation": "start_connector"})
        self.assertEqual(owner.processes.entries, [])

    def test_real_child_explicit_shutdown_exact_wait_and_idempotent_finish(self):
        owner = self.make_owner()
        owner.operate({"operation": "start_connector"})
        self.wait_ready()
        observed = owner.operate({"operation": "inspect_closure"})
        self.assertFalse(observed["task_stop_proven"])
        self.assertFalse(observed["remote_wait_receipts"][0]["natural_wait"])
        final = owner.operate({"operation": "shutdown"})
        self.assertTrue(final["cleanup_confirmed"])
        self.assertFalse(final["task_stop_proven"])
        self.assertEqual(final["remote_wait_receipts"][0]["exit_code"], 0)
        self.assertTrue(final["remote_wait_receipts"][0]["natural_wait"])
        self.assertIs(owner.finish(), final)
        self.assertEqual(
            json.loads((owner.base / "peer-final.json").read_text()), final
        )
        self.assertTrue(self.config.exists())
        self.assertTrue(self.identity.exists())

    def test_real_peer_eof_stops_only_connector_and_joins_remote_plus_transport(self):
        channel, book = self.local_peer()
        channel.close_input()
        final = channel.expect("final", timeout=8)
        wait = channel.join(timeout=8)
        self.assertTrue(final["cleanup_confirmed"])
        self.assertFalse(final["task_stop_proven"])
        self.assertTrue(final["remote_wait_receipts"][0]["natural_wait"])
        self.assertEqual(final["remote_wait_receipts"][0]["exit_code"], 0)
        self.assertTrue(wait["natural_wait"])
        self.assertEqual(wait["exit_code"], 0)
        self.assertTrue(book.finished_naturally())

    def test_fresh_heartbeats_do_not_renew_remote_absolute_deadline(self):
        channel, book = self.local_peer(seconds=2)
        channel.send_json(
            {"operation": "inspect_closure"}, expected_event="inspect_closure"
        )
        self.assertFalse(
            channel.expect("inspect_closure", timeout=1)["task_stop_proven"]
        )
        # Input stays open and its heartbeat is far below the 120s idle limit.
        # Deadline immutability across repeated heartbeats is checked separately.
        final = channel.expect("final", timeout=4)
        wait = channel.join(timeout=4)
        self.assertTrue(final["cleanup_confirmed"])
        self.assertEqual(wait["exit_code"], 0)
        self.assertTrue(book.finished_naturally())

    def test_heartbeats_preserve_deadline_and_last_shutdown_slot(self):
        owner = self.make_owner()
        deadline = owner.deadline
        for _ in range(31):
            owner.operate({"operation": "inspect_closure"})
        self.assertEqual(owner.deadline, deadline)
        with self.assertRaises(local.ProofFailure):
            owner.operate({"operation": "inspect_closure"})
        self.assertEqual(owner.operations, 31)
        self.assertTrue(owner.operate({"operation": "shutdown"})["cleanup_confirmed"])
        self.assertEqual(owner.operations, 32)

    def test_registered_partial_start_is_joined_without_replaying_start(self):
        owner = self.make_owner()
        original = owner.processes.start

        def failed_publication(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("injected failure after native registration")

        with mock.patch.object(
            owner.processes, "start", side_effect=failed_publication
        ):
            with self.assertRaises(OSError):
                owner.operate({"operation": "start_connector"})
        self.wait_ready()
        with self.assertRaises(local.ProofFailure):
            owner.operate({"operation": "start_connector"})
        self.assertEqual(len(owner.processes.entries), 1)
        self.assertTrue(owner.finish()["cleanup_confirmed"])

    def test_uncertain_start_is_retained_not_replayed_or_reported_closed(self):
        owner = self.make_owner()
        module = importlib.import_module("scripts.acceptance.processes.operations")
        with mock.patch.object(
            module.subprocess, "Popen", side_effect=OSError("uncertain start")
        ):
            with self.assertRaises(Exception):
                owner.operate({"operation": "start_connector"})
        with self.assertRaises(local.ProofFailure):
            owner.operate({"operation": "start_connector"})
        self.assertFalse(owner.finish()["cleanup_confirmed"])
        self.assertTrue((owner.base / "peer-final.json").exists())
        self.assertTrue((owner.base / "processes").exists())
        # No OS child existed in this injection; Native intentionally retains uncertainty.
        self.owner = None

    def test_failed_wait_retains_evidence_and_cannot_claim_cleanup(self):
        owner = self.make_owner()
        owner.operate({"operation": "start_connector"})
        self.wait_ready()
        process = owner.processes.entries[0]
        with mock.patch.object(
            process, "wait", side_effect=OSError("injected Wait finalization fault")
        ):
            self.assertFalse(owner.finish()["cleanup_confirmed"])
        process.wait(
            timeout=5, expected=0
        )  # Actual owned cleanup still completes after the fault seam.
        self.assertTrue(owner.base.exists())
        self.assertFalse(owner.finish()["cleanup_confirmed"])

    def test_signal_reporting_fault_still_waits_the_same_owned_child(self):
        owner = self.make_owner()
        owner.operate({"operation": "start_connector"})
        self.wait_ready()
        process = owner.processes.entries[0]
        send = process.process.send_signal

        def sent_then_failed(number):
            send(number)
            raise OSError("signal reporting fault")

        try:
            with (
                mock.patch.object(
                    process.process, "send_signal", side_effect=sent_then_failed
                ) as signal_attempt,
                mock.patch.object(process, "wait", wraps=process.wait) as wait,
            ):
                final = owner.finish()
                signal_attempt.assert_called_once_with(signal.SIGTERM)
                wait.assert_called_once_with(hold.CLEANUP_SECONDS, expected=None)
            self.assertFalse(final["cleanup_confirmed"])
            self.assertIn("OSError", final["failure_kinds"])
            self.assertTrue(final["remote_wait_receipts"][0]["natural_wait"])
            self.assertEqual(final["remote_wait_receipts"][0]["exit_code"], 0)
            self.assertEqual(
                json.loads((owner.base / "peer-final.json").read_text()), final
            )
        finally:
            process.wait(timeout=10, expected=0)

    def test_poll_fault_still_waits_the_same_finite_owned_child_without_signalling(
        self,
    ):
        self.gateway.write_text(
            CHILD.replace("time.monotonic()+8", "time.monotonic()+.3")
        )
        owner = self.make_owner()
        owner.operate({"operation": "start_connector"})
        self.wait_ready()
        process = owner.processes.entries[0]
        poll = process.poll
        first = True

        def first_poll_failed(*args, **kwargs):
            nonlocal first
            if first:
                first = False
                raise OSError("poll observation fault")
            return poll(*args, **kwargs)

        try:
            with (
                mock.patch.object(process, "poll", side_effect=first_poll_failed),
                mock.patch.object(process.process, "send_signal") as signal_attempt,
                mock.patch.object(process, "wait", wraps=process.wait) as wait,
            ):
                final = owner.finish()
                signal_attempt.assert_not_called()
                wait.assert_called_once_with(hold.CLEANUP_SECONDS, expected=None)
            self.assertFalse(final["cleanup_confirmed"])
            self.assertIn("OSError", final["failure_kinds"])
            self.assertTrue(final["remote_wait_receipts"][0]["natural_wait"])
            self.assertEqual(final["remote_wait_receipts"][0]["exit_code"], 0)
            self.assertEqual(
                json.loads((owner.base / "peer-final.json").read_text()), final
            )
        finally:
            process.wait(timeout=10, expected=0)

    def test_main_unknown_mode_rejected_without_any_owner(self):
        envelope = {"request_id": 1, "payload": {"mode": "unknown"}}
        with (
            mock.patch.object(peer, "lines", return_value=iter([envelope])),
            mock.patch.object(peer.signal, "signal"),
            mock.patch.object(peer, "emit"),
            mock.patch.object(peer, "Peer") as fixture,
            mock.patch.object(hold, "ConnectorHold") as connector,
        ):
            self.assertEqual(peer.main(), 1)
        fixture.assert_not_called()
        connector.assert_not_called()

    def test_bootstrap_mode_is_closed_and_agrees_with_the_peer_selection(self):
        import e2e_remote_bootstrap as bootstrap

        _, files = hold.source_snapshot(NATIVE)
        target = hold.Target(
            "local",
            str(self.base),
            os.getuid(),
            self.payload["run_id"],
            str(self.gateway),
            str(self.config),
            self.payload["receipt_directory"],
            8,
            "device",
            "gateway",
        )
        header = hold.bootstrap_header(target, files)
        self.assertEqual(header["mode"], "connector_hold")
        for mode in (True, None, "unknown"):
            with self.subTest(mode=mode), self.assertRaises(bootstrap.BootstrapFailure):
                bootstrap.validate_manifest(
                    {**header, "mode": mode}, self.base, os.getuid()
                )
        for environment, setup in (
            ({bootstrap.PEER_MODE_ENV: "connector_hold"}, {}),
            ({}, self.payload),
        ):
            construction = mock.Mock(side_effect=AssertionError("peer owner"))

            class RejectedOwner:
                @staticmethod
                def __new__(owner):
                    return construction(owner)

            with (
                self.subTest(marker=environment, mode=setup.get("mode")),
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(
                    peer,
                    "lines",
                    return_value=iter([{"request_id": 1, "payload": setup}]),
                ),
                mock.patch.object(peer.signal, "signal"),
                mock.patch.object(peer, "emit"),
                mock.patch.object(peer, "Peer", RejectedOwner),
                mock.patch.object(hold, "ConnectorHold", RejectedOwner),
            ):
                self.assertEqual(peer.main(), 1)
                construction.assert_not_called()

    def test_full_bootstrap_preserves_connector_account_environment(self):
        sentinel = self.base / "provider-bin"
        sentinel.mkdir()
        provider = sentinel / "owned-provider-sentinel"
        provider.write_text("#!/bin/sh\nexit 0\n")
        provider.chmod(0o700)
        self.gateway.write_text(
            CHILD.replace(
                "import json,signal,sys,time", "import json,os,shutil,signal,sys,time"
            ).replace(
                "config=Path(sys.argv[4]); json.loads(config.read_text())",
                "config=Path(sys.argv[4]); json.loads(config.read_text())\n"
                "(config.parent/'child-environment.json').write_text(json.dumps({"
                "'home':os.environ.get('HOME'),'path':os.environ.get('PATH'),"
                "'sentinel':os.environ.get('GW_HOLD_ACCOUNT_SENTINEL'),"
                "'provider':shutil.which('owned-provider-sentinel')}))",
            )
        )
        environment = {
            **os.environ,
            "PATH": str(sentinel) + os.pathsep + os.environ["PATH"],
            "GW_HOLD_ACCOUNT_SENTINEL": "retained",
        }
        channel, book = self.bootstrapped_peer(environment)
        observed = json.loads((self.base / "child-environment.json").read_text())
        self.assertEqual(observed["home"], os.environ["HOME"])
        self.assertEqual(observed["path"], environment["PATH"])
        self.assertEqual(observed["sentinel"], "retained")
        self.assertEqual(observed["provider"], str(provider))
        channel.close_input()
        final = channel.expect("final", timeout=8)
        self.assertTrue(final["cleanup_confirmed"])
        self.assertEqual(channel.join(timeout=8)["exit_code"], 0)
        self.assertTrue(book.finished_naturally())

    def test_full_bootstrap_legacy_peer_keeps_its_minimal_environment(self):
        import e2e_remote_bootstrap as bootstrap

        home = self.base / "legacy-home"
        home.mkdir(mode=0o700)
        source = (
            "import json,os\nprint(json.dumps({'path':os.environ.get('PATH'),"
            "'sentinel':os.environ.get('GW_HOLD_ACCOUNT_SENTINEL')}),flush=True)\n"
        ).encode()
        metadata = {
            "schema_version": 1,
            "run_id": self.payload["run_id"],
            "expected_home": str(home),
            "expected_uid": os.getuid(),
            "files": [
                {
                    "path": bootstrap.PEER,
                    "size": len(source),
                    "sha256": __import__("hashlib").sha256(source).hexdigest(),
                    "executable": False,
                }
            ],
        }
        wrapper = self.base / "legacy-bootstrap.py"
        wrapper.write_text(
            "import os,sys\nfrom pathlib import Path\n"
            "sys.path.insert(0,sys.argv[1])\nimport e2e_remote_bootstrap as b\n"
            "b.actual_account=lambda:(Path(sys.argv[2]),os.getuid())\n"
            "raise SystemExit(b.bootstrap())\n"
        )
        DirectoryOwner, Processes = load_owners(NATIVE)
        owner = DirectoryOwner()
        self.test_owners.append(owner)
        book = Processes(
            self.base / "legacy-processes",
            owner=owner,
            environment={**os.environ, "GW_HOLD_ACCOUNT_SENTINEL": "not inherited"},
            environment_keys_only=True,
        )
        self.books.append(book)
        encoded = json.dumps(metadata).encode()
        process = book.start(
            "legacy-bootstrap",
            [
                sys.executable,
                "-I",
                wrapper,
                Path(bootstrap.__file__).resolve().parent,
                home,
            ],
            self.base,
            stdin=struct.pack("!I", len(encoded)) + encoded + source,
        )
        process.wait(8, expected=0)
        observed = json.loads(process.stdout_path.read_bytes().splitlines()[-1])
        self.assertEqual(observed, {"path": "/usr/bin:/bin", "sentinel": None})
        self.assertTrue(book.finished_naturally())

    def test_controller_visits_both_after_missing_final_and_failed_ssh_wait(self):
        controller = hold.HoldController.__new__(hold.HoldController)
        controller.base = self.base
        controller.finished = None
        controller.interruptions = local.Interruptions()
        controller.processes = mock.Mock()
        controller.processes.finished_naturally.return_value = True
        controller.ownership = mock.Mock()
        channels = []
        for index in range(2):
            channel = mock.Mock()
            channel.failure = None
            channel.join.side_effect = OSError("missing Wait") if index == 0 else None
            if index == 1:
                channel.join.return_value = {"natural_wait": True, "exit_code": 0}
                channel.expect.side_effect = OSError("missing final")
            channels.append(channel)
        controller.links = [
            {
                "channel": channel,
                "initialized": False,
                "deadline": 0,
                "target": SimpleNamespace(
                    run_id=str(index), receipt_directory="/retained/" + str(index)
                ),
            }
            for index, channel in enumerate(channels)
        ]
        final = controller.finish()
        self.assertFalse(final["cleanup_confirmed"])
        for channel in channels:
            channel.close_input.assert_called_once()
            channel.join.assert_called_once()
            channel.start.assert_not_called()
        self.assertEqual(len(final["peers"]), 2)
        self.assertTrue((self.base / "controller-final.json").exists())
        self.assertIs(controller.finish(), final)

    def two_peer_controller(self, *, seconds=8, run=True):
        targets = []
        for index in range(2):
            external = self.base / ("external-" + str(index))
            external.mkdir(mode=0o700)
            identity = external / "identity"
            identity.mkdir(mode=0o700)
            config = external / "connector.json"
            config.write_text(
                json.dumps(
                    {
                        **self.document,
                        "expected_device_id": "device-" + str(index),
                        "identity_directory": str(identity),
                    }
                )
            )
            config.chmod(0o600)
            run_id = str(index + 1) * 16
            targets.append(
                hold.Target(
                    "local-" + str(index),
                    str(self.base),
                    os.getuid(),
                    run_id,
                    str(self.gateway),
                    str(config),
                    str(self.base / ("gh-" + run_id)),
                    seconds,
                    "device-" + str(index),
                    "gateway",
                )
            )
        with mock.patch.dict(
            os.environ, {"DELEGATION_GATEWAY_ACCEPTANCE_MODE": "connector_hold"}
        ):
            controller = hold.HoldController(
                NATIVE, self.base / "controller", targets, local.Interruptions()
            )
        self.controllers.append(controller)
        self.books.append(controller.processes)
        operations = importlib.import_module("scripts.acceptance.processes.operations")

        def local_stage(subject, target):
            # Exercise the real controller/channel/peer/Native children locally.
            # SSH/bootstrap are intentionally outside this test's proof category.
            channel = PeerChannel(
                operations,
                (sys.executable, str(Path(peer.__file__).resolve()), target.run_id),
            )
            link = {
                "channel": channel,
                "target": target,
                "operations": 0,
                "last_activity": time.monotonic(),
                "deadline": time.monotonic() + target.hold_seconds,
                "initialized": False,
            }
            subject.links.append(link)
            self.channels.append(channel)
            channel.start(
                SimpleNamespace(start=subject.start_ssh), target.ssh_alias, subject.base
            )
            channel.send_json(
                {**target.setup(), "delegate_repository": str(NATIVE)},
                expected_event="initialized",
            )
            channel.expect("initialized", timeout=5)
            link["initialized"] = True
            subject.operation(link, "start_connector")
            deadline = time.monotonic() + 3
            marker = Path(target.config).parent / "child-ready"
            while not marker.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)

        controller.stage = MethodType(local_stage, controller)
        if not run:
            return controller
        reader, writer = os.pipe()
        try:
            os.write(writer, b"stop\n")
            with (
                os.fdopen(reader, "rb") as source,
                tempfile.TemporaryFile() as output,
                redirect_stdout(output),
            ):
                controller.run(source)
        finally:
            os.close(writer)
        return controller

    def test_real_two_peer_controller_explicit_stop_joins_both(self):
        controller = self.two_peer_controller()
        final = controller.finish()
        self.assertTrue(final["cleanup_confirmed"])
        self.assertFalse(final["task_stop_proven"])
        for record in final["peers"]:
            self.assertTrue(record["ssh_wait"]["natural_wait"])
            self.assertEqual(record["ssh_wait"]["exit_code"], 0)
            self.assertTrue(record["remote_final"]["cleanup_confirmed"])
            self.assertTrue(
                record["remote_final"]["remote_wait_receipts"][0]["natural_wait"]
            )
        self.assertTrue(controller.processes.finished_naturally())

    def test_real_controller_signal_checkpoint_cleans_both_isolated_sessions(self):
        controller = self.two_peer_controller()
        for link in controller.links:
            process = link["channel"].process
            self.assertEqual(os.getsid(process.pid), process.pid)
            self.assertNotEqual(os.getsid(process.pid), os.getsid(0))
        controller.interruptions.handle(signal.SIGINT, None)
        with self.assertRaises(local.ProofFailure):
            controller.pump()
        self.assertTrue(controller.interruptions.interrupted)
        self.assertTrue(controller.finish()["cleanup_confirmed"])
        self.assertTrue(controller.processes.finished_naturally())

    def test_full_borrowed_stdout_is_bounded_and_both_connector_children_join(self):
        controller = self.two_peer_controller(seconds=60, run=False)
        reader, writer = os.pipe()
        control_read, control_write = os.pipe()

        class PublicationWatchdog(RuntimeError):
            pass

        class BorrowedOutput:
            def fileno(self):
                return writer

            def write(self, text):
                return os.write(writer, text.encode())

            def flush(self):
                pass

        def watchdog(*_):
            raise PublicationWatchdog("unbounded borrowed-stdout publication")

        stage = controller.stage

        def ready_then_arm(subject, target):
            stage(target)
            if len(subject.links) == 2:
                # Test-only guard begins after both real children are ready.
                signal.setitimer(signal.ITIMER_REAL, 2)

        controller.stage = MethodType(ready_then_arm, controller)
        previous = signal.signal(signal.SIGALRM, watchdog)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        try:
            os.set_blocking(writer, False)
            with self.assertRaises(BlockingIOError):
                while True:
                    os.write(writer, b"x" * 4096)
            os.set_blocking(writer, True)
            os.write(control_write, b"stop\n")
            with (
                os.fdopen(control_read, "rb") as control,
                redirect_stdout(BorrowedOutput()),
                mock.patch.object(peer, "OUTPUT_TIMEOUT", 0.03),
            ):
                with self.assertRaisesRegex(local.ProofFailure, "publication deadline"):
                    controller.run(control)
            signal.setitimer(signal.ITIMER_REAL, 0)
            self.assertTrue(os.get_blocking(writer))
            os.fstat(writer)  # The publisher never owns/closes borrowed stdout.
            final = controller.finish()
            self.assertTrue(final["cleanup_confirmed"])
            self.assertTrue((controller.base / "controller-final.json").is_file())
            self.assertTrue(controller.processes.finished_naturally())
            for record in final["peers"]:
                self.assertTrue(record["ssh_wait"]["natural_wait"])
                self.assertEqual(record["ssh_wait"]["exit_code"], 0)
                self.assertTrue(record["remote_final"]["cleanup_confirmed"])
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)
            os.close(control_write)
            os.close(writer)
            os.close(reader)

    def test_first_input_close_fault_still_joins_both_peers_and_preserves_failure(self):
        controller = self.two_peer_controller(seconds=60)
        first = controller.links[0]["channel"]
        second = controller.links[1]["channel"]
        close_first = first.close_input

        def closed_then_failed():
            close_first()
            raise OSError("injected close reporting fault")

        with (
            mock.patch.object(first, "close_input", side_effect=closed_then_failed),
            mock.patch.object(first, "join", wraps=first.join) as first_join,
            mock.patch.object(second, "join", wraps=second.join) as second_join,
            mock.patch.object(first, "expect", wraps=first.expect) as first_final,
            mock.patch.object(second, "expect", wraps=second.expect) as second_final,
        ):
            final = controller.finish()
        first_join.assert_called_once()
        second_join.assert_called_once()
        self.assertIn(mock.call("final", timeout=2), first_final.call_args_list)
        self.assertIn(mock.call("final", timeout=2), second_final.call_args_list)
        self.assertFalse(final["cleanup_confirmed"])
        self.assertIn("OSError", final["failure_kinds"])
        self.assertTrue(controller.processes.finished_naturally())
        for record in final["peers"]:
            self.assertTrue(record["ssh_wait"]["natural_wait"])
            self.assertEqual(record["ssh_wait"]["exit_code"], 0)
            self.assertTrue(record["remote_final"]["cleanup_confirmed"])
        self.assertEqual(
            json.loads((controller.base / "controller-final.json").read_text()), final
        )

    def test_finished_observation_fault_still_releases_and_persists_both_joins(self):
        controller = self.two_peer_controller(seconds=60)
        with (
            mock.patch.object(
                controller.processes,
                "finished_naturally",
                side_effect=RuntimeError("completion observation fault"),
            ),
            mock.patch.object(
                controller.ownership, "release", wraps=controller.ownership.release
            ) as release,
        ):
            final = controller.finish()
        release.assert_called_once()
        self.assertFalse(final["cleanup_confirmed"])
        self.assertIn("RuntimeError", final["failure_kinds"])
        self.assertTrue(controller.processes.finished_naturally())
        self.assertEqual(len(final["peers"]), 2)
        for record in final["peers"]:
            self.assertTrue(record["ssh_wait"]["natural_wait"])
            self.assertEqual(record["ssh_wait"]["exit_code"], 0)
            self.assertTrue(record["remote_final"]["cleanup_confirmed"])
        self.assertEqual(
            json.loads((controller.base / "controller-final.json").read_text()), final
        )

    def test_release_fault_still_persists_both_joins_and_failure(self):
        controller = self.two_peer_controller(seconds=60)
        release = controller.ownership.release

        def released_then_failed():
            release()
            raise OSError("ownership release reporting fault")

        with mock.patch.object(
            controller.ownership, "release", side_effect=released_then_failed
        ) as release_attempt:
            final = controller.finish()
        release_attempt.assert_called_once()
        self.assertFalse(final["cleanup_confirmed"])
        self.assertIn("OSError", final["failure_kinds"])
        self.assertTrue(controller.processes.finished_naturally())
        self.assertEqual(len(final["peers"]), 2)
        for record in final["peers"]:
            self.assertTrue(record["ssh_wait"]["natural_wait"])
            self.assertEqual(record["ssh_wait"]["exit_code"], 0)
            self.assertTrue(record["remote_final"]["cleanup_confirmed"])
        self.assertEqual(
            json.loads((controller.base / "controller-final.json").read_text()), final
        )

    def test_real_two_peer_missing_final_still_joins_sibling_and_retains_locators(self):
        controller = self.two_peer_controller()
        first = controller.links[0]["channel"]
        original = first.expect

        def missing_final(event, **kwargs):
            if event == "final":
                raise OSError("injected missing final delivery")
            return original(event, **kwargs)

        with mock.patch.object(first, "expect", side_effect=missing_final):
            final = controller.finish()
        self.assertFalse(final["cleanup_confirmed"])
        self.assertTrue(controller.processes.finished_naturally())
        self.assertEqual(final["peers"][1]["ssh_wait"]["exit_code"], 0)
        self.assertTrue(final["peers"][1]["remote_final"]["cleanup_confirmed"])
        for link in controller.links:
            self.assertTrue(
                (Path(link["target"].receipt_directory) / "peer-final.json").exists()
            )

    def test_changed_shutdown_receipt_cannot_be_replaced_by_a_successful_final(self):
        controller = self.two_peer_controller(seconds=60)
        first = controller.links[0]["channel"]
        original = first.expect

        def changed_shutdown(event, **kwargs):
            result = original(event, **kwargs)
            if event == "shutdown":
                result = {**result, "cleanup_confirmed": False}
            return result

        with mock.patch.object(first, "expect", side_effect=changed_shutdown):
            final = controller.finish()
        self.assertFalse(final["cleanup_confirmed"])
        self.assertTrue(controller.processes.finished_naturally())
        self.assertTrue(final["peers"][1]["remote_final"]["cleanup_confirmed"])

    def test_source_snapshot_is_allowlisted_source_only(self):
        import e2e_remote_bootstrap as bootstrap

        source, files = hold.source_snapshot(NATIVE)
        self.assertTrue(source)
        self.assertTrue(all(not item.executable for item in files))
        self.assertTrue(all(bootstrap.allowed_path(item.path) for item in files))
        self.assertIn(
            "gateway/scripts/e2e_connector_hold.py", {item.path for item in files}
        )
        self.assertIn(
            "gateway/scripts/e2e_remote_channel.py", {item.path for item in files}
        )

    def test_source_snapshot_runs_peer_without_the_full_native_checkout(self):
        _, files = hold.source_snapshot(NATIVE)
        stage = self.base / "source-stage"
        stage.mkdir(mode=0o700)
        for item in files:
            path = stage / item.path
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.write_bytes(item.data)
            path.chmod(0o600)
        channel, book = self.local_peer(
            script=stage / "gateway/scripts/e2e_remote_peer.py",
            repository=stage / "native",
        )
        channel.close_input()
        final = channel.expect("final", timeout=8)
        self.assertTrue(final["cleanup_confirmed"])
        self.assertEqual(channel.join(timeout=8)["exit_code"], 0)
        self.assertTrue(book.finished_naturally())

    def test_owner_uses_the_composing_loops_deadline_exception(self):
        class LoopDeadline(local.ProofFailure):
            pass

        self.owner = hold.ConnectorHold(
            hold.HoldManifest.parse(self.payload),
            local.Interruptions(),
            deadline_error=LoopDeadline,
        )
        self.owner.deadline = time.monotonic() - 1
        with self.assertRaises(LoopDeadline):
            self.owner.initialize()

    def test_buffered_input_observes_deadline_activated_after_setup_yield(self):
        reader, writer = os.pipe()
        deadline = [None]
        try:
            os.write(writer, b'{}\n{"operation":"inspect_closure"}\n')
            with os.fdopen(reader, "rb") as stream:
                inputs = peer.lines(
                    stream, local.Interruptions(), absolute_deadline=lambda: deadline[0]
                )
                self.assertEqual(next(inputs), {})
                deadline[0] = time.monotonic() - 1
                with self.assertRaises(peer.HoldDeadline):
                    next(inputs)
        finally:
            os.close(writer)

    def test_real_controller_refreshes_sibling_without_extending_hold(self):
        controller = self.two_peer_controller(seconds=60)
        first = controller.links[0]
        deadline = first["deadline"]
        first["last_activity"] = time.monotonic() - 36
        controller.pump()
        self.assertEqual(first["operations"], 2)  # Start, then fresh inspect_closure.
        self.assertEqual(first["deadline"], deadline)
        self.assertTrue(controller.finish()["cleanup_confirmed"])

    def test_real_controller_leaves_deadline_margin_instead_of_racing_a_final(self):
        controller = self.two_peer_controller()
        first = controller.links[0]
        first["last_activity"] = time.monotonic() - 36
        controller.pump()
        self.assertEqual(first["operations"], 1)  # Start only; idle EOF can stop it.
        self.assertTrue(controller.finish()["cleanup_confirmed"])

    def test_controller_requires_start_ack_and_rejects_ended_child_heartbeats(self):
        for name, response in (
            ("start_connector", {"started": True, "pid": False}),
            (
                "inspect_closure",
                {"remote_wait_receipts": [{"natural_wait": True, "exit_code": 0}]},
            ),
        ):
            with self.subTest(operation=name):
                controller = hold.HoldController.__new__(hold.HoldController)
                controller.pump = mock.Mock()
                channel = mock.Mock()
                channel.expect.return_value = {"task_stop_proven": False, **response}
                link = {
                    "channel": channel,
                    "operations": 0,
                    "deadline": time.monotonic() + 60,
                }
                with self.assertRaises(local.ProofFailure):
                    controller.operation(link, name)
                channel.send_json.assert_called_once()
                self.assertEqual(link["operations"], 1)

    def test_controller_stop_accepts_bounded_fragmented_input(self):
        controller = hold.HoldController.__new__(hold.HoldController)
        controller.targets = ()
        controller.links = []
        controller.interruptions = local.Interruptions()
        controller.pump = mock.Mock()
        stream = SimpleNamespace(fileno=lambda: 3)
        with (
            mock.patch("select.select", return_value=([stream], [], [])),
            mock.patch.object(hold.os, "read", side_effect=[b"s", b"to", b"p\n"]),
            tempfile.TemporaryFile() as output,
            redirect_stdout(output),
        ):
            controller.run(stream)
        self.assertEqual(controller.pump.call_count, 3)


if __name__ == "__main__":
    unittest.main()
