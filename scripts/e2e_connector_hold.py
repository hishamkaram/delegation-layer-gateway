#!/usr/bin/env python3
"""Opt-in finite connector ownership, separate from task/provider fixtures.

Only an exclusive receipt directory and the exact foreground connector child
belong to this owner. Config, identity, Native roots/projects and tasks remain
external. A joined connector never proves task termination or device readiness.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import time
from types import SimpleNamespace

import e2e_local as local
import e2e_remote_peer as peer
from e2e_native_capture import load_owners

MAX_HOLD_SECONDS = 900
CLEANUP_SECONDS = 45
HEARTBEAT_SECONDS = 35
STOP_SEND_SECONDS = 5


def canonical_path(value, *, kind, mode=None):
    local.require(type(value) is str and 0 < len(value) <= 4096, "invalid hold path")
    path = Path(value)
    local.require(
        path.is_absolute() and str(path) == value and path.resolve(strict=True) == path,
        "canonical existing hold path required",
    )
    info = path.lstat()
    local.require(info.st_uid == os.getuid(), "hold path owner mismatch")
    local.require(
        stat.S_ISDIR(info.st_mode)
        if kind == "directory"
        else stat.S_ISREG(info.st_mode),
        "hold path kind mismatch",
    )
    if mode is not None:
        local.require(stat.S_IMODE(info.st_mode) == mode, "hold path mode mismatch")
    if kind == "executable":
        local.require(bool(info.st_mode & 0o111), "hold executable required")
    if kind == "file":
        local.require(info.st_nlink == 1, "hold config must have one link")
    return path


def file_identity(path):
    info = path.lstat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def private_json(path, value):
    """Persist exclusive evidence; never replace or adopt an earlier run."""
    with path.open("x", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output, allow_nan=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_config(path):
    from e2e_remote_channel import finite_float, reject_constant, unique_object

    before = file_identity(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        local.require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
            and info.st_size <= 256 << 10,
            "private bounded hold config required",
        )
        local.require(
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == before,
            "hold config changed before open",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read((256 << 10) + 1)
        local.require(
            len(data) <= 256 << 10 and file_identity(path) == before,
            "hold config changed during read",
        )
    finally:
        os.close(descriptor)
    value = json.loads(
        data,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
        parse_float=finite_float,
    )
    local.require(type(value) is dict, "hold config object required")
    return value


@dataclass(frozen=True)
class HoldManifest:
    run_id: str
    gateway: Path
    config: Path
    delegate_repository: Path
    receipt_directory: Path
    hold_seconds: int
    device_id: str
    gateway_id: str
    config_identity: tuple
    identity_directory: Path
    identity_identity: tuple

    @classmethod
    def parse(cls, value):
        peer.exact(
            value,
            {
                "schema_version",
                "mode",
                "run_id",
                "gateway",
                "config",
                "delegate_repository",
                "receipt_directory",
                "hold_seconds",
                "device_id",
                "gateway_id",
            },
        )
        local.require(
            type(value["schema_version"]) is int
            and value["schema_version"] == 1
            and value["mode"] == "connector_hold",
            "invalid hold schema",
        )
        peer.validate_run_id(value["run_id"])
        seconds = value["hold_seconds"]
        local.require(
            type(seconds) is int and 1 <= seconds <= MAX_HOLD_SECONDS,
            "finite hold of at most 900 seconds required",
        )
        for key in ("device_id", "gateway_id"):
            local.require(
                type(value[key]) is str and peer.IDENTIFIER.fullmatch(value[key]),
                "invalid hold identity",
            )
        gateway = canonical_path(value["gateway"], kind="executable")
        config = canonical_path(value["config"], kind="file", mode=0o600)
        source = canonical_path(value["delegate_repository"], kind="directory")
        receipt_text = value["receipt_directory"]
        local.require(type(receipt_text) is str, "hold receipt path must be text")
        base = Path(receipt_text)
        local.require(
            base.is_absolute()
            and str(base) == value["receipt_directory"]
            and base.name == "gh-" + value["run_id"]
            and not os.path.lexists(base),
            "exclusive hold receipt path required",
        )
        canonical_path(str(base.parent), kind="directory")
        selected_identity = file_identity(config)
        doc = read_config(config)
        local.require(file_identity(config) == selected_identity, "hold config changed")
        local.require(
            type(doc.get("schema_version")) is int
            and doc.get("schema_version") == 1
            and doc.get("expected_device_id") == value["device_id"]
            and doc.get("gateway_id") == value["gateway_id"],
            "hold config identity mismatch",
        )
        identity = canonical_path(
            doc.get("identity_directory"), kind="directory", mode=0o700
        )
        local.require(
            base != identity
            and base not in identity.parents
            and identity not in base.parents
            and base not in config.parents,
            "external resources cannot belong to hold receipts",
        )
        return cls(
            value["run_id"],
            gateway,
            config,
            source,
            base,
            seconds,
            value["device_id"],
            value["gateway_id"],
            selected_identity,
            identity,
            file_identity(identity),
        )


class ConnectorHold:
    """One immutable selection, one Start attempt, one idempotent final receipt."""

    def __init__(self, manifest, interruptions, *, deadline_error=peer.HoldDeadline):
        self.manifest = manifest
        self.interruptions = interruptions
        self.deadline = time.monotonic() + manifest.hold_seconds
        # The CLI loop supplies its own class when it runs as __main__; importing
        # the helper's protocol module can otherwise create a second class identity.
        self.deadline_error = deadline_error
        self.finished = False
        self.shutdown_receipt = None
        self.start_attempted = False
        self.operations = 0
        self.connector = None
        self.base = manifest.receipt_directory
        # Import only Native process/directory owners: no provider or fixture setup.
        DirectoryOwner, Processes = load_owners(manifest.delegate_repository)
        self.ownership = DirectoryOwner()
        self.ownership.create("connector hold receipts", self.base, self.base.parent)
        self.processes = Processes(
            self.base / "processes",
            owner=self.ownership,
            environment=dict(os.environ),
            environment_keys_only=True,
        )
        private_json(
            self.base / "manifest.json",
            {
                "run_id": manifest.run_id,
                "gateway": str(manifest.gateway),
                "config": str(manifest.config),
                "delegate_repository": str(manifest.delegate_repository),
                "hold_seconds": manifest.hold_seconds,
                "task_stop_proven": False,
            },
        )

    def checkpoint(self):
        self.interruptions.checkpoint()
        if time.monotonic() >= self.deadline:
            raise self.deadline_error("connector hold deadline exceeded")

    def initialize(self):
        self.checkpoint()
        return {
            "mode": "connector_hold",
            "base": str(self.base),
            "run_id": self.manifest.run_id,
            "task_stop_proven": False,
        }

    def observations(self):
        waits = []
        for process in self.processes.entries:
            result = process.poll()
            waits.append(
                {
                    "pid": process.pid,
                    "natural_wait": bool(result and result.get("natural_wait")),
                    "exit_code": result.get("exit_code") if result else None,
                }
            )
        return {
            "base": str(self.base),
            "run_id": self.manifest.run_id,
            "task_stop_proven": False,
            "remote_wait_receipts": waits,
        }

    def operate(self, value):
        peer.exact(value, {"operation"})
        operation = value["operation"]
        local.require(
            operation in {"start_connector", "inspect_closure", "shutdown"},
            "unknown connector hold operation",
        )
        local.require(not self.finished, "connector hold is closed")
        self.checkpoint()
        # The final operation slot belongs to shutdown, never a heartbeat or Start.
        local.require(
            self.operations < peer.MAX_OPERATIONS - (operation != "shutdown"),
            "connector hold operation budget exhausted",
        )
        self.operations += 1
        if operation == "shutdown":
            return self.finish()
        if operation == "inspect_closure":
            return self.observations()
        local.require(not self.start_attempted, "connector Start cannot be replayed")
        local.require(
            file_identity(self.manifest.config) == self.manifest.config_identity,
            "connector config changed before Start",
        )
        canonical_path(str(self.manifest.config), kind="file", mode=0o600)
        canonical_path(
            str(self.manifest.identity_directory), kind="directory", mode=0o700
        )
        local.require(
            file_identity(self.manifest.identity_directory)[:2]
            == self.manifest.identity_identity[:2],
            "connector identity directory changed before Start",
        )
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        local.require(
            Path(os.environ.get("HOME", "")).resolve(strict=True) == home
            and bool(os.environ.get("PATH")),
            "actual account HOME/PATH required",
        )
        self.start_attempted = True
        self.connector = self.processes.start(
            "connector",
            [
                str(self.manifest.gateway),
                "connector",
                "run",
                "--config",
                str(self.manifest.config),
            ],
            self.base,
        )
        self.checkpoint()
        return {"started": True, "pid": self.connector.pid, "task_stop_proven": False}

    def finish(self):
        if self.finished:
            return self.shutdown_receipt
        self.finished = True
        confirmed = True
        failures = []
        with self.interruptions.cleanup():
            for process in self.processes.entries:
                try:
                    if process.poll() is None:
                        process.process.send_signal(signal.SIGTERM)
                except Exception as error:
                    confirmed = False
                    failures.append(type(error).__name__)
                try:
                    local.require(
                        process.wait(CLEANUP_SECONDS, expected=None) == 0,
                        "connector exit was not clean",
                    )
                except Exception as error:
                    confirmed = False
                    failures.append(type(error).__name__)
            try:
                confirmed &= self.processes.finished_naturally()
                observation = self.observations()
            except Exception as error:
                confirmed = False
                failures.append(type(error).__name__)
                observation = {
                    "base": str(self.base),
                    "run_id": self.manifest.run_id,
                    "task_stop_proven": False,
                    "remote_wait_receipts": [],
                }
            try:
                self.ownership.release()  # Retain every receipt; never remove external paths.
            except (OSError, RuntimeError) as error:
                confirmed = False
                failures.append(type(error).__name__)
        self.shutdown_receipt = {
            **observation,
            "cleanup_confirmed": bool(confirmed),
            "failure_kinds": failures,
        }
        private_json(self.base / "peer-final.json", self.shutdown_receipt)
        return self.shutdown_receipt


@dataclass(frozen=True)
class Target:
    ssh_alias: str
    expected_home: str
    expected_uid: int
    run_id: str
    gateway: str
    config: str
    receipt_directory: str
    hold_seconds: int
    device_id: str
    gateway_id: str

    @classmethod
    def parse(cls, value):
        import e2e_remote as remote

        peer.exact(value, cls.__dataclass_fields__)
        local.require(
            type(value["ssh_alias"]) is str
            and remote.SAFE_ALIAS.fullmatch(value["ssh_alias"]),
            "invalid SSH alias",
        )
        local.require(
            type(value["expected_uid"]) is int and value["expected_uid"] >= 0,
            "invalid remote UID",
        )
        for key in ("expected_home", "gateway", "config", "receipt_directory"):
            remote.canonical_text(value[key])
        peer.validate_run_id(value["run_id"])
        local.require(
            value["receipt_directory"]
            == value["expected_home"] + "/gh-" + value["run_id"],
            "hold receipt locator must bind account and run",
        )
        local.require(
            type(value["hold_seconds"]) is int
            and 1 <= value["hold_seconds"] <= MAX_HOLD_SECONDS,
            "invalid hold budget",
        )
        for key in ("device_id", "gateway_id"):
            local.require(
                type(value[key]) is str and peer.IDENTIFIER.fullmatch(value[key]),
                "invalid hold target identity",
            )
        return cls(**value)

    @property
    def stage(self):
        return self.expected_home + "/gs-" + self.run_id

    def setup(self):
        return {
            "schema_version": 1,
            "mode": "connector_hold",
            "run_id": self.run_id,
            "gateway": self.gateway,
            "config": self.config,
            "delegate_repository": self.stage + "/native",
            "receipt_directory": self.receipt_directory,
            "hold_seconds": self.hold_seconds,
            "device_id": self.device_id,
            "gateway_id": self.gateway_id,
        }


def source_snapshot(repository):
    """Reuse the maintained bootstrap contract; transfer source only, never programs."""
    import e2e_remote as remote
    import e2e_remote_bootstrap as bootstrap

    files = []
    root = Path(__file__).resolve().parent.parent
    for relative in sorted(bootstrap.GATEWAY_SOURCES):
        path = canonical_path(
            str(root / relative.removeprefix("gateway/")), kind="file"
        )
        files.append(remote.TransferFile(relative, path.read_bytes()))
    # Native supports a namespace scripts package; acceptance itself is regular.
    names = ["scripts/acceptance/__init__.py"]
    if (repository / "scripts/__init__.py").is_file():
        names.append("scripts/__init__.py")
    for name in ("directories", "processes", "evidence"):
        names.extend(
            str(path.relative_to(repository))
            for path in sorted((repository / "scripts/acceptance" / name).glob("*.py"))
        )
    for name in names:
        path = canonical_path(str(repository / name), kind="file")
        local.require(path.stat().st_size <= 1 << 20, "Native source exceeds bound")
        relative = "native/" + name
        local.require(bootstrap.allowed_path(relative), "unallowlisted hold source")
        files.append(remote.TransferFile(relative, path.read_bytes()))
    source = (root / "scripts/e2e_remote_bootstrap.py").read_bytes()
    local.require(
        0 < len(source) <= 128 << 10
        and len(files) <= bootstrap.MAX_FILES
        and sum(len(item.data) for item in files) <= bootstrap.MAX_TOTAL_BYTES,
        "hold source snapshot exceeds limits",
    )
    return source, tuple(files)


def bootstrap_header(target, files):
    return {
        "schema_version": 1,
        "mode": "connector_hold",
        "run_id": target.run_id,
        "expected_home": target.expected_home,
        "expected_uid": target.expected_uid,
        "files": [item.metadata() for item in files],
    }


class HoldController:
    """Foreground owner of two channels; finish always visits both exact children."""

    def __init__(self, source, base, targets, interruptions):
        import e2e_remote as remote

        local.require(
            len(targets) == 2
            and len({t.ssh_alias for t in targets}) == 2
            and len({t.run_id for t in targets}) == 2
            and len({t.device_id for t in targets}) == 2,
            "two distinct hold targets required",
        )
        self.targets = tuple(targets)
        self.interruptions = interruptions
        self.base = base
        self.links = []
        self.finished = None
        self.pumping = False
        self.source, self.files = source_snapshot(source)
        DirectoryOwner, Processes = load_owners(source)
        self.ownership = DirectoryOwner()
        self.ownership.create("local connector hold receipts", base, base.parent)
        self.processes = Processes(
            base / "processes",
            owner=self.ownership,
            environment=dict(os.environ),
            environment_keys_only=True,
            stdout_capture_factory=self.capture_factory,
        )
        private_json(
            self.base / "source-snapshot.json",
            {
                "delegate_repository": str(source),
                "bootstrap_source_sha256": hashlib.sha256(self.source).hexdigest(),
                "source_files": [item.metadata() for item in self.files],
                "executable_content_hashed": False,
            },
        )
        self.ssh = remote.installed_ssh()

    def capture_factory(self, argv):
        for link in self.links:
            if tuple(argv) == link["channel"].argv:
                return link["channel"].capture_factory(argv)
        return None

    def start_ssh(self, name, argv, cwd, *, borrowed_input, on_spawned):
        # Native remains the sole Start/Wait owner. A separate session keeps
        # terminal Ctrl-C in the foreground controller's cooperative handler.
        return self.processes.start(
            name,
            argv,
            cwd,
            borrowed_input=borrowed_input,
            on_spawned=on_spawned,
            start_new_session=True,
        )

    def pump(self):
        self.interruptions.checkpoint()
        if self.pumping:
            return
        self.pumping = True
        try:
            for link in self.links:
                process = link["channel"].process
                if process is not None:
                    process.poll()
                # A sibling remains under the same idle budget while staging or
                # waiting for another peer. Refresh never changes its deadline.
                if (
                    link["initialized"]
                    and not link.get("in_operation")
                    and link["channel"].failure is None
                    and link["deadline"] - time.monotonic() > HEARTBEAT_SECONDS
                    and time.monotonic() - link["last_activity"] >= HEARTBEAT_SECONDS
                ):
                    self.operation(link, "inspect_closure")
        finally:
            self.pumping = False

    def operation(self, link, name):
        channel = link["channel"]
        local.require(
            link["operations"] < peer.MAX_OPERATIONS - (name != "shutdown"),
            "local shutdown slot reserved",
        )
        remaining = link["deadline"] - time.monotonic()
        local.require(remaining > 0, "local hold expired")
        link["operations"] += 1
        link["last_activity"] = time.monotonic()
        link["in_operation"] = True
        try:
            channel.send_json(
                {"operation": name},
                expected_event=name,
                timeout=min(10, remaining),
                pump=self.pump,
            )
            response = channel.expect(
                name,
                timeout=min(15, max(0.001, link["deadline"] - time.monotonic())),
                pump=self.pump,
            )
            local.require(
                response.get("task_stop_proven") is False, "invalid hold scope response"
            )
            if name == "start_connector":
                local.require(
                    response.get("started") is True
                    and type(response.get("pid")) is int
                    and response["pid"] > 0,
                    "connector Start acknowledgement missing",
                )
            elif name == "inspect_closure":
                waits = response.get("remote_wait_receipts")
                local.require(
                    type(waits) is list
                    and len(waits) == 1
                    and type(waits[0]) is dict
                    and waits[0].get("natural_wait") is False
                    and waits[0].get("exit_code") is None,
                    "connector child ended during hold",
                )
            return response
        finally:
            link["in_operation"] = False

    def stage(self, target):
        import struct
        import e2e_remote as remote
        import e2e_remote_bootstrap as bootstrap
        from e2e_remote_channel import PeerChannel

        argv = remote.ssh_argv(self.ssh, target)
        # Keep the existing fixed launcher while bounding broken SSH transports.
        marker = argv.index("--")
        argv = (
            argv[:marker]
            + ("-oServerAliveInterval=5", "-oServerAliveCountMax=3")
            + argv[marker:]
        )
        channel = PeerChannel(
            __import__(
                "scripts.acceptance.processes.operations", fromlist=["BorrowedInput"]
            ),
            argv,
        )
        link = {
            "target": target,
            "channel": channel,
            "initialized": False,
            "operations": 0,
            "last_activity": time.monotonic(),
            "deadline": float("inf"),
        }
        self.links.append(
            link
        )  # Register before any Start, including uncertain starts.
        private_json(
            self.base / (target.run_id + "-locators.json"),
            {
                "ssh_alias": target.ssh_alias,
                "run_id": target.run_id,
                "stage": target.stage,
                "receipt_directory": target.receipt_directory,
                "peer_final": target.receipt_directory + "/peer-final.json",
                "task_stop_proven": False,
            },
        )
        channel.start(
            SimpleNamespace(start=self.start_ssh),
            "hold-ssh-" + target.run_id,
            self.base,
        )
        header = json.dumps(
            bootstrap_header(target, self.files),
            separators=(",", ":"),
        ).encode()
        local.require(
            len(header) <= bootstrap.MAX_HEADER, "hold bootstrap header exceeds bound"
        )
        deadline = time.monotonic() + 110
        for data in (
            struct.pack("!I", len(self.source)),
            self.source,
            struct.pack("!I", len(header)),
            header,
            *(item.data for item in self.files),
        ):
            for offset in range(0, len(data), bootstrap.CHUNK_BYTES):
                channel.write_bytes(
                    data[offset : offset + bootstrap.CHUNK_BYTES],
                    timeout=max(0.001, deadline - time.monotonic()),
                    pump=self.pump,
                )
        ready = channel.expect(
            "bootstrap_ready",
            timeout=max(0.001, deadline - time.monotonic()),
            pump=self.pump,
        )
        local.require(
            ready.get("schema_version") == 1
            and ready.get("run_id") == target.run_id
            and ready.get("stage") == target.stage
            and ready.get("home") == target.expected_home
            and ready.get("uid") == target.expected_uid,
            "hold bootstrap locator mismatch",
        )
        version = ready.get("python_version")
        local.require(
            type(version) is list
            and len(version) == 3
            and all(type(part) is int for part in version)
            and tuple(version) >= (3, 12, 0),
            "remote Python version missing",
        )
        remote.canonical_text(ready.get("python_executable"))
        private_json(self.base / (target.run_id + "-bootstrap.json"), ready)
        link["deadline"] = time.monotonic() + target.hold_seconds
        channel.send_json(
            target.setup(), expected_event="initialized", timeout=10, pump=self.pump
        )
        initialized = channel.expect(
            "initialized", timeout=min(30, target.hold_seconds), pump=self.pump
        )
        local.require(
            initialized.get("mode") == "connector_hold"
            and initialized.get("run_id") == target.run_id
            and initialized.get("base") == target.receipt_directory
            and initialized.get("task_stop_proven") is False,
            "hold initialization mismatch",
        )
        link["initialized"] = True
        link["last_activity"] = time.monotonic()
        self.operation(link, "start_connector")

    def run(self, stream):
        import select

        for target in self.targets:
            self.stage(target)
        peer.emit(
            {"state": "connector_children_started", "task_stop_proven": False},
            self.interruptions,
        )
        control = bytearray()
        while True:
            self.pump()
            now = time.monotonic()
            if any(
                now >= link["deadline"] or link["operations"] >= peer.MAX_OPERATIONS - 1
                for link in self.links
            ):
                return
            ready, _, _ = select.select([stream], [], [], 0.2)
            if ready:
                data = os.read(stream.fileno(), 6)
                if not data:
                    local.require(not control, "incomplete controller stop input")
                    return
                control.extend(data)
                local.require(
                    b"stop\n".startswith(control), "only stop or EOF is accepted"
                )
                if control == b"stop\n":
                    return

    def finish(self):
        if self.finished is not None:
            return self.finished
        failures = []
        results = []
        with self.interruptions.cleanup():
            # Request both shutdowns before waiting for either; sibling faults cannot skip cleanup.
            for link in self.links:
                channel = link["channel"]
                try:
                    if (
                        link["initialized"]
                        and channel.failure is None
                        and link["deadline"] - time.monotonic() > STOP_SEND_SECONDS
                    ):
                        channel.send_json(
                            {"operation": "shutdown"},
                            expected_event="shutdown",
                            timeout=STOP_SEND_SECONDS,
                        )
                        link["shutdown_sent"] = True
                except Exception as error:
                    failures.append(type(error).__name__)
                finally:
                    try:
                        channel.close_input()
                    except Exception as error:
                        failures.append(type(error).__name__)
            for link in self.links:
                channel = link["channel"]
                final = None
                wait = None
                shutdown = None
                try:
                    wait = channel.join(timeout=CLEANUP_SECONDS + 15)
                    if link.get("shutdown_sent"):
                        shutdown = channel.expect("shutdown", timeout=2)
                    final = channel.expect("final", timeout=2)
                    local.require(
                        final.get("base") == link["target"].receipt_directory
                        and final.get("run_id") == link["target"].run_id
                        and final.get("cleanup_confirmed") is True
                        and final.get("task_stop_proven") is False
                        and wait.get("natural_wait") is True
                        and wait.get("exit_code") == 0,
                        "connector remote closure or SSH Wait unconfirmed",
                    )
                    if shutdown is not None:
                        local.require(
                            {k: v for k, v in shutdown.items() if k != "event"}
                            == {k: v for k, v in final.items() if k != "event"},
                            "connector final receipt changed",
                        )
                except Exception as error:
                    failures.append(type(error).__name__)
                results.append(
                    {
                        "run_id": link["target"].run_id,
                        "remote_final": final,
                        "ssh_wait": wait,
                    }
                )
            confirmed = not failures and len(results) == 2
            try:
                confirmed &= self.processes.finished_naturally()
            except Exception as error:
                confirmed = False
                failures.append(type(error).__name__)
            try:
                self.ownership.release()
            except Exception as error:
                confirmed = False
                failures.append(type(error).__name__)
        self.finished = {
            "cleanup_confirmed": confirmed,
            "task_stop_proven": False,
            "failure_kinds": failures,
            "peers": results,
        }
        private_json(self.base / "controller-final.json", self.finished)
        return self.finished


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", required=True, type=Path, help="private two-target hold manifest"
    )
    args = parser.parse_args()
    config = canonical_path(str(args.config), kind="file", mode=0o600)
    value = read_config(config)
    peer.exact(
        value, {"schema_version", "delegate_repository", "receipt_directory", "targets"}
    )
    local.require(
        type(value["schema_version"]) is int and value["schema_version"] == 1,
        "unsupported controller schema",
    )
    source = canonical_path(value["delegate_repository"], kind="directory")
    local.require(
        type(value["receipt_directory"]) is str,
        "local receipt path must be text",
    )
    base = Path(value["receipt_directory"])
    local.require(
        base.is_absolute()
        and str(base) == value["receipt_directory"]
        and not os.path.lexists(base),
        "exclusive local receipt directory required",
    )
    canonical_path(str(base.parent), kind="directory")
    local.require(
        type(value["targets"]) is list and len(value["targets"]) == 2,
        "two targets required",
    )
    targets = tuple(Target.parse(item) for item in value["targets"])
    interruptions = local.Interruptions()
    previous = {
        number: signal.signal(number, interruptions.handle)
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    }
    controller = None
    failed = False
    try:
        controller = HoldController.__new__(HoldController)
        controller.__init__(source, base, targets, interruptions)
        controller.run(__import__("sys").stdin.buffer)
    except Exception:
        failed = True
    finally:
        if controller is not None and hasattr(controller, "processes"):
            try:
                failed |= not controller.finish()["cleanup_confirmed"]
            except Exception:
                failed = True
        elif controller is not None and hasattr(controller, "ownership"):
            controller.ownership.release()
            failed = True
        for number, handler in previous.items():
            signal.signal(number, handler)
    return int(failed or interruptions.interrupted)


if __name__ == "__main__":
    raise SystemExit(main())
