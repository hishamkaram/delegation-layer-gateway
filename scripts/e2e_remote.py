#!/usr/bin/env python3
"""Explicit two-Mac, four-attempt fixture controller. No installed provider proof.

Controller owns immutable configuration, transfer bytes and local locator receipts.
Peer owns remote resources; NativeProcesses owns every local child and exact Wait.
All evidence/stages are retained, including after successful closure.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shutil
import stat
import struct
import time
from types import SimpleNamespace
import uuid

import e2e_local as local
import e2e_recovery as recovery
import e2e_remote_bootstrap as bootstrap
import e2e_remote_peer as peer
from e2e_remote_channel import PeerChannel, unique_object

# Static shell program: all target/account/file data travels on stdin instead.
RAW_LOADER = """import os,select,struct,sys,time
if sys.version_info < (3,12): raise SystemExit(12)
deadline=time.monotonic()+120
def exact(n):
 data=bytearray()
 while len(data)<n:
  remaining=deadline-time.monotonic()
  if remaining<=0 or not select.select([0],[],[],remaining)[0]: raise SystemExit(13)
  chunk=os.read(0,n-len(data))
  if not chunk: raise SystemExit(14)
  data.extend(chunk)
 return bytes(data)
n=struct.unpack(\"!I\",exact(4))[0]
if not 0<n<=131072: raise SystemExit(15)
source=exact(n)
globals()[\"__file__\"]=\"<gateway-fixture-bootstrap>\"
exec(compile(source,\"<gateway-fixture-bootstrap>\",\"exec\"),globals())
"""
SSH_COMMAND = "exec python3 -I -c '" + RAW_LOADER + "'"
# 35s + a 45s local join + a 25s sibling heartbeat + 10s send = 115s.
# The fixture assumes wire delivery fits the remaining 5s headroom. This is
# not a guarantee under unbounded network delay; missed responses fail closed.
PEER_HEARTBEAT_SECONDS = 35.0
SAFE_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def require(condition, kind):
    local.require(condition, kind)


def canonical_text(value):
    require(type(value) is str and 0 < len(value) <= 4096, "invalid path")
    path = PurePosixPath(value)
    require(
        path.is_absolute()
        and str(path) == value
        and ".." not in path.parts
        and "\0" not in value
        and "\n" not in value,
        "canonical absolute path required",
    )
    return value


def owned_path(value, *, directory=False, private=False):
    path = Path(canonical_text(value))
    require(path.resolve(strict=True) == path, "symlink path forbidden")
    info = path.lstat()
    require(info.st_uid == os.getuid(), "caller ownership required")
    require(
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
        "wrong path kind",
    )
    if private:
        require(stat.S_IMODE(info.st_mode) & 0o077 == 0, "private path required")
    return path


def read_json(path, limit=4 << 20):
    require(path.stat().st_size <= limit, "JSON size limit")
    value = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    require(type(value) is dict, "JSON object required")
    return value


@dataclass(frozen=True)
class Target:
    ssh_alias: str
    expected_home: str
    expected_uid: int
    pueue: str
    pueued: str

    @classmethod
    def parse(cls, value):
        require(
            type(value) is dict and set(value) == set(cls.__dataclass_fields__),
            "invalid target fields",
        )
        require(
            type(value["ssh_alias"]) is str
            and SAFE_ALIAS.fullmatch(value["ssh_alias"]),
            "unsafe SSH alias",
        )
        require(
            type(value["expected_uid"]) is int and value["expected_uid"] >= 0,
            "invalid expected UID",
        )
        for key in ("expected_home", "pueue", "pueued"):
            canonical_text(value[key])
        home = PurePosixPath(value["expected_home"])
        require(
            home != PurePosixPath("/")
            and home != PurePosixPath("/tmp")
            and PurePosixPath("/tmp") not in home.parents
            and len(os.fsencode(home / ("gp-" + "0" * 16) / "d/s")) + 14 <= 100,
            "remote HOME exceeds socket bound",
        )
        require(
            PurePosixPath(value["pueue"]).name == "pueue"
            and PurePosixPath(value["pueued"]).name == "pueued"
            and PurePosixPath(value["pueue"]).parent
            == PurePosixPath(value["pueued"]).parent,
            "adjacent installed Pueue pair required",
        )
        return cls(**value)


@dataclass(frozen=True)
class Config:
    gateway: Path
    fixture_tool: Path
    delegate_repository: Path
    listen_ip: str
    candidate_directory: Path
    build_receipt: Path
    work_parent: Path
    peers: tuple[Target, Target]

    @classmethod
    def parse(cls, value):
        require(
            type(value) is dict
            and set(value) == {"schema_version", *cls.__dataclass_fields__},
            "invalid controller fields",
        )
        require(
            type(value["schema_version"]) is int and value["schema_version"] == 1,
            "unsupported controller schema",
        )
        fields = {}
        for key in (
            "gateway",
            "fixture_tool",
            "delegate_repository",
            "candidate_directory",
            "build_receipt",
            "work_parent",
        ):
            fields[key] = owned_path(
                value[key],
                directory=key
                in ("delegate_repository", "candidate_directory", "work_parent"),
                private=key == "candidate_directory",
            )
        for key in ("gateway", "fixture_tool"):
            require(os.access(fields[key], os.X_OK), "local executable required")
        address = ipaddress.IPv4Address(value["listen_ip"])
        require(
            not (address.is_unspecified or address.is_multicast or address.is_loopback),
            "explicit reachable IPv4 required",
        )
        fields["listen_ip"] = str(address)
        require(
            type(value["peers"]) is list and len(value["peers"]) == 2,
            "exactly two targets required",
        )
        peers = tuple(Target.parse(item) for item in value["peers"])
        require(
            peers[0].ssh_alias != peers[1].ssh_alias,
            "distinct explicit targets required",
        )
        fields["peers"] = peers
        return cls(**fields)


def candidate_files(config):
    """Validate every ownership/binding before reading or hashing any binary."""
    receipt = read_json(config.build_receipt)
    require(
        receipt.get("platform") == "darwin/arm64"
        and receipt.get("owned_candidate_root") == str(config.candidate_directory),
        "candidate receipt root/platform mismatch",
    )
    results = receipt.get("results")
    require(
        type(results) is list
        and len(results) == 3
        and all(
            type(row) is dict
            and row.get("actual_wait") is True
            and type(row.get("exit_code")) is int
            and row["exit_code"] == 0
            for row in results
        ),
        "candidate build Wait proof missing",
    )
    files = receipt.get("files")
    require(
        type(files) is dict and set(files) == {"gateway", "delegate", "delegate-run"},
        "candidate roles mismatch",
    )
    paths = []
    for role in ("gateway", "delegate", "delegate-run"):
        item = files[role]
        require(
            type(item) is dict
            and item.get("owned_build") is True
            and item.get("path") == str(config.candidate_directory / role),
            "candidate provenance mismatch",
        )
        path = owned_path(item["path"])
        info = path.stat()
        require(
            info.st_nlink == 1
            and info.st_size <= bootstrap.MAX_FILE_BYTES
            and os.access(path, os.X_OK),
            "invalid owned candidate",
        )
        require(
            type(item.get("size")) is int
            and item["size"] == info.st_size
            and type(item.get("sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]),
            "candidate receipt metadata mismatch",
        )
        paths.append((role, path, item, info))
    result = []
    for role, path, item, before in paths:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            held = os.fstat(fd)
            require(
                stat.S_ISREG(held.st_mode)
                and held.st_uid == os.getuid()
                and held.st_nlink == 1
                and (
                    held.st_dev,
                    held.st_ino,
                    held.st_size,
                    held.st_mtime_ns,
                    held.st_ctime_ns,
                )
                == (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ),
                "candidate binding changed before read",
            )
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(item["size"] + 1)
            after = os.fstat(fd)
            require(
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                == (held.st_size, held.st_mtime_ns, held.st_ctime_ns),
                "candidate changed during read",
            )
        finally:
            os.close(fd)
        require(
            len(data) == item["size"]
            and hashlib.sha256(data).hexdigest() == item["sha256"],
            "candidate digest mismatch",
        )
        result.append(TransferFile("bin/" + role, data, True))
    return tuple(result)


@dataclass(frozen=True)
class TransferFile:
    path: str
    data: bytes
    executable: bool = False

    def metadata(self):
        return {
            "path": self.path,
            "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "executable": self.executable,
        }


def freeze_sources(config, harness):
    files = list(candidate_files(config))
    root = Path(__file__).resolve().parent.parent
    for relative in sorted(bootstrap.GATEWAY_SOURCES):
        path = owned_path(str(root / relative.removeprefix("gateway/")))
        files.append(TransferFile(relative, path.read_bytes()))
    # Git runs through the same Native owner as all other local children.
    process = harness.processes.run(
        "tracked-native-sources",
        [
            "/usr/bin/git",
            "-C",
            str(config.delegate_repository),
            "ls-files",
            "-z",
            "--",
            "scripts/__init__.py",
            "scripts/acceptance",
            *(
                path.removeprefix("native/")
                for path in sorted(bootstrap.NATIVE_DATA_SOURCES)
            ),
        ],
        harness.base,
        timeout=10,
    )
    require(
        process.stdout_path.stat().st_size <= 1 << 20, "tracked source list too large"
    )
    names = process.stdout_path.read_bytes().decode().split("\0")
    for name in sorted(
        name
        for name in names
        if name.endswith(".py") or "native/" + name in bootstrap.NATIVE_DATA_SOURCES
    ):
        relative = "native/" + name
        require(bootstrap.allowed_path(relative), "unallowlisted Native source")
        path = owned_path(str(config.delegate_repository / name))
        require(path.stat().st_size <= 1 << 20, "source too large")
        files.append(TransferFile(relative, path.read_bytes()))
    required = {
        *bootstrap.NATIVE_DATA_SOURCES,
        "native/scripts/acceptance/__init__.py",
        "native/scripts/acceptance/processes/operations.py",
        "native/scripts/acceptance/private_cli/fixtures.py",
        "native/scripts/acceptance/private_cli/supervisor.py",
        "native/scripts/acceptance/private_cli/leases.py",
        "native/scripts/acceptance/directories/operations.py",
    }
    require(required <= {item.path for item in files}, "required Native source missing")
    require(
        len(files) <= bootstrap.MAX_FILES
        and sum(len(item.data) for item in files) <= bootstrap.MAX_TOTAL_BYTES,
        "transfer limits exceeded",
    )
    source = owned_path(
        str(Path(__file__).with_name("e2e_remote_bootstrap.py").resolve())
    ).read_bytes()
    require(0 < len(source) <= 128 << 10, "bootstrap source too large")
    return source, tuple(files)


def installed_ssh() -> Path:
    selected = shutil.which("ssh")
    require(selected is not None, "installed SSH executable unavailable")
    try:
        executable = Path(selected).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise local.ProofFailure("installed SSH executable unavailable") from error
    require(
        executable.is_absolute()
        and executable.is_file()
        and os.access(executable, os.X_OK),
        "installed SSH executable invalid",
    )
    return executable


def ssh_argv(executable: Path, target: Target) -> tuple[str, ...]:
    require(
        isinstance(executable, Path)
        and executable.is_absolute()
        and executable.is_file()
        and os.access(executable, os.X_OK),
        "absolute SSH executable required",
    )
    return (
        str(executable),
        "-T",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oControlMaster=no",
        "-oControlPath=none",
        "-oControlPersist=no",
        "-oForwardAgent=no",
        "-oClearAllForwardings=yes",
        "-oProxyCommand=none",
        "-oProxyJump=none",
        "-oPermitLocalCommand=no",
        "-oConnectTimeout=10",
        "--",
        target.ssh_alias,
        SSH_COMMAND,
    )


def durable_record(path, value):
    with path.open("x", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass
class RemoteRoot:
    target: Target
    run_id: str
    channel: PeerChannel
    device: str
    alias: str = "fixture-project"
    context: dict = field(default_factory=dict)
    tasks: list = field(default_factory=list)
    workspace: str = ""
    initialized: bool = False
    operations: int = 0
    # Conservative successful request start; reply delay never refreshes peer idle age.
    last_activity: float = field(default_factory=time.monotonic)
    final: dict | None = None
    wait: dict | None = None
    pump: Callable[[], None] | None = None
    in_operation: bool = False
    before_operation: Callable[[], None] | None = None
    closing: bool = False

    @property
    def stage(self):
        return self.target.expected_home + "/gs-" + self.run_id

    @property
    def base(self):
        return self.target.expected_home + "/gp-" + self.run_id

    def operate(self, operation, **fields):
        require(
            self.initialized and self.operations < peer.MAX_OPERATIONS,
            "peer operation budget exhausted",
        )
        require(not self.in_operation, "peer operation already active")
        self.operations += 1
        self.in_operation = True
        try:
            if self.before_operation is not None:
                self.before_operation()
            request_started = time.monotonic()
            self.channel.send_json(
                {"operation": operation, **fields},
                expected_event=operation,
                timeout=10,
                pump=self.pump,
            )
            result = self.channel.expect(
                operation, timeout=40 if operation == "shutdown" else 15, pump=self.pump
            )
            self.last_activity = request_started
            return result
        finally:
            self.in_operation = False

    def heartbeat(self, *, force=False):
        if (
            not self.initialized
            or self.closing
            or self.in_operation
            or self.final is not None
            or self.channel.failure is not None
            or self.channel.process is None
        ):
            return
        if self.channel.process.poll() is not None:
            return
        if force or time.monotonic() - self.last_activity >= PEER_HEARTBEAT_SECONDS:
            self.operate("inspect_closure")


def bootstrap_peer(root, harness, source, files, manifest, pump=None):
    durable_record(
        harness.base / (root.run_id + "-resources.json"),
        {
            "schema_version": 1,
            "run_id": root.run_id,
            "ssh_alias": root.target.ssh_alias,
            "expected_home": root.target.expected_home,
            "expected_uid": root.target.expected_uid,
            "stage": root.stage,
            "peer_final": root.base + "/peer-final.json",
        },
    )
    root.channel.start(harness.processes, "ssh-" + root.run_id, harness.base)
    header = json.dumps(
        {
            "schema_version": 1,
            "run_id": root.run_id,
            "expected_home": root.target.expected_home,
            "expected_uid": root.target.expected_uid,
            "files": [item.metadata() for item in files],
        },
        separators=(",", ":"),
    ).encode()
    require(len(header) <= bootstrap.MAX_HEADER, "bootstrap header too large")
    deadline = time.monotonic() + 110
    for data in (
        struct.pack("!I", len(source)),
        source,
        struct.pack("!I", len(header)),
        header,
    ):
        root.channel.write_bytes(
            data, timeout=max(0.001, deadline - time.monotonic()), pump=pump
        )
    for item in files:
        for offset in range(0, len(item.data), bootstrap.CHUNK_BYTES):
            root.channel.write_bytes(
                item.data[offset : offset + bootstrap.CHUNK_BYTES],
                timeout=max(0.001, deadline - time.monotonic()),
                pump=pump,
            )
    ready = root.channel.expect(
        "bootstrap_ready", timeout=max(0.001, deadline - time.monotonic()), pump=pump
    )
    require(
        ready.get("schema_version") == 1
        and ready.get("run_id") == root.run_id
        and ready.get("home") == root.target.expected_home
        and ready.get("uid") == root.target.expected_uid
        and ready.get("stage") == root.stage,
        "bootstrap locator binding mismatch",
    )
    version = ready.get("python_version")
    require(
        type(version) is list
        and len(version) == 3
        and all(type(part) is int for part in version)
        and tuple(version) >= (3, 12, 0),
        "remote Python version missing",
    )
    canonical_text(ready.get("python_executable"))
    durable_record(harness.base / (root.run_id + "-bootstrap.json"), ready)
    # Ready is tentative; initialized alone establishes peer handoff.
    request_started = time.monotonic()
    root.channel.send_json(
        manifest, expected_event="initialized", timeout=10, pump=pump
    )
    initialized = root.channel.expect("initialized", timeout=40, pump=pump)
    require(
        initialized.get("base") == root.base
        and initialized.get("state") == root.base + "/d/s"
        and initialized.get("allocation") == 2
        and initialized.get("project_alias") == root.alias
        and initialized.get("providers")
        == [
            {
                "provider": "pi:json",
                "models": ["openai/gpt-4.1"],
                "max_budget_seconds": 30,
            }
        ],
        "peer identity/budget mismatch",
    )
    context = initialized.get("context")
    require(
        type(context) is dict
        and all(
            type(context.get(key)) is str and 0 < len(context[key]) <= 1024
            for key in ("root_token", "project_token")
        ),
        "peer context missing",
    )
    require(
        initialized.get("workspace") == root.base + "/d/project-canary",
        "peer workspace binding mismatch",
    )
    if manifest.get("capture_native", False):
        require(
            initialized.get("native_control_variant") == "diagnostic_capture",
            "diagnostic Native capture variant missing",
        )
    root.context = context
    root.workspace = initialized["workspace"]
    root.initialized = True
    root.last_activity = request_started


def require_closed(root, task):
    value = root.operate("inspect_closure")
    record = value.get("tasks", {}).get(task, {})
    require(
        value.get("closure_confirmed") is True
        and record.get("cause") == "requested"
        and record.get("scope_empty") is True
        and record.get("worker_wait") is not None
        and record.get("worker_wait_result") in ("success", "exit-error")
        and datetime.fromisoformat(record["worker_wait"].replace("Z", "+00:00"))
        < datetime.fromisoformat(record["deadline"].replace("Z", "+00:00")),
        "requested task closure before deadline unconfirmed",
    )


def check_revoked_visibility(h, revoked, other):
    denied = h.mcp(
        "get_capabilities",
        {"device_id": revoked.device, "project_alias": revoked.alias},
        failure=True,
    )
    require(
        denied.get("code") == "not_found",
        "revoked device did not return the required authorization denial",
    )
    devices = h.mcp("list_devices", {})["devices"]
    require(
        len(devices) == 1
        and devices[0].get("device_id") == other.device
        and devices[0].get("online") is True,
        "revoked device inventory visibility or independent peer changed",
    )


def fixture_scenarios(h, roots):
    """Exactly two accepted tasks per target; retries retain operation identity."""
    h.brief_canary = "E2E_PRIVATE_BRIEF_" + uuid.uuid4().hex
    listed = h.mcp("list_devices", {})["devices"]
    require(
        {row["device_id"] for row in listed} == {root.device for root in roots}
        and all(row["online"] for row in listed),
        "two explicit devices missing",
    )
    for device, alias, budget in (
        (roots[0].device, "missing-project", 30),
        ("missing-device", roots[0].alias, 30),
        (roots[0].device, roots[0].alias, 31),
    ):
        h.mcp(
            "prepare_dispatch",
            {
                "device_id": device,
                "project_alias": alias,
                "brief": "denied fixture selection",
                "provider": "pi:json",
                "permission": "read-only",
                "model": "openai/gpt-4.1",
                "budget_seconds": budget,
            },
            failure=True,
        )
    expected = b"private supervisor acceptance passed"
    for root in roots:
        prepared = h.prepare(
            root, "Return controlled fixture sentence. " + h.brief_canary
        )
        handle = {"operation_id": prepared["operation_id"]}
        dispatched = h.mcp("dispatch_task", handle)
        require(
            dispatched["task_id"] == prepared["task_id"]
            and dispatched["device_id"] == root.device,
            "dispatch binding changed",
        )
        final = h.await_operation(prepared["operation_id"], result=True)
        descriptor = final["observation"]["result"]
        chunk = h.mcp(
            "read_result_chunk",
            {**handle, "descriptor": descriptor, "offset": 0, "limit": 65536},
        )
        require(
            base64.b64decode(chunk["data_base64"], validate=True) == expected
            and descriptor["sha256"] == hashlib.sha256(expected).hexdigest()
            and descriptor["length"] == len(expected),
            "accepted result bytes/descriptor mismatch",
        )
    active = []
    # Conservative local bound starts before either admission. Canonical peer
    # deadlines remain the authority for actual native termination evidence.
    cancellation_deadline = time.monotonic() + 25
    for root in roots:
        root.operate("hold_fixture")
        prepared = h.prepare(root, "DELEGATE_PRIVATE_SILENCE_WAIT")
        h.mcp("dispatch_task", {"operation_id": prepared["operation_id"]})
        active.append((root, prepared))
    for _ in range(2):
        for root, prepared in active:
            live = root.operate("wait_fixture_started", task_id=prepared["task_id"])
            require(
                live.get("task_id") == prepared["task_id"]
                and live.get("live_lease_proven") is True
                and live.get("attempts")
                == {"attempted": 2, "rejected_concurrent": 0, "rejected_limit": 0},
                "overlapping fixture lease/attempt proof missing",
            )
    h.restart_gateway()
    for root, prepared in active:
        h.until(
            lambda r=root: h.capability_online(r.device, r.alias),
            10,
            "same-registry connector reconnect",
        )
        handle = {"operation_id": prepared["operation_id"]}
        recovery.require_active_operation(
            h.mcp("resolve_operation", handle), root, prepared
        )
        recovery.require_dispatch_retry(h.mcp("dispatch_task", handle), root, prepared)
        recovery.require_active_operation(
            h.mcp("resolve_operation", handle), root, prepared
        )
        live = root.operate("wait_fixture_started", task_id=prepared["task_id"])
        require(
            live.get("task_id") == prepared["task_id"]
            and live.get("live_lease_proven") is True
            and live.get("attempts")
            == {"attempted": 2, "rejected_concurrent": 0, "rejected_limit": 0},
            "restart changed fixture attempt count",
        )
    for root, prepared in active:
        operation = prepared["operation_id"]
        cancel = {
            "operation_id": operation,
            "cancellation_id": h.operations[operation]["cancellation_id"],
        }
        for _ in range(2):
            require(
                time.monotonic() < cancellation_deadline,
                "fixture cancellation schedule exceeded finite budget",
            )
            result = h.mcp("cancel_task", cancel)
            require(
                time.monotonic() < cancellation_deadline,
                "fixture cancellation acknowledgement exceeded finite budget",
            )
            require(
                result["cancellation_id"] == cancel["cancellation_id"],
                "cancel identity changed",
            )
    for root, prepared in active:
        h.await_operation(prepared["operation_id"])
        require_closed(root, prepared["task_id"])
        root.operate("release_fixture")
    h.check_canaries()
    # Device revocation occurs only after all four public operations closed.
    h.admin("revoke-device", {"device_id": roots[0].device, "revoked": True})
    check_revoked_visibility(h, roots[0], roots[1])
    h.restart_gateway()
    h.until(
        lambda: h.capability_online(roots[1].device, roots[1].alias),
        10,
        "independent connector reconnect after revocation",
    )
    check_revoked_visibility(h, roots[0], roots[1])
    h.summary["fixture_tasks_executed"] = 4
    h.summary["revocation_acceptance"] = "public_authorization_and_inventory_visibility"
    # Public visibility does not observe a revoked certificate handshake attempt.
    h.summary["revoked_certificate_reconnect_denial"] = "unverified"
    h.summary["stages"].append(
        "two_mac_four_fixture_attempts_restart_cancel_authorization_visibility"
    )


class RemoteHarness(local.Harness):
    """Service the fixed peer roster at local blocking boundaries.

    Controller installs the callback once. This harness owns only its reentry
    guard; RemoteRoot remains the authority for peer operation scheduling.
    """

    def __init__(self, args, interruptions):
        self.peer_pump: Callable[[], None] | None = None
        self._pumping = False
        super().__init__(args, interruptions)

    def pump_peers(self):
        if self.peer_pump is None or self._pumping:
            return
        self._pumping = True
        try:
            self.peer_pump()
        finally:
            self._pumping = False

    @contextmanager
    def _serviced(self):
        self.pump_peers()
        try:
            yield
        finally:
            self.pump_peers()

    def command(self, executable, arguments, env=None, cwd=None, expected=0):
        with self._serviced():
            return super().command(executable, arguments, env, cwd, expected)

    def admin(self, action, value, output=None):
        with self._serviced():
            return super().admin(action, value, output)

    def mcp(self, tool, arguments, failure=False):
        with self._serviced():
            return super().mcp(tool, arguments, failure)

    def until(self, check, seconds, description):
        def serviced_check():
            with self._serviced():
                return check()

        return super().until(serviced_check, seconds, description)

    def stop_process(self, process):
        with self._serviced():
            return super().stop_process(process)

    def check_auth(self):
        with self._serviced():
            return super().check_auth()


def target_roster(config: Config, diagnostic_target: str | None):
    if diagnostic_target is None:
        return tuple(enumerate(config.peers))
    require(type(diagnostic_target) is str, "explicit diagnostic target required")
    selected = tuple(
        (index, target)
        for index, target in enumerate(config.peers)
        if target.ssh_alias == diagnostic_target
    )
    require(
        len(selected) == 1, "diagnostic target must exactly match one configured alias"
    )
    return selected


class Controller:
    def __init__(self, config, interruptions, diagnostic_target: str | None = None):
        self.config = config
        self.diagnostic_target = diagnostic_target
        self.targets = target_roster(config, diagnostic_target)
        selected = self.targets[0][1]
        args = SimpleNamespace(
            gateway=config.gateway,
            fixture_tool=config.fixture_tool,
            delegate_repository=config.delegate_repository,
            work_parent=config.work_parent,
            capture_native=diagnostic_target is not None,
            delegate=config.candidate_directory / "delegate",
            delegate_run=config.candidate_directory / "delegate-run",
            pueue=Path(selected.pueue),
            pueued=Path(selected.pueued),
        )
        self.ssh = installed_ssh()
        self.h = RemoteHarness(args, interruptions)
        self.roots = []
        self.h.peer_pump = self.pump_peers
        self.h.summary.pop("connector_processes", None)
        self.h.summary.update(
            expected_connector_targets=len(self.targets),
            category=(
                "diagnostic_native_capture"
                if diagnostic_target is not None
                else "physical two-Mac zero-cost fixture"
            ),
            physical_device_acceptance="unverified",
            multi_network_acceptance="unverified",
            real_provider_acceptance="unverified",
            cloud_client_acceptance="unverified",
            max_active_fixture_tasks=0 if diagnostic_target is not None else 2,
            fixture_task_limit=0 if diagnostic_target is not None else 4,
        )

    def pump_peers(self, *, force=False, exclude: RemoteRoot | None = None):
        for root in self.roots:
            if root is not exclude:
                root.heartbeat(force=force)

    def run(self):
        h, config = self.h, self.config
        source, files = freeze_sources(config, h)
        for index, target in self.targets:
            link = PeerChannel(h.acceptance.processes, ssh_argv(self.ssh, target))
            self.roots.append(
                RemoteRoot(
                    target,
                    uuid.uuid4().hex[:16],
                    link,
                    "fixture-device-" + str(index + 1),
                )
            )

        def capture(argv):
            for root in self.roots:
                if tuple(argv) == root.channel.argv:
                    return root.channel.capture_factory(argv)
            return None

        def drain_others(current):
            for other in self.roots:
                if other is not current and other.channel.process is not None:
                    other.channel.process.poll()

        for root in self.roots:
            root.pump = lambda current=root: drain_others(current)
            root.before_operation = h.pump_peers
        h.processes.stdout_capture_factory = capture
        h.start_network(listen_ip=config.listen_ip)
        for root in self.roots:
            manifest = {
                "schema_version": 1,
                "run_id": root.run_id,
                "gateway": root.stage + "/bin/gateway",
                "delegate": root.stage + "/bin/delegate",
                "delegate_run": root.stage + "/bin/delegate-run",
                "pueue": root.target.pueue,
                "pueued": root.target.pueued,
                "delegate_repository": root.stage + "/native",
                "allocation": 2,
                "ca_pem": Path(h.material["ca_file"]).read_text(),
                "device_ca_pem": Path(
                    h.material["device_ca"]["certificate"]
                ).read_text(),
                "gateway_id": h.gateway_id,
                "device_id": root.device,
                "project_alias": root.alias,
                "enrollment_url": h.public + "/v1/enroll",
                "wss_url": h.device_url,
            }

            if self.diagnostic_target is not None:
                manifest["capture_native"] = True

            def pump(current=root):
                for other in self.roots:
                    if other is not current and other.channel.process is not None:
                        other.heartbeat()

            bootstrap_peer(root, h, source, files, manifest, pump)
            h.roots.append(root)
            h.admin("register-device", {"device_id": root.device, "name": root.device})
            binding = {
                "device_id": root.device,
                "project_alias": root.alias,
                "root_guard": local.context_guard(root.context["root_token"]),
                "project_guard": local.context_guard(root.context["project_token"]),
            }
            h.admin("register-project", binding)
            if self.diagnostic_target is None:
                h.grant_root(root)
            else:
                h.admin(
                    "put-grant",
                    {
                        "principal_id": h.principal,
                        "device_id": root.device,
                        "project_alias": root.alias,
                        "scopes": ["inventory:read"],
                        "providers": ["pi:json"],
                        "permissions": ["read-only"],
                        "max_budget_seconds": 30,
                    },
                )
            enrollment = h.admin(
                "issue-enrollment-token",
                {"device_id": root.device, "mode": "regular", "generation": 1},
                output=h.base / (root.run_id + "-enrollment.json"),
            )
            root.operate("enroll", enrollment=enrollment)
            root.operate("start_connector")
            h.until(
                lambda r=root: h.capability_online(r.device, r.alias),
                20,
                "authenticated connector handshake",
            )
            if self.diagnostic_target is not None:
                refreshed = h.admin("refresh-project", binding)
                require(
                    refreshed.get("alias") == root.alias
                    and refreshed.get("context")
                    == {
                        "root": binding["root_guard"],
                        "project": binding["project_guard"],
                    },
                    "diagnostic project refresh changed selected binding",
                )
                require(
                    not h.operations and not root.tasks,
                    "diagnostic must stop before task admission",
                )
                h.summary.update(result="diagnostic_rpc_completed")
                h.summary["stages"].append(
                    "one_selected_connector_fresh_project_inspection"
                )
                return
            for _ in range(6):
                if h.admin("initialize-root", binding)["stage"] == "ready":
                    break
            else:
                raise local.ProofFailure("bounded root initialization failed")
            h.until(
                lambda r=root: h.mcp(
                    "get_capabilities",
                    {"device_id": r.device, "project_alias": r.alias},
                )["delegate_ready"],
                10,
                "native readiness publication",
            )
        fixture_scenarios(h, self.roots)
        h.summary["physical_device_acceptance"] = "passed_fixture_only"
        h.summary["result"] = "passed"

    def finish(self):
        """Never equate transport exit or cleanup receipts with task closure."""
        h = self.h
        faults = []
        with h.interruptions.cleanup():
            # Public cancellation keeps the original IDs; no fresh task admission.
            for operation, record in h.operations.items():
                if operation in h.closed_operations:
                    continue
                try:
                    h.mcp(
                        "cancel_task",
                        {
                            "operation_id": operation,
                            "cancellation_id": record["cancellation_id"],
                        },
                    )
                    h.await_operation(operation)
                except Exception as error:
                    faults.append(
                        {"stage": "public_cancel", "kind": type(error).__name__}
                    )
            if h.gateway is not None:
                try:
                    h.stop_process(h.gateway)
                except Exception as error:
                    faults.append(
                        {"stage": "gateway_join", "kind": type(error).__name__}
                    )
            for root in self.roots:
                root.closing = True
                try:
                    # Refresh before shutdown (send/reply <=50s, final <=10s).
                    # Other peers are refreshed again before the <=45s local join.
                    self.pump_peers(force=True)
                    if root.initialized and root.channel.failure is None:
                        shutdown = root.operate("shutdown")
                        root.final = root.channel.expect("final", timeout=10)
                        require(
                            {
                                key: value
                                for key, value in shutdown.items()
                                if key != "event"
                            }
                            == {
                                key: value
                                for key, value in root.final.items()
                                if key != "event"
                            },
                            "peer final receipt changed",
                        )
                except Exception as error:
                    faults.append(
                        {"stage": "peer_shutdown", "kind": type(error).__name__}
                    )
                finally:
                    root.channel.close_input()
                try:
                    # The closing peer must receive no further input. A sibling
                    # refresh failure is retained but never skips this child's Wait.
                    self.pump_peers(force=True, exclude=root)
                except Exception as error:
                    faults.append(
                        {"stage": "pre_join_peer_refresh", "kind": type(error).__name__}
                    )
                try:
                    if root.channel.process is not None:
                        root.wait = root.channel.join(timeout=45)
                    require(
                        root.wait is not None
                        and root.wait.get("natural_wait") is True
                        and root.wait.get("exit_code") == 0
                        and root.final is not None
                        and root.final.get("base") == root.base
                        and root.final.get("cleanup_confirmed") is True,
                        "remote exit/cleanup unconfirmed; retain known locators",
                    )
                    if h.summary.get("category") == "diagnostic_native_capture":
                        require(
                            root.final.get("attempts")
                            == {
                                "attempted": 0,
                                "rejected_concurrent": 0,
                                "rejected_limit": 0,
                            },
                            "diagnostic peer reported a fixture attempt",
                        )
                except Exception as error:
                    faults.append(
                        {
                            "stage": "ssh_join_remote_closure",
                            "kind": type(error).__name__,
                        }
                    )
                # Native has finalized its capture only after exact Wait.
                if root.wait is not None:
                    root.channel.capture.close()
            if h.jwks is not None:
                if h.jwks_thread is not None:
                    h.jwks.shutdown()
                    h.jwks_thread.join()
                h.jwks.server_close()
            if not h.processes.finished_naturally():
                # Passive bounded drain only. Never invent a local force-kill path.
                if h.processes.drain(timeout=10):
                    faults.append({"stage": "local_native_wait", "kind": "unconfirmed"})
            try:
                h.ownership.release()
            except Exception as error:
                faults.append({"stage": "owner_release", "kind": type(error).__name__})
        h.summary.update(
            cleanup_confirmed=not faults,
            paths_removed=False,
            cleanup_errors=faults,
            remote_receipts=[
                {
                    "run_id": root.run_id,
                    "final": root.final,
                    "ssh_wait": root.wait,
                    "operations": root.operations,
                }
                for root in self.roots
            ],
        )
        if h.interruptions.finalize_cleanup():
            h.summary["cleanup_confirmed"] = False
        if not h.summary["cleanup_confirmed"]:
            h.summary["physical_device_acceptance"] = "unverified"
        if h.summary.get("result") == "diagnostic_rpc_completed":
            h.summary["result"] = (
                "diagnostic_completed" if h.summary["cleanup_confirmed"] else "failed"
            )
            if h.summary["cleanup_confirmed"]:
                h.summary["fixture_tasks_executed"] = 0
        durable_record(h.base / "summary.json", h.summary)
        return h.summary["cleanup_confirmed"]


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-remote-fixtures", action="store_true", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--diagnose-native-target", metavar="ALIAS")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    os.umask(0o077)
    interruptions = local.Interruptions()
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interruptions.handle)
    controller = None
    success = False
    cleanup = False
    failure = None
    try:
        config = Config.parse(read_json(owned_path(str(args.config))))
        target_roster(
            config, args.diagnose_native_target
        )  # Reject before resource creation.
        controller = Controller(config, interruptions, args.diagnose_native_target)
        controller.run()
        success = True
    except Exception as error:
        failure = type(error).__name__
        if controller is not None:
            controller.h.summary.update(
                result="failed",
                failure_kind=failure,
                failure_trace=local.failure_trace(error),
                physical_device_acceptance="unverified",
            )
    finally:
        if controller is not None:
            try:
                cleanup = controller.finish()
            except Exception as error:
                failure = type(error).__name__
    print(
        json.dumps(
            {
                "category": (
                    controller.h.summary["category"]
                    if controller is not None
                    else "diagnostic_native_capture"
                    if args.diagnose_native_target is not None
                    else "physical two-Mac zero-cost fixture"
                ),
                "result": (
                    controller.h.summary["result"] if success and cleanup else "failed"
                ),
                "cleanup_confirmed": cleanup,
                "failure_kind": failure,
                "real_provider_acceptance": "unverified",
                "cloud_client_acceptance": "unverified",
                "multi_network_acceptance": "unverified",
            },
            separators=(",", ":"),
        )
    )
    return int(not (success and cleanup))


if __name__ == "__main__":
    raise SystemExit(main())
