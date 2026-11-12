#!/usr/bin/env python3
"""Private stdin peer for fixture proof or a finite connector-only hold.

The caller supplies the first JSON line and fixed operations on subsequent lines.
Delegate remains the task authority. The selected owner controls fixture resources
or only its connector child and receipts; this peer never launches SSH itself.
EOF requests cleanup, never supplies task-stop evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from contextlib import ExitStack
import base64
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import ssl
import stat
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import e2e_local as local


MAX_LINE = 64 << 10
MAX_OPERATIONS = 32
REQUEST_FIELDS = frozenset({"request_id", "payload"})
OUTPUT_TIMEOUT = 2.0
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
RUN_ID = re.compile(r"[0-9a-f]{16}\Z")
TASK_ID = re.compile(r"[0-9a-f]{32}\Z")


def exact(value, keys):
    local.require(
        type(value) is dict and set(value) == set(keys), "invalid peer fields"
    )


def owned_path(value, *, executable=False):
    local.require(type(value) is str and len(value) <= 4096, "invalid owned path")
    path = Path(value)
    local.require(path.is_absolute(), "absolute owned path required")
    path = path.resolve(strict=True)
    info = path.stat()
    local.require(info.st_uid == os.getuid(), "path is not caller owned")
    if executable:
        local.require(
            stat.S_ISREG(info.st_mode) and os.access(path, os.X_OK),
            "executable required",
        )
    else:
        local.require(path.is_dir(), "repository directory required")
    return path


def endpoint(value, scheme, path):
    local.require(type(value) is str and len(value) <= 2048, "invalid endpoint")
    parsed = urlsplit(value)
    local.require(
        parsed.scheme == scheme
        and parsed.path == path
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment,
        "invalid fixture endpoint",
    )
    address = ipaddress.ip_address(parsed.hostname or "")
    local.require(
        not address.is_unspecified and not address.is_multicast,
        "invalid fixture address",
    )
    local.require(
        parsed.port is not None and 1 <= parsed.port <= 65535, "explicit port required"
    )
    return str(address)


@dataclass(frozen=True)
class Manifest:
    run_id: str
    gateway: Path
    delegate: Path
    delegate_run: Path
    pueue: Path
    pueued: Path
    delegate_repository: Path
    allocation: int
    ca_pem: str
    device_ca_pem: str
    gateway_id: str
    device_id: str
    project_alias: str
    enrollment_url: str
    wss_url: str
    capture_native: bool = False

    @classmethod
    def parse(cls, value):
        fields = {"schema_version", *cls.__dataclass_fields__}
        if type(value) is dict and "capture_native" not in value:
            fields.remove("capture_native")
        exact(value, fields)
        capture_native = value.get("capture_native", False)
        local.require(type(capture_native) is bool, "capture_native must be a boolean")
        local.require(
            type(value["schema_version"]) is int and value["schema_version"] == 1,
            "unsupported peer schema",
        )
        validate_run_id(value["run_id"])
        local.require(
            type(value["allocation"]) is int and value["allocation"] in (1, 2),
            "allocation must be one or two",
        )
        for key in ("gateway_id", "device_id", "project_alias"):
            local.require(
                type(value[key]) is str and IDENTIFIER.fullmatch(value[key]),
                "invalid fixture identity",
            )
        for key in ("ca_pem", "device_ca_pem"):
            cert = value[key]
            local.require(
                type(cert) is str and len(cert) <= 16384 and "PRIVATE KEY" not in cert,
                "public CA certificate required",
            )
            ssl.PEM_cert_to_DER_cert(cert)
        public = endpoint(value["enrollment_url"], "https", "/v1/enroll")
        device = endpoint(value["wss_url"], "wss", "/device")
        local.require(
            public == device, "fixture listeners must use the same explicit host"
        )
        fields = {
            key: value[key]
            for key in cls.__dataclass_fields__
            if key != "capture_native"
        }
        fields["capture_native"] = capture_native
        for key in (
            "gateway",
            "delegate",
            "delegate_run",
            "pueue",
            "pueued",
            "delegate_repository",
        ):
            fields[key] = owned_path(
                value[key], executable=key != "delegate_repository"
            )
        validate_selected_pairs(
            fields["delegate"],
            fields["delegate_run"],
            fields["pueue"],
            fields["pueued"],
        )
        return cls(**fields)


def validate_run_id(value):
    local.require(
        type(value) is str and RUN_ID.fullmatch(value),
        "run_id must be 16 lowercase hexadecimal characters",
    )


def run_directory(home, run_id):
    validate_run_id(run_id)
    return home / ("gp-" + run_id)


def validate_selected_pairs(delegate, runner, client, daemon):
    local.require(
        delegate.name == "delegate"
        and runner.name == "delegate-run"
        and delegate.parent == runner.parent,
        "selected Delegate and runner must be the adjacent installed pair",
    )
    local.require(
        client.name == "pueue"
        and daemon.name == "pueued"
        and client.parent == daemon.parent,
        "selected supervisor roles must be an adjacent installed pair",
    )
    # Native selection.go selects any colocated bundle entry first, then any
    # ../libexec entry. PATH is considered only when both bundles are absent.
    for directory in (delegate.parent, delegate.parent.parent / "libexec"):
        if any(os.path.lexists(directory / name) for name in ("pueue", "pueued")):
            expected_client = owned_path(str(directory / "pueue"), executable=True)
            expected_daemon = owned_path(str(directory / "pueued"), executable=True)
            local.require(
                (client, daemon) == (expected_client, expected_daemon),
                "selected pair differs from native preferred supervisor bundle",
            )
            return
    # DelegateRoot's closed PATH places this selected client directory before
    # system directories; native resolves the daemon adjacent to that client.


def allocation_wrapper(fixture, counter, base, allocation):
    local.require(
        type(allocation) is int and allocation in (1, 2), "invalid allocation"
    )
    source = local.provider_wrapper(fixture, counter, base)
    # Reuse the audited local attempt/concurrency owner; change only its cap.
    local.require(
        source.count("if count >= 4:") == 1, "maintained allocation contract changed"
    )
    return source.replace("if count >= 4:", f"if count >= {allocation}:")


def enrollment_input(value, device):
    exact(value, {"device_id", "token", "expires_at"})
    local.require(value["device_id"] == device, "enrollment device mismatch")
    token = value["token"]
    local.require(
        type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", token),
        "invalid enrollment token",
    )
    decoded = base64.urlsafe_b64decode(token + "=")
    local.require(
        len(decoded) == 32
        and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == token,
        "noncanonical enrollment token",
    )
    local.require(type(value["expires_at"]) is str, "invalid enrollment expiry")
    expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
    local.require(expiry.tzinfo is not None, "enrollment expiry must have a timezone")
    return dict(value)


def project_closure(closure):
    tasks = {}
    for task, record in closure["tasks"].items():
        termination = record["termination"]
        wait = record["worker_wait"]
        tasks[task] = {
            "cause": termination["cause"] if termination is not None else None,
            "scope_empty": termination["scope_empty"]
            if termination is not None
            else None,
            # A recorded absent disposition is not a native child Wait.
            "worker_wait": wait["observed_at"] if wait is not None else None,
            "worker_wait_result": wait["result"] if wait is not None else None,
            "deadline": record["intent"]["deadline"],
        }
    return tasks


class Peer:
    directory = local.Harness.directory
    input_file = local.Harness.input_file
    until = local.Harness.until
    fixture_attempts = local.Harness.fixture_attempts

    def __init__(self, manifest, interruptions):
        self.manifest = manifest
        self.interruptions = interruptions
        self.acceptance = local.load_acceptance(manifest.delegate_repository)
        self.ownership = self.acceptance.directories.DirectoryOwner()
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        local.require(
            home != Path("/tmp") and Path("/tmp") not in home.parents,
            "actual HOME must be outside /tmp",
        )
        local.require(home.stat().st_uid == os.getuid(), "actual HOME is not owned")
        self.base = run_directory(home, manifest.run_id)
        self.sequence = 0
        self.root = None
        self.connector = None
        self.fixture_snapshot = None
        self.fixture_observers = ExitStack()
        self.fixture_observer = None
        self.enrolled = False
        self.finished = False
        self.cleanup_gate_released = False
        self.shutdown_receipt = None
        self.accepted_commands = set()
        # Validate Darwin's shorter socket limit before creating or starting anything.
        local.require(
            len(os.fsencode(self.base / "d/s")) + 14 <= 100,
            "remote state path exceeds socket bound",
        )
        self.ownership.create("remote peer", self.base, home)
        self.captures = self.ownership.create(
            "native cleanup captures", self.base / "captures", self.base
        )
        self.home = self.directory("home")
        self.temporary = self.directory("tmp")
        ca = self.base / "ca.pem"
        ca.write_text(manifest.ca_pem)
        ca.chmod(0o600)
        self.device_ca = self.base / "device-ca.pem"
        self.device_ca.write_text(manifest.device_ca_pem)
        self.device_ca.chmod(0o600)
        self.material = {"ca_file": str(ca)}
        self.args = SimpleNamespace(
            **{
                key: getattr(manifest, key)
                for key in (
                    "gateway",
                    "delegate",
                    "delegate_run",
                    "pueue",
                    "pueued",
                    "delegate_repository",
                )
            },
            capture_native=manifest.capture_native,
        )
        self.env = local.child_environment(
            self.home,
            self.temporary,
            [manifest.gateway.parent, Path("/usr/bin"), Path("/bin")],
        )
        self.processes = self.acceptance.processes.Processes(
            self.base / "processes",
            environment=self.env,
            owner=self.ownership,
            environment_keys_only=True,
        )

    def command(self, executable, arguments, env=None, cwd=None, expected=0):
        result = local.Harness.command(self, executable, arguments, env, cwd, expected)
        # Only successful bounded one-shot calls whose expected exit was
        # checked may proceed to the independent canonical root cleanup.
        self.accepted_commands.add(id(self.processes.entries[-1]))
        return result

    def initialize(self):
        local.require(self.root is None, "peer already initialized")
        self.interruptions.checkpoint()
        self.root = local.DelegateRoot(self, "d")
        root = self.root
        fixture = root.providers / "pi-maintained"
        (root.providers / "pi").write_text(
            allocation_wrapper(
                fixture, root.counter, self.base, self.manifest.allocation
            )
        )
        root.start()
        result = {
            "base": str(self.base),
            "state": str(root.state),
            "workspace": str(root.workspace),
            "context": root.context,
            "project_alias": self.manifest.project_alias,
            "providers": [
                {
                    "provider": "pi:json",
                    "models": ["openai/gpt-4.1"],
                    "max_budget_seconds": 30,
                }
            ],
            "allocation": self.manifest.allocation,
        }
        if self.manifest.capture_native:
            result["native_control_variant"] = "diagnostic_capture"
        return result

    def enroll(self, enrollment):
        local.require(
            not self.enrolled and self.connector is None, "peer already enrolled"
        )
        enrollment = enrollment_input(enrollment, self.manifest.device_id)
        root, manifest = self.root, self.manifest
        identity = root.base / "identity"
        identity.mkdir(mode=0o700)
        config = {
            "schema_version": 1,
            "gateway_id": manifest.gateway_id,
            "expected_device_id": manifest.device_id,
            "enrollment_url": manifest.enrollment_url,
            "wss_url": manifest.wss_url,
            "trust_ca_file": self.material["ca_file"],
            "device_ca_file": str(self.device_ca),
            "identity_directory": str(identity),
            "delegate_executable": str(root.connector_executable),
            "temporary_directory": str(root.temporary),
            "control_timeout": "30s",
            "network_timeout": "35s",
            "projects": [
                {
                    "alias": manifest.project_alias,
                    "root": str(root.state),
                    "directory": str(root.workspace),
                    "root_token": root.context["root_token"],
                    "project_token": root.context["project_token"],
                    "providers": [
                        {
                            "provider": "pi:json",
                            "models": ["openai/gpt-4.1"],
                            "efforts": [],
                            "permissions": ["read-only"],
                            "max_budget_seconds": 30,
                            "native_model": True,
                            "native_effort": True,
                        }
                    ],
                }
            ],
        }
        self.connector_config = self.input_file(config)
        token_file = self.input_file(enrollment)
        self.command(
            manifest.gateway,
            [
                "connector",
                "enroll",
                "--config",
                self.connector_config,
                "--token-file",
                token_file,
            ],
            root.env,
        )
        self.enrolled = True
        return {"enrolled": True}

    def start_connector(self):
        local.require(
            self.enrolled and self.connector is None, "connector start is not permitted"
        )
        self.interruptions.checkpoint()
        self.connector = self.processes.start(
            "connector-run",
            [
                self.manifest.gateway,
                "connector",
                "run",
                "--config",
                self.connector_config,
            ],
            self.root.base,
            environment=self.root.env,
        )
        self.interruptions.checkpoint()
        return {"started": True, "pid": self.connector.pid, "online": "unverified"}

    def operate(self, value):
        local.require(
            type(value) is dict and type(value.get("operation")) is str,
            "invalid operation",
        )
        operation = value["operation"]
        exact(
            value,
            {"operation", "enrollment"}
            if operation == "enroll"
            else {"operation", "task_id"}
            if operation == "wait_fixture_started"
            else {"operation"},
        )
        local.require(not self.finished, "peer is closed")
        self.interruptions.checkpoint()
        if operation == "enroll":
            return self.enroll(value["enrollment"])
        if operation == "start_connector":
            return self.start_connector()
        if operation == "hold_fixture":
            local.require(
                self.fixture_observer is None,
                "retained fixture observer already binds this snapshot",
            )
            self.root.acquire_fixture_gate()
            self.fixture_snapshot = self.root.fixture_execution_snapshot()
            self.interruptions.checkpoint()
            return {"held": True}
        if operation == "release_fixture":
            self.release_gate(cleanup=False)
            return {"released": True, "task_stop_proven": False}
        if operation == "wait_fixture_started":
            local.require(
                self.root.fixture_gate is not None
                and self.root.fixture_gate.descriptor >= 0
                and self.fixture_snapshot is not None,
                "fixture snapshot and held gate required",
            )
            task_id = value["task_id"]
            local.require(
                type(task_id) is str and TASK_ID.fullmatch(task_id),
                "invalid prepared task identity",
            )
            if self.fixture_observer is None:
                observation, lease = self.fixture_observers.enter_context(
                    self.root.fixture_execution_lease(self.fixture_snapshot, task_id)
                )
                self.fixture_observer = (self.fixture_snapshot, observation, lease)
            snapshot, observation, lease = self.fixture_observer
            local.require(
                snapshot is self.fixture_snapshot and observation.task_id == task_id,
                "fixture observer belongs to another task or snapshot",
            )
            local.require(
                snapshot.root == self.root.state
                and snapshot.nonce == self.root.nonce
                and snapshot.context
                == (
                    self.root.context["root_token"],
                    self.root.context["project_token"],
                ),
                "retained fixture context changed",
            )
            local.require(
                self.root.invocations() == snapshot.executions + 1,
                "retained fixture execution count changed",
            )
            fresh = self.root.fixture_waiters() - snapshot.waiters
            local.require(
                fresh == frozenset({(observation.path.name, *observation.identity)}),
                "retained fixture FIFO identity changed",
            )
            attempts = self.fixture_attempts()
            local.require(
                attempts
                == {
                    "attempted": snapshot.executions + 1,
                    "rejected_concurrent": 0,
                    "rejected_limit": 0,
                },
                "retained fixture attempt evidence changed",
            )
            lease.assert_live()
            return {
                "task_id": observation.task_id,
                "live_lease_proven": True,
                "attempts": attempts,
            }
        if operation == "inspect_closure":
            try:
                closure = self.acceptance.supervisor.read_managed_closure(
                    self.root.state, ()
                )
            except self.acceptance.supervisor.AcceptanceFailure:
                return {"closure_confirmed": False, "reason": "canonical_not_confirmed"}
            return {
                "closure_confirmed": True,
                "tasks": project_closure(closure),
                "cleanup_gate_released": self.cleanup_gate_released,
            }
        if operation == "shutdown":
            return self.finish()
        raise local.ProofFailure("unknown fixed peer operation")

    def release_gate(self, *, cleanup):
        if self.root is not None:
            gate = self.root.fixture_gate
            held = gate is not None and gate.descriptor >= 0
            self.root.release_fixture_gate()
            self.cleanup_gate_released |= cleanup and held and gate.descriptor < 0

    def finish(self):
        if self.finished:
            return self.shutdown_receipt
        confirmed = False
        failure = None
        with self.interruptions.cleanup():
            observer_failure = None
            try:
                self.fixture_observers.close()
            except Exception as error:
                observer_failure = error
            try:
                # Join every registered intake owner, including a child whose
                # start succeeded before publication of self.connector failed.
                for process in self.processes.entries:
                    if process.argv[1:3] == ["connector", "run"]:
                        if process.poll() is None:
                            process.process.send_signal(signal.SIGTERM)
                        local.require(
                            process.wait(45, expected=None) == 0,
                            "connector descendant joins unconfirmed",
                        )
                pending = self.processes.pending(
                    exclude=(
                        ()
                        if self.root is None or self.root.daemon is None
                        else (self.root.daemon,)
                    )
                )
                local.require(
                    not pending, "direct process ownership remains unresolved"
                )
                local.require(
                    observer_failure is None, "fixture observer cleanup unconfirmed"
                )
                local.require(
                    all(
                        process is (self.root.daemon if self.root else None)
                        or (process.result or {}).get("exit_code") == 0
                        or id(process) in self.accepted_commands
                        for process in self.processes.entries
                    ),
                    "abnormal direct child exit retained",
                )
                # Cleanup release is explicitly reported, never mistaken for
                # cancellation/termination-before-budget acceptance evidence.
                self.release_gate(cleanup=True)
                if self.root is not None:
                    self.root.finish()
                local.require(
                    not self.processes.pending(), "process Wait receipts incomplete"
                )
                counts = self.fixture_attempts()
                local.require(
                    counts["attempted"] <= self.manifest.allocation
                    and not counts["rejected_concurrent"]
                    and not counts["rejected_limit"],
                    "fixture allocation evidence failed",
                )
                confirmed = True
            except Exception as error:
                failure = type(error).__name__
            finally:
                # If intake joining failed, this is still a cleanup-induced
                # gate release, with cleanup unconfirmed; no stop is asserted.
                self.release_gate(cleanup=True)
            # Keep evidence even after confirmed cleanup; never unlink roots.
            try:
                self.ownership.release()
            except (OSError, RuntimeError) as error:
                confirmed = False
                failure = type(error).__name__
        self.finished = True
        try:
            counts = self.fixture_attempts()
        except (OSError, ValueError, local.ProofFailure) as error:
            confirmed = False
            failure = type(error).__name__
            counts = None
        self.shutdown_receipt = {
            "cleanup_confirmed": confirmed,
            "cleanup_gate_released": self.cleanup_gate_released,
            "base": str(self.base),
            "failure_kind": failure,
            "attempts": counts,
            "remote_wait_receipts": [
                {
                    "pid": process.pid,
                    "natural_wait": (process.result or {}).get("natural_wait", False),
                    "exit_code": (process.result or {}).get("exit_code"),
                }
                for process in self.processes.entries
            ],
        }
        # Keep cleanup/Wait evidence even when SSH output is blocked or lost.
        local.private_json(self.base / "peer-final.json", self.shutdown_receipt)
        return self.shutdown_receipt


def decode_line(data):
    local.require(
        len(data) <= MAX_LINE and data.endswith(b"\n"),
        "peer line exceeds bound or is incomplete",
    )

    def pairs(items):
        result = {}
        for key, value in items:
            local.require(key not in result, "duplicate peer field")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=pairs)


class HoldDeadline(local.ProofFailure):
    """The separate connector hold expired; cleanup has its own finite budget."""


def lines(stream, interruptions, idle_seconds=120, *, absolute_deadline=None):
    buffer = b""
    deadline = time.monotonic() + idle_seconds

    def check_absolute():
        absolute = absolute_deadline() if absolute_deadline is not None else None
        if absolute is not None and time.monotonic() >= absolute:
            raise HoldDeadline("connector hold deadline exceeded")

    while True:
        interruptions.checkpoint()
        check_absolute()
        local.require(time.monotonic() < deadline, "peer input deadline exceeded")
        ready, _, _ = select.select([stream], [], [], 0.2)
        if not ready:
            continue
        data = os.read(stream.fileno(), 4096)
        if not data:
            local.require(not buffer, "incomplete peer input at EOF")
            return
        buffer += data
        local.require(
            len(buffer.split(b"\n", 1)[0]) <= MAX_LINE, "peer line exceeds bound"
        )
        while b"\n" in buffer:
            check_absolute()
            line, buffer = buffer.split(b"\n", 1)
            yield decode_line(line + b"\n")
            deadline = time.monotonic() + idle_seconds


def emit(value, interruptions):
    data = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    local.require(len(data) <= MAX_LINE, "peer receipt exceeds bound")
    descriptor = sys.stdout.fileno()
    blocking = os.get_blocking(descriptor)
    deadline = time.monotonic() + OUTPUT_TIMEOUT
    offset = 0
    try:
        os.set_blocking(descriptor, False)
        while offset < len(data):
            interruptions.checkpoint()
            remaining = deadline - time.monotonic()
            local.require(remaining > 0, "peer publication deadline exceeded")
            try:
                written = os.write(descriptor, data[offset:])
                local.require(written > 0, "peer publication made no progress")
                offset += written
            except (BlockingIOError, InterruptedError):
                select.select([], [descriptor], [], min(remaining, 0.05))
    finally:
        os.set_blocking(descriptor, blocking)


def request_payload(value, expected_id):
    """The input stream owns one contiguous request sequence, including setup."""
    exact(value, REQUEST_FIELDS)
    request_id = value["request_id"]
    local.require(
        type(request_id) is int
        and request_id == expected_id
        and 1 <= request_id <= 1 + MAX_OPERATIONS,
        "invalid peer request sequence",
    )
    payload = value["payload"]
    local.require(
        type(payload) is dict and not (REQUEST_FIELDS & payload.keys()),
        "invalid peer request payload",
    )
    return payload


def event_frame(event, result, request_id=None):
    """Only this transport boundary writes event and correlation fields."""
    local.require(
        type(result) is dict and not ({"event", "request_id"} & result.keys()),
        "peer response contains transport fields",
    )
    frame = {**result, "event": event}
    if request_id is not None:
        frame["request_id"] = request_id
    return frame


def main():
    os.umask(0o077)
    interruptions = local.Interruptions()
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, interruptions.handle)
    peer = None
    failed = False
    try:
        hold_deadline = [None]
        inputs = lines(
            sys.stdin.buffer, interruptions, absolute_deadline=lambda: hold_deadline[0]
        )
        setup = request_payload(next(inputs), 1)
        selected_mode = os.environ.get("DELEGATION_GATEWAY_ACCEPTANCE_MODE")
        local.require(
            (selected_mode is None and "mode" not in setup)
            or (
                selected_mode == "connector_hold" and setup.get("mode") == selected_mode
            ),
            "bootstrap peer mode mismatch",
        )
        if "mode" in setup:
            local.require(setup["mode"] == "connector_hold", "unknown peer mode")
            from e2e_connector_hold import HoldManifest, ConnectorHold

            manifest = HoldManifest.parse(setup)
            owner = ConnectorHold
        else:
            manifest = Manifest.parse(setup)
            owner = Peer
        # Publish the owner before any initialization can launch children.
        peer = owner.__new__(owner)
        if "mode" in setup:
            peer.__init__(manifest, interruptions, deadline_error=HoldDeadline)
            hold_deadline[0] = peer.deadline
        else:
            peer.__init__(manifest, interruptions)
        emit(event_frame("initialized", peer.initialize(), 1), interruptions)
        for request_id, envelope in enumerate(inputs, start=2):
            value = request_payload(envelope, request_id)
            # Every request re-observes the operation; no cached response is replayed.
            result = peer.operate(value)
            emit(event_frame(value["operation"], result, request_id), interruptions)
            if peer.finished:
                break
    except HoldDeadline:
        pass  # Intentional finite hold expiration still requires exact owned cleanup.
    except Exception as error:
        failed = True
        try:
            emit(
                {"event": "failed", "failure_kind": type(error).__name__}, interruptions
            )
        except (OSError, local.ProofFailure):
            pass
    finally:
        if peer is not None and hasattr(peer, "processes"):
            receipt = peer.finish()
            failed |= not receipt["cleanup_confirmed"]
            try:
                emit(event_frame("final", receipt), interruptions)
            except (OSError, local.ProofFailure):
                failed = True
        elif peer is not None and hasattr(peer, "ownership"):
            peer.ownership.release()
            failed = True
    return int(failed or interruptions.interrupted)


if __name__ == "__main__":
    raise SystemExit(main())
