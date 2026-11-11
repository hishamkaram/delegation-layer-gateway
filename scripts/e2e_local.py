#!/usr/bin/env python3
"""Explicit, zero-cost local process acceptance; never runs by default.

Build the test-only helper with `go build -tags=e2e -o BIN ./internal/e2e`.
All binary/source paths are caller supplied. This proves two local connector
processes, not two physical devices, networks, real providers or cloud clients.
Delegate acceptance owns native resource proof; no canonical records are written.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
from builtins import BaseExceptionGroup
from contextlib import contextmanager
from datetime import datetime
import hashlib
import http.server
import importlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import sys
import tempfile
import textwrap
import threading
import time
import traceback
from types import SimpleNamespace
import urllib.error
import urllib.request
import uuid

from e2e_contracts import (
    CleanupUnconfirmed,
    FixtureExecutionSnapshot,
    FixtureLeaseObservation,
    ProofFailure,
)


AUDITED_PI_FIXTURE_SHA256 = (
    "1dfa264d1719282a8c69db2fd318fbfd9ac5b90a480a919ebe70ff1379c5e365"
)


class Interruptions:
    """Main records signals and delivers interruption only at owned checkpoints."""

    def __init__(self):
        self.interrupted = False
        self.pending = False
        self.cleanup_active = False
        self.finalized = False

    def handle(self, _number, _frame):
        if self.finalized:
            return
        self.interrupted = True
        self.pending = True

    @contextmanager
    def cleanup(self):
        previous_active = self.cleanup_active
        self.cleanup_active = True
        try:
            yield
        finally:
            self.cleanup_active = previous_active

    def finalize_cleanup(self):
        # No signal may create new pending work once cleanup facts are settled.
        self.finalized = True
        pending = self.pending
        self.pending = False
        return pending

    def checkpoint(self):
        if self.pending and not self.cleanup_active and not self.finalized:
            self.pending = False
            raise ProofFailure("harness interrupted; owned cleanup required")


def require(condition, message):
    if not condition:
        raise ProofFailure(message)


def failure_trace(error):
    return [
        {
            "file": Path(frame.filename).name,
            "function": frame.name,
            "line": frame.lineno,
        }
        for frame in traceback.extract_tb(error.__traceback__)[-8:]
    ]


def private_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream)
        stream.write("\n")


def checked_binary(value):
    path = Path(value)
    require(
        path.is_absolute() and path.is_file() and os.access(path, os.X_OK),
        "absolute executable required",
    )
    return path.resolve(strict=True)


def short_root(parent):
    # Linux AF_UNIX sockaddr_un allows at most 107 path bytes. Reserve space for
    # Delegate's longest owner endpoint suffix BEFORE any owner can be started.
    require(
        len(os.fsencode(parent)) + 14 <= 100,
        "fixture state path too long",
    )
    return parent


def context_guard(token):
    return "ctx1_" + hashlib.sha256(token.encode()).hexdigest()


def child_environment(home, temporary, paths, ca=None):
    # An allowlist, never an inherited credential/account environment.
    result = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "TMPDIR": str(temporary),
        "PATH": os.pathsep.join(map(str, paths)),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if ca is not None:
        result["SSL_CERT_FILE"] = str(ca)
        result["SSL_CERT_DIR"] = str(home / "empty-ca-directory")
    return result


def load_acceptance(repository):
    require(
        (repository / "scripts/acceptance/processes/operations.py").is_file(),
        "Delegate acceptance source missing",
    )
    provider_source = repository / "scripts/acceptance/private_cli/fixtures.py"
    require(
        hashlib.sha256(provider_source.read_bytes()).hexdigest()
        == AUDITED_PI_FIXTURE_SHA256,
        "provider fixture source changed; audit before updating source pin",
    )
    sys.path.insert(0, str(repository))
    names = {
        "directories": "scripts.acceptance.directories.operations",
        "processes": "scripts.acceptance.processes.operations",
        "fixtures": "scripts.acceptance.private_cli.fixtures",
        "supervisor": "scripts.acceptance.private_cli.supervisor",
        "leases": "scripts.acceptance.private_cli.leases",
    }
    return SimpleNamespace(
        **{key: importlib.import_module(value) for key, value in names.items()}
    )


def fixture_listen_ip(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        raise ProofFailure(
            "fixture listen IP must be a canonical IPv4 literal"
        ) from None
    require(
        isinstance(value, str)
        and str(address) == value
        and not address.is_unspecified
        and not address.is_multicast
        and not address.is_link_local
        and value != "255.255.255.255",
        "fixture listen IP must be a canonical unicast IPv4 literal",
    )
    return value


def free_port(listen_ip="127.0.0.1"):
    # The CLI accepts addresses, not inherited listeners. A competing bind fails
    # this run explicitly; it never causes a new root or workload retry.
    with socket.socket() as listener:
        listener.bind((listen_ip, 0))
        return listener.getsockname()[1]


class JWKSHandler(http.server.BaseHTTPRequestHandler):
    document = b""

    def do_GET(self):
        if self.path != "/jwks":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.document)))
        self.end_headers()
        self.wfile.write(self.document)

    def log_message(self, *_args):
        pass  # Never log bearer/URL/request values from a fixture server.


def provider_wrapper(fixture, counter, base):
    # The execution budget remains authoritative in provider-count. This
    # separate append-only observation includes attempts rejected by either gate.
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import fcntl
        import os
        import stat
        import sys

        def event(value):
            path = {str(base / "fixture-attempts")!r}
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid() or info.st_nlink != 1:
                    raise RuntimeError("unsafe fixture attempt ledger")
                record = value + b"\\n"
                if os.write(fd, record) != len(record):
                    raise RuntimeError("incomplete fixture attempt event")
                os.fsync(fd)
                parent = os.open({str(base)!r}, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            finally:
                os.close(fd)

        if '--mode' in sys.argv[1:] and '--help' not in sys.argv[1:]:
            event(b'attempt')
            lease = os.open({str(base / "provider-active.lock")!r}, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                event(b'rejected_concurrent')
                raise SystemExit(72)
            os.set_inheritable(lease, True)
            count_path = {str(base / "provider-count")!r}
            count = int(open(count_path).read()) if os.path.exists(count_path) else 0
            if count >= 4:
                event(b'rejected_limit')
                raise SystemExit(73)
            fd = os.open(count_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, str(count + 1).encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            fd = os.open({str(counter)!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, b'execution\\n')
                os.fsync(fd)
            finally:
                os.close(fd)
        os.execv({str(fixture)!r}, [{str(fixture)!r}, *sys.argv[1:]])
        """
    )


def native_capture_launcher(delegate, repository, capture_root):
    script = Path(__file__).with_name("e2e_native_capture.py").resolve()
    arguments = [
        sys.executable,
        str(script),
        "--delegate",
        str(delegate),
        "--repository",
        str(repository),
        "--capture-root",
        str(capture_root),
        "--",
    ]
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import os
        import sys

        os.execv({sys.executable!r}, {arguments!r} + sys.argv[1:])
        """
    )


def native_capture_complete(value):
    return (
        value.get("diagnostic_only") is True
        and value.get("direct_wait_confirmed") is True
        and value.get("cleanup_confirmed") is True
        and value.get("capture_failed") is False
        and value.get("interrupted") is False
        and value.get("output_within_limits") is True
        and type(value.get("child_exit_code")) is int
        and value["child_exit_code"] in (0, 1, 2)
    )


def require_requested_closure(closure, task_id):
    # Input is the maintained validator's canonical, identity-bound root view.
    task = closure["tasks"][task_id]
    termination = task["termination"]
    require(
        termination["cause"] == "requested" and termination["scope_empty"] is True,
        "canonical termination was not requested and empty",
    )
    waited = datetime.fromisoformat(task["worker_wait"]["observed_at"])
    deadline = datetime.fromisoformat(task["intent"]["deadline"])
    require(
        waited < deadline, "actual native Wait completed only after the task budget"
    )


class DelegateRoot:
    def __init__(self, owner, label):
        self.owner = owner
        self.base = owner.directory(label)
        self.state = short_root(self.base / "s")
        self.workspace = self.base / "project-canary"
        self.workspace.mkdir(mode=0o700)
        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        self.temporary = self.base / "tmp"
        self.temporary.mkdir(mode=0o700)
        self.providers = self.base / "provider-bin"
        self.providers.mkdir(mode=0o700)
        self.waiters = self.base / "waiters"
        self.waiters.mkdir(mode=0o700)
        self.config = self.state / ".supervisor/pueue.yml"
        self.native_captures = None
        self.connector_executable = owner.args.delegate
        if owner.args.capture_native:
            self.native_captures = self.base / "native-captures"
            self.native_captures.mkdir(mode=0o700)
            self.connector_executable = self.base / "delegate-capture"
            self.connector_executable.write_text(
                native_capture_launcher(
                    owner.args.delegate,
                    owner.args.delegate_repository,
                    self.native_captures,
                )
            )
            self.connector_executable.chmod(0o700)
        self.gate = self.base / "gate"
        self.fixture_gate = None
        self.nonce = uuid.uuid4().hex
        self.tasks = []
        self.pending = []
        self.daemon = None
        self.context = None
        paths = [
            self.providers,
            owner.args.delegate.parent,
            owner.args.pueue.parent,
            owner.args.pueued.parent,
            Path("/usr/bin"),
            Path("/bin"),
        ]
        self.env = child_environment(
            self.home, self.temporary, paths, owner.material["ca_file"]
        )
        owner.acceptance.fixtures.install_pi_fixture(
            self.providers, self.gate, self.waiters, self.nonce
        )
        self.counter = self.base / "fixture-invocations"
        fixture = self.providers / "pi-maintained"
        (self.providers / "pi").rename(fixture)
        wrapper = provider_wrapper(fixture, self.counter, owner.base)
        (self.providers / "pi").write_text(wrapper)
        (self.providers / "pi").chmod(0o700)

    def command(self, arguments, expected=0):
        return self.owner.command(
            self.owner.args.delegate,
            ["--root", self.state, *arguments, "--json"],
            self.env,
            self.workspace,
            expected,
        )

    def start(self):
        self.command(["supervisor", "ensure-owner"])
        self.close_engine(())  # Empty-root canonical proof before foreground ownership.
        self.daemon = self.owner.processes.start(
            "fixture-pueued",
            [self.owner.args.pueued, "-c", self.config],
            self.base,
            environment=self.env,
        )
        self.owner.until(
            lambda: (
                (
                    self.command(["supervisor", "status"], {0, 1}).get(
                        "supervisor_control"
                    )
                    or {}
                ).get("state")
                == "ready"
            ),
            15,
            "foreground private engine readiness",
        )
        self.command(["context", "enable-connector", "--offline-cutover-confirmed"])
        self.context = self.command(["context", "inspect", "--cwd", self.workspace])[
            "connector"
        ]
        require(
            {"namespace-admission-v1", "namespace-mutation-lease-v1"}.issubset(
                self.context["features"]
            ),
            "Delegate root contract unavailable; offline connector cutover required",
        )
        require(
            self.invocations() == 0,
            "root initialization unexpectedly executed a provider",
        )

    def invocations(self):
        return (
            len(self.counter.read_bytes().splitlines()) if self.counter.exists() else 0
        )

    def fixture_execution_snapshot(self):
        # The maintained reader verifies all actual tasks, including unknown IDs.
        self.owner.acceptance.supervisor.read_managed_closure(self.state, ())
        return FixtureExecutionSnapshot(
            self.state,
            self.nonce,
            (self.context["root_token"], self.context["project_token"]),
            self.invocations(),
            self.fixture_waiters(),
        )

    def fixture_waiters(self):
        entries = set()
        for path in self.waiters.glob(self.nonce + "-*.fifo"):
            info = path.lstat()
            require(
                stat.S_ISFIFO(info.st_mode) and info.st_uid == os.getuid(),
                "fixture waiter is not an owned FIFO",
            )
            pid = path.name[len(self.nonce) + 1 : -5]
            require(
                pid.isascii()
                and pid.isdecimal()
                and int(pid) > 0
                and str(int(pid)) == pid,
                "fixture waiter has an invalid nonce/PID name",
            )
            entries.add((path.name, info.st_dev, info.st_ino))
        return frozenset(entries)

    def wait_fixture_execution(self, before, task_id):
        with self.fixture_execution_lease(before, task_id) as (observation, _lease):
            return observation

    @contextmanager
    def fixture_execution_lease(self, before, task_id):
        require(
            before.root == self.state
            and before.nonce == self.nonce
            and before.context
            == (self.context["root_token"], self.context["project_token"]),
            "fixture snapshot belongs to another root context",
        )
        old = {name: (device, inode) for name, device, inode in before.waiters}

        def new_execution():
            count = self.invocations()
            require(count <= before.executions + 1, "fixture execution count overshot")
            current = self.fixture_waiters()
            for name, device, inode in current:
                require(
                    name not in old or old[name] == (device, inode),
                    "previous fixture waiter inode was replaced",
                )
            fresh = current - before.waiters
            require(len(fresh) <= 1, "multiple new fixture waiter identities")
            return (
                next(iter(fresh)) if count == before.executions + 1 and fresh else None
            )

        deadline = time.monotonic() + 10
        name, device, inode = self.owner.until(
            new_execution, 10, "new fixture execution and FIFO identity"
        )
        remaining = deadline - time.monotonic()
        require(remaining > 0, "fixture readiness deadline expired before handshake")
        path = self.waiters / name
        pid = int(name[len(self.nonce) + 1 : -5])
        lease = self.owner.acceptance.leases.LiveFIFOLease.acquire(
            task_id, pid, path, self.nonce, timeout=remaining
        )
        try:
            require(
                lease.identity == (device, inode), "new fixture FIFO identity changed"
            )
            lease.assert_live()
            yield FixtureLeaseObservation(task_id, pid, path, lease.identity), lease
        finally:
            lease.close()

    def close_engine(self, tasks):
        stop_wait = threading.Event()
        wait_failures = []

        def observe_daemon():
            try:
                while not stop_wait.is_set():
                    if self.daemon.poll() is not None:
                        return
                    stop_wait.wait(0.02)
            except Exception as error:
                wait_failures.append(error)

        # Signal delivery occurs only at checkpoints. Startup delivery is
        # inside observer ownership, and shutdown delivery follows actual Wait.
        waiter = None
        try:
            if self.daemon is not None:
                waiter = threading.Thread(
                    target=observe_daemon, name="owned-daemon-wait"
                )
                waiter.start()
            self.owner.interruptions.checkpoint()
            closure = (
                self.owner.acceptance.supervisor.shutdown_terminal_private_supervisor(
                    self.owner.args.delegate,
                    self.owner.args.pueue,
                    self.config,
                    self.env,
                    timeout=45,
                    state=self.state,
                    task_ids=tuple(tasks),
                    capture_root=self.owner.captures,
                    supervisor_cleanups=self.pending,
                )
            )
        finally:
            stop_wait.set()
            if waiter is not None and waiter.ident is not None:
                waiter.join()
            if wait_failures:
                helper_failure = sys.exception()
                if helper_failure is not None:
                    wait_failures.insert(0, helper_failure)
                raise CleanupUnconfirmed(
                    "foreground daemon wait observation failed"
                ) from BaseExceptionGroup(
                    "daemon shutdown and wait observations", wait_failures
                )
        if self.daemon is not None:
            self.daemon.wait(15, expected=0)
        self.owner.interruptions.checkpoint()
        return closure

    def acquire_fixture_gate(self):
        # This root owns one create-once inode across baseline and recovery.
        if self.fixture_gate is None:
            self.fixture_gate = self.owner.acceptance.leases.LockedReleaseGate.acquire(
                self.gate
            )
        gate = self.fixture_gate
        require(gate.descriptor >= 0, "fixture gate lease is already released")
        held = os.fstat(gate.descriptor)
        visible = self.gate.stat(follow_symlinks=False)
        require(
            stat.S_ISREG(visible.st_mode)
            and (held.st_dev, held.st_ino) == (visible.st_dev, visible.st_ino),
            "fixture gate inode was replaced",
        )
        return gate

    def release_fixture_gate(self):
        if self.fixture_gate is not None:
            self.fixture_gate.release()

    def finish(self):
        self.release_fixture_gate()
        # Network intake is joined first. The maintained reader scans every
        # actual managed task in this exclusively owned root; absent drafts are
        # never asserted to have an execution-closure receipt.
        self.owner.acceptance.supervisor.await_managed_lifetime_closure(
            self.state, (), timeout=45
        )
        closure = self.close_engine(())
        require(not self.pending, "native cleanup owner retained")
        return closure


def gateway_process_joined(arguments, result):
    """Classify local descendant ownership from a confirmed process receipt."""
    if result is None or not result.get("natural_wait"):
        return False
    code = result["exit_code"]
    if code not in (0, 1, 2):
        return False
    if arguments[:1] == ["serve"] or arguments[:2] == ["connector", "run"]:
        # These owners can accept native CLI work. Only their normal successful
        # shutdown contract joins it. A panic's direct Wait cannot prove that.
        return code == 0
    # Source-backed one-shot commands own no local native CLI descendants.
    # admin uses Unix HTTP to the separately joined Gateway owner. enroll owns
    # identity storage and HTTPS only (cli/runtime.go, deviceruntime/enroll.go).
    # migrate/begin-recovery use only the exclusively leased local Registry
    # (cli/init.go, cli/offline.go), never the live recovery wire service.
    return arguments[:1] in (
        ["init"],
        ["identity"],
        ["migrate"],
        ["begin-recovery"],
        ["admin"],
        ["version"],
    ) or (arguments[:2] == ["connector", "enroll"])


class Harness:
    def __init__(self, args, interruptions=None):
        self.args = args
        self.interruptions = (
            interruptions if interruptions is not None else Interruptions()
        )
        self.acceptance = load_acceptance(args.delegate_repository)
        self.ownership = self.acceptance.directories.DirectoryOwner()
        self.base = Path(tempfile.mkdtemp(prefix="gw-e2e-", dir=args.work_parent))
        self.base.chmod(0o700)
        self.ownership.adopt_created(
            "Gateway local process acceptance", self.base, args.work_parent
        )
        self.captures = self.ownership.create(
            "native cleanup captures", self.base / "native-captures", self.base
        )
        self.home = self.directory("home")
        self.temporary = self.directory("tmp")
        self.env = child_environment(
            self.home,
            self.temporary,
            [args.gateway.parent, Path("/usr/bin"), Path("/bin")],
        )
        self.processes = self.acceptance.processes.Processes(
            self.base / "processes",
            environment=self.env,
            owner=self.ownership,
            environment_keys_only=True,
        )
        self.sequence = 0
        self.material = None
        self.fixture_allowed_ips = ()
        self.roots = []
        self.connectors = []
        self.gateway = None
        self.jwks = None
        self.jwks_thread = None
        self.public = None
        self.admin_socket = self.base / "admin.sock"
        self.responses = []
        self.last_mcp_started = 0.0
        self.operations = {}
        self.closed_operations = set()
        self.summary = {
            "category": "actual local Gateway/connector/Delegate processes with source-audited Pi fixture",
            "result": "started",
            "cleanup_confirmed": False,
            "paths_removed": False,
            "physical_device_acceptance": "unverified",
            "multi_network_acceptance": "unverified",
            "connector_processes": 2,
            "fixture_task_limit": 4,
            "max_active_fixture_tasks": 1,
            "max_task_budget_seconds": 30,
            "provider_fixture_source_sha256": AUDITED_PI_FIXTURE_SHA256,
            "real_provider_acceptance": "unverified",
            "external_network_acceptance": "unverified",
            "native_control_variant": (
                "diagnostic Python parent with delayed captured output"
                if args.capture_native
                else "direct selected CLI"
            ),
            "selected_binaries": {
                key: str(getattr(args, key))
                for key in (
                    "gateway",
                    "delegate",
                    "delegate_run",
                    "pueue",
                    "pueued",
                    "fixture_tool",
                )
            },
            "delegate_repository": str(args.delegate_repository),
            "stages": [],
        }

    def fixture_attempts(self):
        counts = {"attempted": 0, "rejected_concurrent": 0, "rejected_limit": 0}
        try:
            fd = os.open(self.base / "fixture-attempts", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return counts
        with os.fdopen(fd, "rb") as ledger:
            fcntl.flock(ledger.fileno(), fcntl.LOCK_SH)
            info = os.fstat(ledger.fileno())
            require(
                stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.geteuid()
                and info.st_nlink == 1
                and info.st_size <= 16 << 10,
                "unsafe or oversized fixture attempt ledger",
            )
            data = ledger.read((16 << 10) + 1)
        require(len(data) <= 16 << 10, "fixture attempt ledger exceeded bound")
        events = {
            b"attempt": "attempted",
            b"rejected_concurrent": "rejected_concurrent",
            b"rejected_limit": "rejected_limit",
        }
        require(not data or data.endswith(b"\n"), "incomplete fixture attempt ledger")
        for event in data.split(b"\n")[:-1]:
            require(event in events, "unknown fixture attempt event")
            counts[events[event]] += 1
        return counts

    def assert_fixture_attempts(self, expected):
        require(
            type(expected) is int and expected >= 0,
            "invalid expected fixture attempt count",
        )
        require(
            self.fixture_attempts()
            == {"attempted": expected, "rejected_concurrent": 0, "rejected_limit": 0},
            "unexpected or rejected fixture execution attempt",
        )

    def record_final_fixture_attempts(self):
        try:
            counts = self.fixture_attempts()
            self.summary["fixture_attempts"] = counts
            require(
                counts["attempted"] <= 4
                and counts["rejected_concurrent"] == 0
                and counts["rejected_limit"] == 0,
                "fixture attempt budget or concurrency oracle failed",
            )
            if self.summary.get("result") == "local_recovery_passed":
                require(
                    counts["attempted"] == 4, "completed recovery attempt count changed"
                )
        except (OSError, ValueError, ProofFailure):
            self.summary["result"] = "failed"
            self.summary["fixture_attempt_evidence"] = "invalid"

    def directory(self, label):
        return self.ownership.create(label, self.base / label, self.base).directory

    def input_file(self, value):
        self.sequence += 1
        path = self.base / f"input-{self.sequence:04d}.json"
        private_json(path, value)
        return path

    def command(self, executable, arguments, env=None, cwd=None, expected=0):
        self.interruptions.checkpoint()
        self.sequence += 1
        process = self.processes.run(
            f"control-{self.sequence:04d}",
            [executable, *arguments],
            cwd or self.base,
            expected=expected,
            timeout=40,
            environment=env or self.env,
        )
        value = process.json(bound=1 << 20)
        self.interruptions.checkpoint()
        return value

    def helper(self, action, value):
        return self.command(
            self.args.fixture_tool, [action, "--input", self.input_file(value)]
        )

    def admin(self, action, value, output=None):
        args = [
            "admin",
            "--socket",
            self.admin_socket,
            "--action",
            action,
            "--input-file",
            self.input_file(value),
        ]
        if output is not None:
            self.interruptions.checkpoint()
            args += ["--output-file", output]
            self.sequence += 1
            self.processes.run(
                f"admin-{self.sequence:04d}",
                [self.args.gateway, *args],
                self.base,
                timeout=40,
                environment=self.env,
            )
            value = json.loads(output.read_text())
            self.interruptions.checkpoint()
            return value
        return self.command(self.args.gateway, args)

    def pace_mcp(self):
        # Each one-shot SDK session also authenticates initialization traffic.
        # Space sessions within the server's 10/s, burst-20 authority limit.
        delay = 0.5 - (time.monotonic() - self.last_mcp_started)
        if delay > 0:
            time.sleep(delay)
        self.last_mcp_started = time.monotonic()

    def mcp_input(self, tool, arguments):
        value = {
            "endpoint": self.public + "/mcp",
            "ca_file": self.material["ca_file"],
            "token_file": self.material["token_file"],
            "tool": tool,
            "arguments": arguments,
        }
        if allowed_ips := getattr(self, "fixture_allowed_ips", ()):
            value["allowed_ips"] = list(allowed_ips)
        return value

    def consume_mcp(self, result, failure=False):
        self.responses.append(result)
        envelope = result.get("structuredContent")
        require(isinstance(envelope, dict), "MCP structured response missing")
        if failure:
            require(
                result.get("isError") and envelope.get("error"),
                "invalid explicit selection accepted",
            )
            return envelope["error"]
        require(
            not result.get("isError") and envelope.get("data") is not None,
            "MCP operation failed",
        )
        return envelope["data"]

    def mcp(self, tool, arguments, failure=False):
        self.pace_mcp()
        result = self.helper("mcp", self.mcp_input(tool, arguments))
        return self.consume_mcp(result, failure)

    def until(self, check, seconds, description):
        deadline = time.monotonic() + seconds
        while True:
            self.interruptions.checkpoint()
            value = check()
            self.interruptions.checkpoint()
            if value:
                return value
            require(time.monotonic() < deadline, description + " timed out")
            time.sleep(0.2)

    def start_network(self, *, listen_ip="127.0.0.1"):
        listen_ip = fixture_listen_ip(listen_ip)
        # The default helper already owns the historical loopback allowlist.
        self.fixture_allowed_ips = () if listen_ip == "127.0.0.1" else (listen_ip,)

        class HarnessJWKSHandler(JWKSHandler):
            pass

        self.jwks = http.server.HTTPServer((listen_ip, 0), HarnessJWKSHandler)
        issuer = f"https://{listen_ip}:{self.jwks.server_port}/"
        self.public = f"https://{listen_ip}:{free_port(listen_ip)}"
        value = {
            "directory": str(self.directory("tls")),
            "issuer": issuer,
            "audience": self.public + "/mcp",
        }
        if self.fixture_allowed_ips:
            value["allowed_ips"] = list(self.fixture_allowed_ips)
        self.material = self.helper("material", value)
        # Assigned once before serving; other Harness instances have private keys.
        HarnessJWKSHandler.document = Path(self.material["jwks_file"]).read_bytes()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(
            self.material["tls"]["certificate"], self.material["tls"]["private_key"]
        )
        self.jwks.socket = tls.wrap_socket(self.jwks.socket, server_side=True)
        self.jwks_thread = threading.Thread(
            target=self.jwks.serve_forever, name="fixture-jwks"
        )
        self.jwks_thread.start()
        self.env["SSL_CERT_FILE"] = self.material["ca_file"]
        self.env["SSL_CERT_DIR"] = str(self.home / "empty-ca-directory")
        database = self.base / "registry.sqlite"
        identity = self.command(self.args.gateway, ["init", "--database", database])
        self.gateway_id = identity["gateway_id"]
        config = {
            "gateway_id": self.gateway_id,
            "public_url": self.public,
            "public_address": self.public.removeprefix("https://"),
            "device_address": f"{listen_ip}:{free_port(listen_ip)}",
            "tls": self.material["tls"],
            "device_ca": self.material["device_ca"],
            "database": str(database),
            "admin_socket": str(self.admin_socket),
            "audit_directory": str(self.directory("audit")),
            "identity": {
                "issuer": issuer,
                "audience": self.public + "/mcp",
                "jwks_url": issuer + "jwks",
            },
        }
        self.gateway_config = config
        self.gateway_config_path = self.input_file(config)
        self.start_gateway()
        self.issuer = issuer
        self.check_auth()
        principal = self.admin(
            "resolve-principal", {"issuer": issuer, "subject": "local-e2e-subject"}
        )
        self.principal = principal["principal_id"]
        self.summary["stages"].append("real_process_startup_https_jwks_auth")

    def start_gateway(self):
        self.gateway = self.processes.start(
            "gateway-serve",
            [self.args.gateway, "serve", "--config", self.gateway_config_path],
            self.base,
            environment=self.env,
        )

        def bound():
            completed = self.gateway.poll()
            if completed is not None:
                self.summary["startup_failure"] = {
                    "kind": "process_exit",
                    "exit_code": completed["exit_code"],
                }
                raise ProofFailure("Gateway exited before listener startup")
            data = self.gateway.stdout_path.read_bytes()
            require(len(data) <= 65536, "unexpected Gateway startup output")
            return json.loads(data.splitlines()[0]) if b"\n" in data else None

        addresses = self.until(bound, 15, "Gateway listener startup")
        require(
            addresses["public"] == self.gateway_config["public_address"]
            and addresses["device"] == self.gateway_config["device_address"],
            "Gateway bound another public authority",
        )
        self.device_url = "wss://" + addresses["device"] + "/device"

    def restart_gateway(self):
        self.stop_process(self.gateway)
        self.start_gateway()
        self.check_auth()

    def check_auth(self):
        context = ssl.create_default_context(cafile=self.material["ca_file"])
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        )
        wrong = json.loads(Path(self.material["wrong_token_file"]).read_text())["token"]
        for token in ("", wrong):
            request = urllib.request.Request(
                self.public + "/mcp",
                data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Authorization": "Bearer " + token,
                },
            )
            try:
                with opener.open(request, timeout=5) as response:
                    status = response.status
            except urllib.error.HTTPError as error:
                status = error.code
                error.close()
            require(
                status == 401,
                "missing or wrong-audience bearer was not rejected with 401",
            )

    def start_connectors(self):
        for index in range(2):
            root = DelegateRoot(self, f"d{index + 1}")
            self.roots.append(root)  # Retain ownership before any public startup.
            root.start()
            device = f"fixture-device-{index + 1}"
            alias = "fixture-project"
            root.device = device
            root.alias = alias
            self.admin("register-device", {"device_id": device, "name": device})
            binding = {
                "device_id": device,
                "project_alias": alias,
                "root_guard": context_guard(root.context["root_token"]),
                "project_guard": context_guard(root.context["project_token"]),
            }
            self.admin("register-project", binding)
            self.grant_root(root)
            token_file = root.base / "enrollment.json"
            self.admin(
                "issue-enrollment-token",
                {"device_id": device, "mode": "regular", "generation": 1},
                output=token_file,
            )
            identity = root.base / "identity"
            identity.mkdir(mode=0o700)
            config = {
                "schema_version": 1,
                "gateway_id": self.gateway_id,
                "expected_device_id": device,
                "enrollment_url": self.public + "/v1/enroll",
                "wss_url": self.device_url,
                "trust_ca_file": self.material["ca_file"],
                "device_ca_file": self.material["device_ca"]["certificate"],
                "identity_directory": str(identity),
                "delegate_executable": str(root.connector_executable),
                "temporary_directory": str(root.temporary),
                "control_timeout": "30s",
                "network_timeout": "35s",
                "projects": [
                    {
                        "alias": alias,
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
            path = self.input_file(config)
            root.connector_config_path = path
            self.command(
                self.args.gateway,
                ["connector", "enroll", "--config", path, "--token-file", token_file],
                root.env,
            )
            self.start_connector(root)
            self.until(
                lambda: self.capability_online(device, alias),
                20,
                "strict authenticated connector handshake",
            )
            for _ in range(6):
                progress = self.admin("initialize-root", binding)
                if progress["stage"] == "ready":
                    break
            else:
                raise ProofFailure(
                    "bounded explicit root initialization did not become ready"
                )
            self.until(
                lambda: self.mcp(
                    "get_capabilities", {"device_id": device, "project_alias": alias}
                )["delegate_ready"],
                10,
                "post-reopen dated capability publication",
            )
        listed = self.mcp("list_devices", {})["devices"]
        require(
            {entry["device_id"] for entry in listed}
            == {root.device for root in self.roots},
            "two enrolled connector identities not visible",
        )
        require(all(entry["online"] for entry in listed), "one connector is offline")
        self.summary["stages"].append("two_actual_connectors_enrolled_root_initialized")

    def start_connector(self, root):
        self.interruptions.checkpoint()
        connector = self.processes.start(
            "connector-run",
            [
                self.args.gateway,
                "connector",
                "run",
                "--config",
                root.connector_config_path,
            ],
            root.base,
            environment=root.env,
        )
        self.connectors.append(connector)
        self.interruptions.checkpoint()

    def grant_root(self, root):
        self.admin(
            "put-grant",
            {
                "principal_id": self.principal,
                "device_id": root.device,
                "project_alias": root.alias,
                "scopes": [
                    "inventory:read",
                    "task:dispatch",
                    "task:read",
                    "task:cancel",
                ],
                "providers": ["pi:json"],
                "permissions": ["read-only"],
                "max_budget_seconds": 30,
            },
        )

    def capability_online(self, device, alias):
        value = self.mcp(
            "get_capabilities", {"device_id": device, "project_alias": alias}
        )
        return value["online"]

    def prepare(self, root, brief):
        prepared = self.mcp(
            "prepare_dispatch",
            {
                "device_id": root.device,
                "project_alias": root.alias,
                "brief": brief,
                "provider": "pi:json",
                "permission": "read-only",
                "budget_seconds": 30,
                "model": "openai/gpt-4.1",
            },
        )
        root.tasks.append(prepared["task_id"])  # Possibly admitted before I/O.
        self.operations[prepared["operation_id"]] = {
            "cancellation_id": uuid.uuid4().hex,
            "task_id": prepared["task_id"],
        }
        return prepared

    def await_operation(self, operation, result=False):
        def observation():
            value = self.mcp("resolve_operation", {"operation_id": operation})
            report = value.get("observation") or {}
            if report.get("kind") == "refused" and value.get("reserved") is False:
                self.closed_operations.add(operation)
                require(not result, "permanently refused task has no accepted result")
                return value
            if report.get("execution_closure") and (not result or report.get("result")):
                return value
            return None

        value = self.until(
            observation, 45, "canonical execution closure and accepted result"
        )
        self.closed_operations.add(operation)
        return value

    def task_scenarios(self):
        root = self.roots[0]
        self.mcp(
            "prepare_dispatch",
            {
                "brief": "must not choose a device implicitly",
                "provider": "pi:json",
                "permission": "read-only",
                "budget_seconds": 30,
            },
            failure=True,
        )
        self.mcp(
            "prepare_dispatch",
            {
                "device_id": root.device,
                "project_alias": "missing-project",
                "brief": "must not choose another alias",
                "provider": "pi:json",
                "permission": "read-only",
                "budget_seconds": 30,
            },
            failure=True,
        )
        require(
            sum(item.invocations() for item in self.roots) == 0,
            "invalid selection launched provider",
        )
        self.assert_fixture_attempts(0)
        self.brief_canary = "E2E_PRIVATE_BRIEF_" + uuid.uuid4().hex
        prepared = self.prepare(
            root, "Return the controlled fixture sentence. " + self.brief_canary
        )
        handle = {"operation_id": prepared["operation_id"]}
        first = self.mcp("dispatch_task", handle)
        require(
            first["task_id"] == prepared["task_id"]
            and first["device_id"] == root.device,
            "dispatch changed prepared identity or selected device",
        )
        self.await_operation(prepared["operation_id"], result=True)
        # Deliberately discard the first ACK as an observer, then repeat the
        # same durable operation. This is not injected TCP packet-loss proof.
        repeated = self.mcp("dispatch_task", handle)
        require(
            repeated["task_id"] == prepared["task_id"],
            "same-operation retry changed task",
        )
        final = self.await_operation(prepared["operation_id"], result=True)
        descriptor = final["observation"]["result"]
        self.baseline_prepared = prepared
        self.baseline_descriptor = descriptor
        chunk = self.mcp(
            "read_result_chunk",
            {**handle, "descriptor": descriptor, "offset": 0, "limit": 65536},
        )
        expected = b"private supervisor acceptance passed"
        require(
            base64.b64decode(chunk["data_base64"], validate=True) == expected,
            "accepted fixture result bytes changed",
        )
        require(
            descriptor["sha256"] == hashlib.sha256(expected).hexdigest()
            and descriptor["length"] == len(expected),
            "accepted result descriptor changed",
        )
        require(
            root.invocations() == 1 and self.roots[1].invocations() == 0,
            "retry reexecuted or selected another device",
        )
        self.assert_fixture_attempts(1)
        self.summary["stages"].append(
            "explicit_selection_same_operation_retry_accepted_result_closure"
        )
        drained = self.admin(
            "drain-administrative-task",
            {
                "device_id": root.device,
                "root_guard": context_guard(root.context["root_token"]),
                "task_id": prepared["task_id"],
                "project_alias": root.alias,
                "action": "resolve",
            },
        )
        require(
            drained["key"]
            == {
                "device_id": root.device,
                "root_guard": context_guard(root.context["root_token"]),
                "task_id": prepared["task_id"],
            }
            and drained["origin"]["operation_id"] == prepared["operation_id"]
            and drained["observation"]["kind"] == "terminal"
            and not drained["reserved"],
            "administrative resolve changed task identity or closure",
        )
        require(
            root.invocations() == 1 and self.roots[1].invocations() == 0,
            "administrative resolve executed another provider",
        )
        self.assert_fixture_attempts(1)
        self.summary["stages"].append(
            "private_administrative_resolve_through_real_connector"
        )
        root.acquire_fixture_gate()
        fixture_before = root.fixture_execution_snapshot()
        long = self.prepare(root, "DELEGATE_PRIVATE_SILENCE_WAIT")
        self.mcp("dispatch_task", {"operation_id": long["operation_id"]})
        root.wait_fixture_execution(fixture_before, long["task_id"])
        cancellation = self.operations[long["operation_id"]]["cancellation_id"]
        cancel = {
            "operation_id": long["operation_id"],
            "cancellation_id": cancellation,
        }
        acknowledged = self.mcp("cancel_task", cancel)
        require(
            acknowledged["cancellation_id"] == cancellation,
            "cancellation ID changed",
        )
        self.await_operation(long["operation_id"])
        closure = self.acceptance.supervisor.read_managed_closure(
            root.state, tuple(root.tasks)
        )
        require_requested_closure(closure, long["task_id"])
        self.summary["requested_native_scope_empty_before_deadline"] = True
        retried = self.mcp("cancel_task", cancel)
        require(
            retried["cancellation_id"] == cancellation,
            "cancel retry changed identity",
        )
        require(root.invocations() == 2, "long fixture ran more than once")
        self.assert_fixture_attempts(2)
        self.summary["fixture_tasks_executed"] = sum(
            item.invocations() for item in self.roots
        )
        self.summary["stages"].append("stable_cancel_then_canonical_execution_closure")
        self.check_canaries()

    def check_canaries(self):
        wire = json.dumps(self.responses).encode()
        forbidden = [self.brief_canary, str(self.base)]
        for root in self.roots:
            forbidden.extend(
                [
                    root.context["root_token"],
                    root.context["project_token"],
                    str(root.workspace),
                ]
            )
        token = json.loads(Path(self.material["token_file"]).read_text())["token"]
        forbidden.append(token)
        for value in forbidden:
            require(
                value.encode() not in wire, "private canary escaped public MCP metadata"
            )
        for path in (self.base / "audit").glob("*"):
            if path.is_file():
                data = path.read_bytes()
                require(
                    all(value.encode() not in data for value in forbidden),
                    "private canary escaped audit metadata",
                )
        self.summary["stages"].append("public_metadata_and_audit_canaries_absent")

    def recovery_scenarios(self):
        from e2e_recovery import RecoveryScenario

        RecoveryScenario(self).run()
        self.check_canaries()

    def stop_process(self, process):
        if process.poll() is None:
            # Exact fixture-owned Gateway/connector handles only. No process
            # search, process group, provider signal or task PID is used.
            process.process.send_signal(signal.SIGTERM)
        code = process.wait(45, expected=None)
        require(isinstance(code, int), "owned Wait did not return an exit code")
        if code != 0:
            self.record_process_failure(process, code)
            raise CleanupUnconfirmed("process exit did not confirm owned CLI joins")
        return code

    def record_process_failure(self, process, code):
        failures = self.summary.setdefault("process_exit_failures", [])
        failure = {"pid": process.pid, "exit_code": code, "direct_wait_confirmed": True}
        if failure not in failures:
            failures.append(failure)
        self.summary["result"] = "failed"

    def gateway_intake_faults(self):
        reports = []
        for process in self.processes.entries:
            if process.argv[0] != str(self.args.gateway):
                continue
            result = process.poll()
            if result is not None and result["exit_code"] != 0:
                self.record_process_failure(process, result["exit_code"])
            if not gateway_process_joined(process.argv[1:], result):
                reports.append(
                    {
                        "stage": "gateway_intake_unconfirmed",
                        "pid": process.pid,
                        "exit_code": result["exit_code"] if result else None,
                        "direct_wait_confirmed": result is not None,
                    }
                )
        # A child can start before its higher-level handle assignment succeeds.
        # Keep the process registry's uncertain starts outside native closure.
        for pending in self.processes.pending(exclude=self.processes.entries):
            if pending["argv"][0] == str(self.args.gateway):
                reports.append({"stage": "gateway_start_unconfirmed"})
        return reports

    def native_capture_faults(self):
        faults = []
        for root in self.roots:
            if root.native_captures is None:
                continue
            try:
                captures = list(root.native_captures.iterdir())
            except OSError:
                faults.append({"stage": "native_capture", "kind": "unconfirmed"})
                continue
            for capture in captures:
                try:
                    directory = capture.lstat()
                    require(
                        stat.S_ISDIR(directory.st_mode)
                        and directory.st_uid == os.geteuid()
                        and stat.S_IMODE(directory.st_mode) == 0o700,
                        "native capture directory unavailable",
                    )
                    path = capture / "metadata.json"
                    info = path.lstat()
                    require(
                        stat.S_ISREG(info.st_mode)
                        and info.st_uid == os.geteuid()
                        and stat.S_IMODE(info.st_mode) == 0o600
                        and info.st_nlink == 1
                        and info.st_size <= 65536,
                        "native capture metadata unavailable",
                    )
                    value = json.loads(path.read_bytes())
                    require(
                        isinstance(value, dict) and native_capture_complete(value),
                        "native capture ownership remains unconfirmed",
                    )
                except (OSError, ValueError, RecursionError, ProofFailure):
                    faults.append({"stage": "native_capture", "kind": "unconfirmed"})
        return faults

    def finish(self):
        with self.interruptions.cleanup():
            return self._finish_owned()

    def _finish_owned(self):
        faults = []
        # Retry only already-owned operations with their original cancellation
        # IDs. Errors stay distinct from the later native full-root proof.
        for operation, record in self.operations.items():
            if operation in self.closed_operations:
                continue
            try:
                self.mcp(
                    "cancel_task",
                    {
                        "operation_id": operation,
                        "cancellation_id": record["cancellation_id"],
                    },
                )
                self.await_operation(operation)
            except Exception as error:
                self.summary.setdefault("observation_cleanup_errors", []).append(
                    {"stage": "public_task_control", "kind": type(error).__name__}
                )
        intake_joined = True
        for process in reversed(self.connectors):
            try:
                self.stop_process(process)
            except Exception as error:
                intake_joined = False
                faults.append({"stage": "connector_join", "kind": type(error).__name__})
        if self.gateway is not None:
            try:
                self.stop_process(self.gateway)
            except Exception as error:
                intake_joined = False
                faults.append({"stage": "gateway_join", "kind": type(error).__name__})
        gateway_faults = self.gateway_intake_faults()
        if gateway_faults:
            intake_joined = False
            faults.extend(gateway_faults)
        native_faults = self.native_capture_faults()
        if native_faults:
            intake_joined = False
            faults.extend(native_faults)
        if intake_joined:
            for root in self.roots:
                try:
                    closure = root.finish()
                    self.summary.setdefault("canonical_root_closures", []).append(
                        closure
                    )
                except Exception as error:
                    faults.append(
                        {
                            "stage": "canonical_native_closure",
                            "kind": type(error).__name__,
                            "trace": failure_trace(error),
                            "retained_cleanup_entries": len(root.pending),
                        }
                    )
        if self.jwks is not None:
            if self.jwks_thread is not None:
                self.jwks.shutdown()
                self.jwks_thread.join()
            self.jwks.server_close()
        if not self.processes.finished_naturally():
            faults.append({"stage": "owned_process_wait", "kind": "unconfirmed"})
        self.record_final_fixture_attempts()
        self.summary["cleanup_errors"] = faults
        self.summary["cleanup_confirmed"] = not faults
        self.summary["evidence_directory"] = str(self.base)
        interrupted_during_cleanup = self.interruptions.finalize_cleanup()
        if self.interruptions.interrupted:
            self.summary["interrupted"] = True
        if interrupted_during_cleanup:
            self.summary["interrupted_during_cleanup"] = True
            self.summary["result"] = "failed"
        private_json(self.base / "summary.json", self.summary)
        return not faults

    def run(self):
        passed = False
        try:
            self.interruptions.checkpoint()
            self.start_network()
            self.interruptions.checkpoint()
            self.start_connectors()
            self.interruptions.checkpoint()
            self.task_scenarios()
            self.interruptions.checkpoint()
            self.recovery_scenarios()
            self.interruptions.checkpoint()
            self.summary["result"] = "local_recovery_passed"
            passed = True
        except Exception as error:
            self.summary["result"] = "failed"
            self.summary["failure_kind"] = type(error).__name__
            self.summary["failure_trace"] = failure_trace(error)
            # Fixed classification only; raw exceptions can contain paths,
            # authentication inputs, provider output or subprocess argv.
        finally:
            closed = self.finish()
        print(
            json.dumps(
                {
                    "result": self.summary["result"],
                    "cleanup_confirmed": closed,
                    "evidence_directory": str(self.base),
                }
            ),
            flush=True,
        )
        if not closed:
            return 3
        return (
            0
            if passed
            and self.summary["result"] == "local_recovery_passed"
            and not self.summary.get("process_exit_failures")
            else 1
        )


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "gateway",
        "delegate",
        "delegate-run",
        "pueue",
        "pueued",
        "fixture-tool",
    ):
        parser.add_argument("--" + name, required=True, type=checked_binary)
    parser.add_argument("--delegate-repository", required=True, type=Path)
    parser.add_argument("--work-parent", type=Path, default=Path.home())
    parser.add_argument(
        "--capture-native",
        action="store_true",
        help="diagnostic variant with a Python CLI parent and private output capture",
    )
    parser.add_argument(
        "--run-native",
        action="store_true",
        help="explicitly opt into the approved finite zero-cost fixture run",
    )
    args = parser.parse_args(argv)
    args.delegate_repository = args.delegate_repository.resolve(strict=True)
    args.work_parent = args.work_parent.resolve(strict=True)
    require(
        args.delegate.name == "delegate"
        and args.delegate_run.name == "delegate-run"
        and args.delegate.parent == args.delegate_run.parent,
        "selected Delegate/runner must be the existing adjacent pair",
    )
    require(
        args.pueue.name == "pueue" and args.pueued.name == "pueued",
        "explicit native supervisor pair required",
    )
    require(
        args.run_native,
        "native acceptance requires explicit --run-native and an available acceptance slot",
    )
    return args


def main(argv=None):
    os.umask(0o077)
    interruptions = Interruptions()

    previous = {
        number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
    }
    for number in previous:
        signal.signal(number, interruptions.handle)
    try:
        return Harness(arguments(argv), interruptions=interruptions).run()
    except Exception as error:
        print(
            json.dumps(
                {
                    "result": "fixture_setup_failed",
                    "failure_kind": type(error).__name__,
                    "cleanup_confirmed": False,
                }
            ),
            flush=True,
        )
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
