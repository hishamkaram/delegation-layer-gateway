#!/usr/bin/env python3
"""Opt-in SQLite rollback with real Gateway/connector/Delegate processes.

Registry owns restored correlations and recovery barriers. Delegate retains its
later task requests, execution and accepted results. The existing local harness
owns every process, its four-attempt controlled provider budget and cleanup.
No installed provider account, remote device or deployed registry is used.
Snapshot commitments cover the consistent backup's main SQLite file. SQLite's
transient WAL/SHM sidecars are permitted; their byte identity is not committed.
"""

from dataclasses import dataclass
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import sys
import uuid

from e2e_local import Harness, Interruptions, arguments, require
from e2e_recovery import RecoveryScenario, native_guards, task_key


EXPECTED_RESULT = b"private supervisor acceptance passed"


@dataclass(frozen=True)
class Snapshot:
    path: Path
    device: int
    inode: int
    length: int
    sha256: str


def private_database(path):
    """The fixture creator selects an existing private, canonical database."""
    require(path.is_absolute() and path.resolve(strict=True) == path, "database alias")
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == os.getuid()
        and info.st_nlink == 1,
        "database ownership changed",
    )
    return info


def database_identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def backup_database(source, destination, *, create):
    """Use SQLite's consistent backup API, with all connections explicitly closed.

    The caller must already have joined its sole Gateway writer. The native task
    store is neither opened nor copied here. Restoring updates the existing
    fixture database through SQLite rather than leaving old WAL pages beside a
    replaced pathname.
    """
    require(source != destination, "snapshot source equals destination")
    before = private_database(source)
    if create:
        descriptor = os.open(
            destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        os.close(descriptor)
    target_before = private_database(destination)
    with (
        closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as reader,
        closing(sqlite3.connect(destination)) as writer,
    ):
        reader.backup(writer)
        require(
            writer.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
            "restored database integrity failed",
        )
    require(
        database_identity(private_database(source)) == database_identity(before),
        "snapshot source changed during backup",
    )
    after = private_database(destination)
    require(
        (target_before.st_dev, target_before.st_ino) == (after.st_dev, after.st_ino),
        "snapshot destination replaced during backup",
    )


def snapshot_descriptor(path):
    info = private_database(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        held = os.fstat(descriptor)
        require(database_identity(held) == database_identity(info), "snapshot changed")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            digest = hashlib.file_digest(stream, "sha256")
        after = os.fstat(descriptor)
        require(database_identity(held) == database_identity(after), "snapshot changed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return Snapshot(path, info.st_dev, info.st_ino, info.st_size, digest.hexdigest())


def require_snapshot(snapshot):
    require(
        snapshot_descriptor(snapshot.path) == snapshot, "snapshot commitment changed"
    )


def require_result(descriptor):
    require(
        isinstance(descriptor, dict)
        and descriptor.get("length") == len(EXPECTED_RESULT)
        and descriptor.get("sha256") == hashlib.sha256(EXPECTED_RESULT).hexdigest(),
        "accepted result descriptor changed",
    )


def operation_membership(database, operation_ids):
    """Independent offline oracle: selected correlations really left the store."""
    before = private_database(database)
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    try:
        marks = ",".join("?" for _ in operation_ids)
        rows = connection.execute(
            "SELECT id FROM operations WHERE id IN (" + marks + ")", operation_ids
        ).fetchall()
    finally:
        connection.close()
    require(
        database_identity(private_database(database)) == database_identity(before),
        "offline membership source changed",
    )
    return {row[0] for row in rows}


def verify_result_bytes(harness, prepared, descriptor):
    require_result(descriptor)
    chunk = harness.mcp(
        "read_result_chunk",
        {
            "operation_id": prepared["operation_id"],
            "descriptor": descriptor,
            "offset": 0,
            "limit": 65536,
        },
    )
    require_result_bytes(chunk)


def require_result_bytes(chunk):
    require(
        chunk.get("offset") == 0
        and chunk.get("next_offset") == len(EXPECTED_RESULT)
        and chunk.get("eof") is True
        and base64.b64decode(chunk["data_base64"], validate=True) == EXPECTED_RESULT,
        "accepted result bytes changed across rollback",
    )


class SnapshotRollback(RecoveryScenario):
    """The existing recovery flow, preceded by a genuine older-store restore."""

    def __init__(self, harness):
        super().__init__(harness)
        self.snapshot = None
        self.live_context = None
        self.live = None
        self.future_result = None
        self.stale = None

    def capture_snapshot(self):
        h = self.h
        h.assert_fixture_attempts(2)
        # This frozen preparation is present in the snapshot but never sent.
        self.stale = h.prepare(h.roots[0], "must remain unsent after rollback")
        require(h.stop_process(h.gateway) == 0, "snapshot writer join unverified")
        source = Path(h.gateway_config["database"])
        target = h.base / "registry-before-later-work.sqlite"
        backup_database(source, target, create=True)
        self.snapshot = snapshot_descriptor(target)
        h.summary["rollback_snapshot"] = {
            "sha256": self.snapshot.sha256,
            "bytes": self.snapshot.length,
            "gateway_writer_original_wait": 0,
            "fixture_attempts": 2,
            "consistent_copy": "sqlite3.Connection.backup",
            "commitment_scope": "main SQLite backup file, not transient WAL/SHM bytes",
            "stale_operation_id": self.stale["operation_id"],
            "stale_task_id": self.stale["task_id"],
        }
        h.start_gateway()
        for root in h.roots:
            h.until(lambda root=root: self.connected(root), 15, "snapshot reconnect")

    def reserved_attributed(self):
        """The third task finishes after the snapshot, before the rollback."""
        h, root = self.h, self.h.roots[0]
        prepared = h.prepare(root, "Return the controlled fixture sentence.")
        h.mcp("dispatch_task", {"operation_id": prepared["operation_id"]})
        result = h.await_operation(prepared["operation_id"], result=True)
        descriptor = result["observation"]["result"]
        verify_result_bytes(h, prepared, descriptor)
        view = h.admin("get-administrative-task", task_key(root, prepared["task_id"]))
        require(view["attributed"] is True, "future original attribution missing")
        # Save independently observed pre-rollback identity/result, never ask the
        # restored classifier to compute this expected binding.
        self.future_result = {
            "prepared": prepared,
            "descriptor": descriptor,
            "view": view,
        }
        return view

    def native_unattributed(self):
        """Fourth native task is live across the actual SQLite rollback."""
        h, root = self.h, self.h.roots[0]
        root.acquire_fixture_gate()
        before = root.fixture_execution_snapshot()
        context = root.command(
            [
                "context",
                "inspect",
                "--cwd",
                root.workspace,
                "--gateway-id",
                h.gateway_id,
            ]
        )["connector"]
        origin = {
            "gateway_id": h.gateway_id,
            "admission_generation": context["origin_barrier"]["generation"],
            "operation_id": uuid.uuid4().hex,
            "principal_ref": "fixture-local-import",
            "gateway_request_sha256": hashlib.sha256(
                b"local-import-request"
            ).hexdigest(),
        }
        origin_file = h.input_file(origin)
        task = uuid.uuid4().hex
        root.tasks.append(task)
        brief = root.base / "rollback-unattributed-brief.txt"
        with brief.open("x", encoding="utf-8") as stream:
            brief.chmod(0o600)
            stream.write("DELEGATE_PRIVATE_SILENCE_WAIT")
        root.command(
            [
                "dispatch",
                "--id",
                task,
                "--provider",
                "pi:json",
                "--brief",
                brief,
                "--cwd",
                root.workspace,
                "--permission",
                "read-only",
                "--budget",
                "29.5s",
                "--model",
                "openai/gpt-4.1",
                "--expected-root",
                root.context["root_token"],
                "--expected-project",
                root.context["project_token"],
                "--origin",
                origin_file,
            ]
        )
        context = root.fixture_execution_lease(before, task)
        self.live = context.__enter__()
        self.live_context = context
        self.unattributed_origin_file = origin_file
        self.unattributed = {"task_id": task, "origin": origin}
        return self.unattributed

    def release_live_probe(self):
        if self.live_context is not None:
            context, self.live_context = self.live_context, None
            context.__exit__(None, None, None)
        self.h.roots[0].release_fixture_gate()

    def start_recovery(self):
        h = self.h
        require(
            self.snapshot is not None and self.live is not None,
            "rollback setup missing",
        )
        observation, lease = self.live
        lease.assert_live()
        require(h.stop_process(h.gateway) == 0, "rollback writer join unverified")
        lease.assert_live()
        require_snapshot(self.snapshot)
        source = Path(h.gateway_config["database"])
        later = self.future_result["prepared"]["operation_id"]
        stale = self.stale["operation_id"]
        selected = (later, stale)
        require(
            operation_membership(source, selected) == {later, stale}
            and operation_membership(self.snapshot.path, selected) == {stale},
            "snapshot does not predate the known later correlation",
        )
        backup_database(self.snapshot.path, source, create=False)
        require(
            operation_membership(source, selected) == {stale},
            "actual rollback did not remove the later correlation",
        )
        lease.assert_live()
        h.command(
            h.args.gateway, ["migrate", "--database", h.gateway_config["database"]]
        )
        identity = h.command(
            h.args.gateway, ["identity", "--database", h.gateway_config["database"]]
        )
        require(
            identity.get("gateway_id") == h.gateway_id,
            "restore changed Gateway identity",
        )
        session = h.command(
            h.args.gateway,
            [
                "begin-recovery",
                "--database",
                h.gateway_config["database"],
                "--recovery-id",
                self.recovery,
            ],
        )
        require(
            session.get("recovery_id") == self.recovery
            and session.get("kind") == "restore",
            "offline restore intent changed",
        )
        lease.assert_live()
        require_snapshot(self.snapshot)
        h.summary["rollback_while_native_active"] = {
            "task_id": observation.task_id,
            "provider_pid": observation.pid,
            "fifo_identity": list(observation.identity),
            "gateway_writer_original_wait": 0,
            "snapshot_sha256": self.snapshot.sha256,
            "native_live_before_and_after_restore_and_offline_fence": True,
            "later_correlation_present_before_and_absent_after_restore": True,
        }
        self.release_live_probe()
        # The fixture owner releases only its own gate. Native performs normal
        # result publication and canonical task closure; no provider is signalled.
        self.native_closure(
            h.roots[0], self.unattributed["task_id"], self.unattributed_origin_file
        )
        h.start_gateway()
        h.check_auth()

    def verify_public_result(self):
        super().verify_public_result()
        h, root = self.h, self.h.roots[0]
        future = self.future_result
        handle = {"operation_id": future["prepared"]["operation_id"]}
        observed = h.await_operation(handle["operation_id"], result=True)
        require(
            observed["task_id"] == future["prepared"]["task_id"]
            and observed["observation"]["result"] == future["descriptor"],
            "restored future task/result binding changed",
        )
        verify_result_bytes(h, future["prepared"], future["descriptor"])
        view = h.admin(
            "get-administrative-task", task_key(root, future["prepared"]["task_id"])
        )
        require(
            view["attributed"] is True and view["origin"] == future["view"]["origin"],
            "canonical receipt reconstruction changed original attribution",
        )
        repeated = h.mcp("dispatch_task", handle)
        require(
            repeated["task_id"] == future["prepared"]["task_id"],
            "restored retry changed task",
        )
        stale = h.mcp(
            "dispatch_task", {"operation_id": self.stale["operation_id"]}, failure=True
        )
        require(
            stale.get("code") == "conflict",
            "stale snapshot preparation was not denied",
        )
        h.closed_operations.add(self.stale["operation_id"])
        h.summary["rollback_restored_future_result"] = {
            "operation_id": handle["operation_id"],
            "task_id": future["prepared"]["task_id"],
            "descriptor": future["descriptor"],
            "attribution": "exact frozen Native receipt and retained principal",
            "stale_preparation_denial": stale["code"],
        }
        self.verify_unattributed_visibility(root)

    def verify_unattributed_visibility(self, root):
        h = self.h
        # This is the private principal owner used by login, not a second OAuth
        # authentication. A new mapping/grant must not promote unmatched work.
        principal = h.admin(
            "resolve-principal", {"issuer": h.issuer, "subject": "later-restore-login"}
        )["principal_id"]
        require(principal != h.principal, "later principal did not remain distinct")
        h.admin(
            "put-grant",
            {
                "principal_id": principal,
                "device_id": root.device,
                "project_alias": root.alias,
                "scopes": ["inventory:read", "task:read", "task:cancel"],
                "providers": ["pi:json"],
                "permissions": ["read-only"],
                "max_budget_seconds": 30,
            },
        )
        unknown = h.admin(
            "get-administrative-task", task_key(root, self.unattributed["task_id"])
        )
        require(
            unknown["attributed"] is False
            and unknown["origin"] == self.unattributed["origin"],
            "later principal inherited an unattributed native task",
        )
        h.summary["rollback_unattributed_visibility"] = {
            "task_id": self.unattributed["task_id"],
            "later_principal_registered_and_granted": True,
            "attribution_remains_unmatched": True,
            "scope": "private principal resolution/grant; not a second OAuth login",
        }
        self.verify_native_result(root)

    def verify_native_result(self, root):
        h = self.h
        task = self.unattributed["task_id"]
        guards = native_guards(root, self.unattributed_origin_file)
        spec = self.native_spec(root, task, self.unattributed_origin_file)
        collected = root.command(
            ["collect", task, *guards, "--expected-spec-sha256", spec]
        )
        require(
            collected.get("publication") == "committed"
            and collected.get("outcome", {}).get("verdict") == "committed",
            "unattributed native task has no accepted result",
        )
        descriptor = collected["payload"]
        require_result(descriptor)
        result = root.command(
            [
                "result",
                "read",
                task,
                *guards,
                "--expected-spec-sha256",
                spec,
                "--expected-descriptor",
                h.input_file(descriptor),
                "--offset",
                "0",
                "--limit",
                "65536",
            ]
        )
        native_range = result.get("connector", {}).get("result_range")
        require(
            isinstance(native_range, dict)
            and native_range.get("descriptor") == descriptor,
            "native result range changed accepted descriptor",
        )
        require_result_bytes(native_range)
        h.summary["rollback_unattributed_visibility"][
            "accepted_native_result_verified"
        ] = True

    def run(self):
        self.capture_snapshot()
        # Reuse the maintained recovery's roster, routing census, epoch reset,
        # inventory/debt, drain, regular credentials and guarded reopen checks.
        super().run()
        require_snapshot(self.snapshot)
        self.h.summary["recovery"]["kind"] = "actual_sqlite_snapshot_rollback"
        self.h.summary["stages"].append(
            "older_registry_snapshot_restored_with_later_native_work"
        )


class RollbackHarness(Harness):
    def __init__(self, args, interruptions=None):
        super().__init__(args, interruptions)
        self.sources = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (
                Path(__file__).resolve(),
                Path(__file__).with_name("e2e_local.py").resolve(),
                Path(__file__).with_name("e2e_recovery.py").resolve(),
            )
        }
        self.summary.update(
            category="actual older SQLite Gateway snapshot with later authoritative Native work",
            source_files=self.sources,
            python_version=sys.version,
            source_inputs_unchanged=False,
        )

    def recovery_scenarios(self):
        scenario = SnapshotRollback(self)
        try:
            scenario.run()
            self.check_canaries()
            require(
                all(
                    hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
                    for path, digest in self.sources.items()
                ),
                "rollback source inputs changed",
            )
            self.summary["source_inputs_unchanged"] = True
        finally:
            scenario.release_live_probe()


def main(argv=None):
    os.umask(0o077)
    interruptions = Interruptions()
    previous = {
        number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
    }
    for number in previous:
        signal.signal(number, interruptions.handle)
    try:
        return RollbackHarness(arguments(argv), interruptions=interruptions).run()
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
