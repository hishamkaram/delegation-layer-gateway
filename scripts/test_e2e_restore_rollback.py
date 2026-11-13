"""Real SQLite rollback and fail-closed ownership tests; no Native actors."""

import base64
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from e2e_local import ProofFailure
import e2e_restore_rollback as rollback


def database(path, rows):
    path.touch(mode=0o600)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE operations(id TEXT PRIMARY KEY)")
        connection.executemany(
            "INSERT INTO operations VALUES(?)", [(row,) for row in rows]
        )
        connection.commit()
    return path


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.source = database(self.base / "registry.sqlite", ["old"])
        self.backup = self.base / "snapshot.sqlite"

    def test_real_backup_and_restore_remove_later_committed_rows(self):
        rollback.backup_database(self.source, self.backup, create=True)
        snapshot = rollback.snapshot_descriptor(self.backup)
        with closing(sqlite3.connect(self.source)) as connection:
            connection.execute("INSERT INTO operations VALUES('later')")
            connection.commit()
        self.assertEqual(
            rollback.operation_membership(self.source, ("old", "later")),
            {"old", "later"},
        )
        rollback.backup_database(self.backup, self.source, create=False)
        self.assertEqual(
            rollback.operation_membership(self.source, ("old", "later")), {"old"}
        )
        rollback.require_snapshot(snapshot)

    def test_snapshot_commitment_rejects_replacement_or_edited_database(self):
        rollback.backup_database(self.source, self.backup, create=True)
        snapshot = rollback.snapshot_descriptor(self.backup)
        replacement = self.base / "replacement.sqlite"
        replacement.write_bytes(self.backup.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(self.backup)
        with self.assertRaisesRegex(ProofFailure, "snapshot commitment changed"):
            rollback.require_snapshot(snapshot)
        snapshot = rollback.snapshot_descriptor(self.backup)
        with closing(sqlite3.connect(self.backup)) as connection:
            connection.execute("INSERT INTO operations VALUES('edited')")
            connection.commit()
        with self.assertRaisesRegex(ProofFailure, "snapshot commitment changed"):
            rollback.require_snapshot(snapshot)

    def test_copy_cannot_overwrite_a_snapshot_or_copy_onto_source(self):
        rollback.backup_database(self.source, self.backup, create=True)
        original = self.backup.read_bytes()
        with self.assertRaises(FileExistsError):
            rollback.backup_database(self.source, self.backup, create=True)
        with self.assertRaisesRegex(ProofFailure, "source equals destination"):
            rollback.backup_database(self.source, self.source, create=False)
        self.assertEqual(self.backup.read_bytes(), original)

    def test_nonprivate_source_and_symlink_are_rejected_before_destination_create(self):
        self.source.chmod(0o644)
        with self.assertRaisesRegex(ProofFailure, "ownership changed"):
            rollback.backup_database(self.source, self.backup, create=True)
        self.assertFalse(self.backup.exists())
        self.source.chmod(0o600)
        alias = self.base / "alias"
        alias.symlink_to(self.source)
        with self.assertRaisesRegex(ProofFailure, "database alias"):
            rollback.backup_database(alias, self.backup, create=True)
        self.assertFalse(self.backup.exists())


class RestoreOwnerTests(unittest.TestCase):
    def test_invalid_pre_snapshot_budget_cannot_prepare_stop_or_copy(self):
        for counts in (
            {"attempted": 1, "rejected_concurrent": 0, "rejected_limit": 0},
            {"attempted": 3, "rejected_concurrent": 0, "rejected_limit": 0},
            {"attempted": 2, "rejected_concurrent": 1, "rejected_limit": 0},
            {"attempted": 2, "rejected_concurrent": 0, "rejected_limit": 1},
        ):
            with (
                self.subTest(counts=counts),
                tempfile.TemporaryDirectory() as temporary,
            ):
                base = Path(temporary).resolve()
                source = database(base / "registry.sqlite", ["old"])
                h = SimpleNamespace(
                    fixture_attempts=mock.Mock(return_value=counts),
                    prepare=mock.Mock(
                        return_value={"operation_id": "stale", "task_id": "task"}
                    ),
                    stop_process=mock.Mock(return_value=0),
                    gateway=object(),
                    gateway_config={"database": str(source)},
                    base=base,
                    roots=[object()],
                    summary={},
                    start_gateway=mock.Mock(),
                    until=mock.Mock(return_value=True),
                )
                h.assert_fixture_attempts = lambda expected: (
                    rollback.Harness.assert_fixture_attempts(h, expected)
                )
                scenario = rollback.SnapshotRollback(h)
                with self.assertRaisesRegex(
                    ProofFailure, "unexpected or rejected fixture"
                ):
                    scenario.capture_snapshot()
                h.prepare.assert_not_called()
                h.stop_process.assert_not_called()
                h.start_gateway.assert_not_called()
                self.assertFalse((base / "registry-before-later-work.sqlite").exists())
                self.assertNotIn("rollback_snapshot", h.summary)

    def setup_scenario(self, base):
        source = database(base / "registry.sqlite", ["stale", "later"])
        snapshot_path = database(base / "snapshot.sqlite", ["stale"])
        events = []
        h = SimpleNamespace(
            gateway_config={"database": str(source)},
            gateway=object(),
            gateway_id="gateway",
            args=SimpleNamespace(gateway=Path("/fixture/gateway")),
            summary={},
            roots=[SimpleNamespace(release_fixture_gate=mock.Mock())],
        )
        h.stop_process = mock.Mock(side_effect=lambda _p: events.append("join") or 0)

        def command(_program, args):
            events.append(args[0])
            if args[0] == "identity":
                return {"gateway_id": h.gateway_id}
            return {"recovery_id": scenario.recovery, "kind": "restore"}

        h.command = mock.Mock(side_effect=command)
        h.start_gateway = mock.Mock(side_effect=lambda: events.append("start"))
        h.check_auth = mock.Mock(side_effect=lambda: events.append("auth"))
        scenario = rollback.SnapshotRollback(h)
        scenario.snapshot = rollback.snapshot_descriptor(snapshot_path)
        scenario.stale = {"operation_id": "stale"}
        scenario.future_result = {"prepared": {"operation_id": "later"}}
        observation = SimpleNamespace(task_id="task", pid=123, identity=(1, 2))
        lease = SimpleNamespace(
            assert_live=mock.Mock(side_effect=lambda: events.append("live"))
        )
        scenario.live = observation, lease
        scenario.unattributed = {"task_id": "task"}
        scenario.unattributed_origin_file = base / "origin.json"
        scenario.release_live_probe = mock.Mock(
            side_effect=lambda: events.append("release")
        )
        scenario.native_closure = mock.Mock(
            side_effect=lambda *_: events.append("native_closure")
        )
        return scenario, source, events

    def test_actual_restore_is_between_original_writer_join_and_offline_fence(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenario, source, events = self.setup_scenario(Path(temporary).resolve())
            original = rollback.backup_database

            def copy(*args, **kwargs):
                events.append("restore")
                return original(*args, **kwargs)

            with mock.patch.object(rollback, "backup_database", side_effect=copy):
                scenario.start_recovery()
            self.assertEqual(
                events,
                [
                    "live",
                    "join",
                    "live",
                    "restore",
                    "live",
                    "migrate",
                    "identity",
                    "begin-recovery",
                    "live",
                    "release",
                    "native_closure",
                    "start",
                    "auth",
                ],
            )
            self.assertEqual(
                rollback.operation_membership(source, ("stale", "later")), {"stale"}
            )
            self.assertTrue(
                scenario.h.summary["rollback_while_native_active"][
                    "later_correlation_present_before_and_absent_after_restore"
                ]
            )

    def test_skipping_the_real_restore_cannot_publish_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenario, _source, _events = self.setup_scenario(Path(temporary).resolve())
            with (
                mock.patch.object(rollback, "backup_database"),
                self.assertRaisesRegex(ProofFailure, "actual rollback did not remove"),
            ):
                scenario.start_recovery()
            scenario.h.command.assert_not_called()
            self.assertNotIn("rollback_while_native_active", scenario.h.summary)

    def test_missing_live_writer_or_failed_gateway_join_cannot_restore(self):
        for failure in ("live", "gateway"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temporary,
            ):
                scenario, source, _events = self.setup_scenario(
                    Path(temporary).resolve()
                )
                if failure == "live":
                    scenario.live[1].assert_live.side_effect = ProofFailure("not live")
                else:
                    scenario.h.stop_process.return_value = 1
                    scenario.h.stop_process.side_effect = None
                with (
                    mock.patch.object(rollback, "backup_database") as copier,
                    self.assertRaises(ProofFailure),
                ):
                    scenario.start_recovery()
                copier.assert_not_called()
                scenario.h.command.assert_not_called()
                self.assertEqual(
                    rollback.operation_membership(source, ("stale", "later")),
                    {"stale", "later"},
                )
                if failure == "live":
                    scenario.h.stop_process.assert_not_called()

    def test_outer_recovery_owner_releases_live_probe_on_failure(self):
        scenario = mock.Mock()
        scenario.run.side_effect = ProofFailure("failed recovery")
        h = SimpleNamespace(check_canaries=mock.Mock())
        with (
            mock.patch.object(rollback, "SnapshotRollback", return_value=scenario),
            self.assertRaises(ProofFailure),
        ):
            rollback.RollbackHarness.recovery_scenarios(h)
        scenario.release_live_probe.assert_called_once_with()
        h.check_canaries.assert_not_called()


class ResultTests(unittest.TestCase):
    def test_result_range_checks_bytes_identity_and_end(self):
        descriptor = {
            "basename": "result.txt",
            "length": len(rollback.EXPECTED_RESULT),
            "sha256": hashlib.sha256(rollback.EXPECTED_RESULT).hexdigest(),
        }
        valid = {
            "offset": 0,
            "next_offset": len(rollback.EXPECTED_RESULT),
            "eof": True,
            "data_base64": base64.b64encode(rollback.EXPECTED_RESULT).decode(),
        }
        h = SimpleNamespace(mcp=mock.Mock(return_value=valid))
        rollback.verify_result_bytes(h, {"operation_id": "op"}, descriptor)
        for field, changed in (
            ("offset", 1),
            ("next_offset", 1),
            ("eof", False),
            ("data_base64", "UE9ORw=="),
        ):
            with self.subTest(field=field), self.assertRaises(ProofFailure):
                h.mcp.return_value = {**valid, field: changed}
                rollback.verify_result_bytes(h, {"operation_id": "op"}, descriptor)


if __name__ == "__main__":
    unittest.main()
