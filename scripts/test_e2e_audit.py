"""Real bounded audit-file and Unix-HTTP reader tests; no provider execution."""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import e2e_audit as audit
from e2e_local import ProofFailure


IDENTITY = {"device_id": "device-a", "epoch": "epoch-one", "generation": 7}
HEALTH = {"audit_healthy": True, "audit_failures": 0, "metric_failures": 0}


def denial(**fields):
    return {
        "at": "2026-11-11T13:00:00.123456789Z",
        "code": "device_credential_denied",
        "device": "device-a",
        "credential": dict(IDENTITY),
        **fields,
    }


def line(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def completed_control():
    return {
        "at": "2026-11-12T21:00:00Z",
        "code": "control_completed",
        "principal": "principal-one",
        "device": "device-one",
        "project": "project-one",
        "operation": "operation-one",
        "control": {
            "class": "admit",
            "actor": "principal",
            "authorization": "allowed",
            "recheck": "allowed",
            "transport": "reply_received",
            "control_observation_duration_ns": 37,
            "connection": {"BootEpoch": "boot-one", "Counter": 2},
            "request_id": "g:3",
            "write_state": "write_completed",
            "request_frame_bytes": 101,
            "response_frame_bytes": 202,
            "response_known": True,
        },
    }


def connected(code="device_connected"):
    return {
        "at": "2026-11-12T21:00:00Z",
        "code": code,
        "device": "device-a",
        "credential": dict(IDENTITY),
        "connection": {"BootEpoch": "boot-one", "Counter": 2},
        "connection_duration_ns": 37,
    }


class MetadataRecordTests(unittest.TestCase):
    def test_current_go_completed_control_row_is_accepted(self):
        # Go Event/ControlMetadata JSON shape and completedAuditFixture values.
        # ConnectionGeneration deliberately retains its Go field-name encoding.
        encoded = (
            b'{"at":"2026-11-12T21:00:00Z","code":"control_completed",'
            b'"principal":"principal-one","device":"device-one",'
            b'"project":"project-one","operation":"operation-one",'
            b'"control":{"class":"admit","actor":"principal",'
            b'"authorization":"allowed","recheck":"allowed",'
            b'"transport":"reply_received","control_observation_duration_ns":37,'
            b'"connection":{"BootEpoch":"boot-one","Counter":2},'
            b'"request_id":"g:3","write_state":"write_completed",'
            b'"request_frame_bytes":101,"response_frame_bytes":202,'
            b'"response_known":true}}\n'
        )
        self.assertEqual(list(audit.records(encoded)), [(0, json.loads(encoded))])

    def assert_rejected(self, value):
        with self.assertRaises(ProofFailure):
            list(audit.records(line(value)))

    def test_current_connection_records_include_only_verified_identity(self):
        early = {
            "at": "2026-11-12T21:00:00Z",
            "code": "device_connection_failed",
            "connection_duration_ns": 37,
        }
        verified = connected("device_connection_failed")
        before_generation = deepcopy(verified)
        del before_generation["connection"]
        values = [
            connected(),
            connected("device_disconnected"),
            early,
            verified,
            before_generation,
        ]
        self.assertEqual(
            [value for _, value in audit.records(b"".join(map(line, values)))], values
        )

    def test_valid_control_partitions_preserve_measurement_uncertainty(self):
        for transport, write, request, response in (
            ("not_attempted", "not_started", 0, 0),
            ("not_sent", "not_started", 101, 0),
            ("write_unknown", "attempted_unknown", 101, 0),
            # A validated reply is possible before the original writer joins.
            ("write_unknown", "attempted_unknown", 101, 202),
            ("written_no_reply", "write_completed", 101, 0),
            ("reply_received", "write_completed", 101, 202),
            ("reply_invalid", "write_completed", 101, 202),
        ):
            with self.subTest(transport=transport, response=response):
                value = completed_control()
                value["control"].update(
                    transport=transport,
                    write_state=write,
                    request_frame_bytes=request,
                    response_frame_bytes=response,
                    response_known=response > 0,
                )
                self.assertEqual(list(audit.records(line(value))), [(0, value)])
        prepared = completed_control()
        prepared["code"] = "operation_prepared"
        prepared["control"] = {
            **prepared["control"],
            "class": "prepare",
            "recheck": "not_evaluated",
            "transport": "not_attempted",
            "write_state": "not_started",
            "request_frame_bytes": 0,
            "response_frame_bytes": 0,
            "response_known": False,
        }
        del prepared["control"]["connection"]
        del prepared["control"]["request_id"]
        admin = completed_control()
        admin["control"]["actor"] = "local_admin"
        del admin["principal"]
        self.assertEqual(list(audit.records(line(prepared))), [(0, prepared)])
        self.assertEqual(list(audit.records(line(admin))), [(0, admin)])

    def test_unknown_nested_fields_missing_fields_and_noninteger_numbers_fail(self):
        for field, bad in (
            ("unapproved", "private-canary-content"),
            ("class", "unknown"),
            ("actor", "unknown"),
            ("authorization", "unknown-decision"),
            ("recheck", "unknown-decision"),
            ("control_observation_duration_ns", True),
            ("control_observation_duration_ns", -1),
            ("control_observation_duration_ns", 1 << 63),
            ("request_frame_bytes", False),
            ("request_frame_bytes", 1.0),
            ("request_frame_bytes", 0),
            ("response_frame_bytes", 1 << 20 | 1),
            ("response_known", 1),
            ("response_known", False),
            ("request_id", "private-canary/path"),
            ("connection", {"BootEpoch": "boot", "Counter": True}),
            ("connection", {"BootEpoch": "boot", "Counter": 1 << 64}),
            ("connection", {"BootEpoch": "boot", "Counter": 0}),
            ("connection", {"boot_epoch": "boot", "counter": 2}),
            ("connection", {"BootEpoch": "boot", "Counter": 1, "extra": "private"}),
        ):
            with self.subTest(field=field, bad=bad):
                value = completed_control()
                value["control"][field] = bad
                self.assert_rejected(value)
        missing = completed_control()
        del missing["control"]["write_state"]
        self.assert_rejected(missing)

    def test_illegal_event_identity_and_transport_combinations_fail(self):
        for fields in (
            {"code": "authentication_denied"},
            {"code": "device_disconnected"},
            {"credential": dict(IDENTITY)},
            {"connection": {"BootEpoch": "boot", "Counter": 1}},
            {"connection_duration_ns": 1},
            {"project": "private-canary/path"},
            {"extra": "private-canary-content"},
        ):
            with self.subTest(fields=fields):
                self.assert_rejected({**completed_control(), **fields})
        for changed in (
            {"transport": "unrecognized"},
            {"transport": "not_sent"},
            {"transport": "write_unknown"},
            {"transport": "written_no_reply"},
            {"write_state": "not_started"},
            {"class": "prepare"},
            {"actor": "local_admin"},
        ):
            with self.subTest(changed=changed):
                value = completed_control()
                value["control"].update(changed)
                self.assert_rejected(value)
        for missing in ("principal", "device", "project"):
            value = completed_control()
            del value[missing]
            self.assert_rejected(value)

    def test_connection_schema_refuses_unverified_or_cross_event_metadata(self):
        for fields in (
            {"connection_duration_ns": True},
            {"connection_duration_ns": 1 << 63},
            {"connection_duration_ns": -1},
            {"device": "other-device"},
            {"principal": "principal"},
            {"operation": "operation"},
            {"control": completed_control()["control"]},
            {"project": "project"},
            {"credential": {**IDENTITY, "extra": "private-canary"}},
        ):
            with self.subTest(fields=fields):
                self.assert_rejected({**connected(), **fields})
        for missing in ("credential", "connection", "device"):
            value = connected()
            del value[missing]
            self.assert_rejected(value)
        self.assert_rejected(
            {
                "at": "2026-11-12T21:00:00Z",
                "code": "device_connection_failed",
                "device": "device-a",
                "connection_duration_ns": 37,
            }
        )

    def test_legacy_rows_remain_readable_and_nested_duplicates_are_rejected(self):
        for value in (
            {
                "at": "2026-11-11T13:00:00Z",
                "code": "control_completed",
                "principal": "principal",
                "device": "device-a",
                "operation": "operation",
            },
            {
                "at": "2026-11-11T13:00:00Z",
                "code": "device_connected",
                "device": "device-a",
            },
            denial(),
        ):
            with self.subTest(code=value["code"]):
                self.assertEqual(list(audit.records(line(value))), [(0, value)])
        encoded = line(completed_control()).replace(
            b'"Counter":2', b'"Counter":2,"Counter":3'
        )
        with self.assertRaises(ProofFailure):
            list(audit.records(encoded))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.path = self.directory / "audit-20261111-00.jsonl"
        self.credential = audit.credential_identity(IDENTITY, "device-a")

    def write(self, data, path=None):
        target = self.path if path is None else path
        target.write_bytes(data)
        target.chmod(0o600)

    def append(self, data):
        with self.path.open("ab") as stream:
            stream.write(data)

    def test_current_metadata_rows_do_not_break_matching_denial_cursor(self):
        self.write(line(completed_control()) + line(connected()))
        cursor = audit.AuditCursor.capture(self.directory)
        self.append(line(connected("device_disconnected")) + line(denial()))
        match = cursor.find_denial(self.credential)
        self.assertEqual(match["length"], len(line(denial())))
        self.assertEqual(match["sha256"], hashlib.sha256(line(denial())).hexdigest())

    def test_only_a_new_matching_complete_registration_denial_is_proof(self):
        self.write(line(denial()))
        cursor = audit.AuditCursor.capture(self.directory)
        self.assertFalse(cursor.find_denial(self.credential))
        for changed in (
            {"device_id": "device-b", "epoch": "epoch-one", "generation": 7},
            {"device_id": "device-a", "epoch": "epoch-two", "generation": 7},
            {"device_id": "device-a", "epoch": "epoch-one", "generation": 8},
        ):
            self.append(line(denial(device=changed["device_id"], credential=changed)))
        self.append(
            line({"at": "2026-11-11T13:00:00Z", "code": "device_request_started"})
        )
        self.assertFalse(cursor.find_denial(self.credential))
        encoded = line(denial())
        self.append(encoded[:-1])
        self.assertFalse(cursor.find_denial(self.credential))
        self.append(b"\n")
        match = cursor.find_denial(self.credential)
        self.assertEqual(match["segment"], self.path.name)
        self.assertEqual(match["length"], len(encoded))
        self.assertEqual(match["offset"], self.path.stat().st_size - len(encoded))
        self.assertEqual(match["sha256"], hashlib.sha256(encoded).hexdigest())
        receipt = cursor.receipt()
        self.assertEqual(receipt["positions"][0]["size"], len(line(denial())))

    def test_a_record_started_before_cursor_never_counts_even_when_completed_later(
        self,
    ):
        encoded = line(denial())
        self.write(encoded[:40])
        cursor = audit.AuditCursor.capture(self.directory)
        self.append(encoded[40:])
        self.assertFalse(cursor.find_denial(self.credential))
        self.append(encoded)
        self.assertTrue(cursor.find_denial(self.credential))

    def test_rotation_preserves_cursor_and_accepts_next_segment_or_new_day(self):
        self.write(line(denial()))
        cursor = audit.AuditCursor.capture(self.directory)
        second = self.directory / "audit-20261111-01.jsonl"
        self.write(line(denial()), second)
        self.assertTrue(cursor.find_denial(self.credential))
        next_day = self.directory / "audit-20261112-00.jsonl"
        self.write(line(denial()), next_day)
        self.assertTrue(cursor.find_denial(self.credential))

    def test_disappeared_rewritten_replaced_truncated_history_and_rotation_gaps_fail(
        self,
    ):
        for mutation in ("remove", "rewrite", "replace", "truncate", "gap"):
            with self.subTest(mutation=mutation):
                for path in self.directory.iterdir():
                    path.unlink()
                self.write(line(denial()))
                cursor = audit.AuditCursor.capture(self.directory)
                if mutation == "remove":
                    self.path.unlink()
                elif mutation == "rewrite":
                    self.write(line(denial(credential={**IDENTITY, "generation": 8})))
                elif mutation == "replace":
                    replacement = self.directory / "replacement"
                    self.write(line(denial()), replacement)
                    replacement.replace(self.path)
                elif mutation == "truncate":
                    self.write(b"")
                else:
                    self.write(
                        line(denial()), self.directory / "audit-20261111-02.jsonl"
                    )
                with self.assertRaises(ProofFailure):
                    cursor.find_denial(self.credential)

    def test_malformed_complete_record_invalidates_even_when_match_precedes_it(self):
        self.write(b"")
        cursor = audit.AuditCursor.capture(self.directory)
        for bad in (
            b"not JSON\n",
            b'{"at":"2026-11-11T13:00:00Z","at":"duplicate","code":"x"}\n',
            line({"code": "device_request_started"}),
            line(denial(principal="unrelated")),
            line(denial(credential={**IDENTITY, "generation": True})),
            line(denial(credential={**IDENTITY, "extra": "unapproved"})),
            line(denial(device="other-device")),
            line(denial(at="2026-02-30T13:00:00Z")),
            line(
                {"at": "2026-11-11T13:00:00Z", "code": "other", "credential": IDENTITY}
            ),
        ):
            with self.subTest(bad=bad):
                self.write(line(denial()) + bad)
                with self.assertRaises(ProofFailure):
                    cursor.find_denial(self.credential)

    def test_file_directory_and_memory_bounds_fail_closed(self):
        self.write(line(denial()))
        for mode in (0o644, 0o660):
            self.path.chmod(mode)
            with self.assertRaises(ProofFailure):
                audit.AuditCursor.capture(self.directory)
        self.path.chmod(0o600)
        self.directory.chmod(0o755)
        with self.assertRaises(ProofFailure):
            audit.AuditCursor.capture(self.directory)
        self.directory.chmod(0o700)
        with patch.object(audit, "SEGMENT_BYTES", 10):
            with self.assertRaises(ProofFailure):
                audit.AuditCursor.capture(self.directory)
        with patch.object(audit, "TOTAL_BYTES", 10):
            with self.assertRaises(ProofFailure):
                audit.AuditCursor.capture(self.directory)
        self.write(b"x" * (audit.MAX_RECORD_BYTES + 1))
        with self.assertRaises(ProofFailure):
            audit.AuditCursor.capture(self.directory)
        self.path.unlink()
        self.path.symlink_to("/dev/null")
        with self.assertRaises(ProofFailure):
            audit.AuditCursor.capture(self.directory)

    def test_identity_is_frozen_strict_and_uint64_bounded(self):
        value = dict(IDENTITY)
        identity = audit.credential_identity(value, "device-a")
        value["generation"] = 8
        self.assertEqual(identity, ("device-a", "epoch-one", 7))
        for key, invalid in (
            ("generation", True),
            ("generation", 0),
            ("generation", 1 << 64),
            ("epoch", "contains:colon"),
            ("epoch", ""),
            ("epoch", "x" * 129),
            ("device_id", "other"),
        ):
            with (
                self.subTest(key=key, invalid=invalid),
                self.assertRaises(ProofFailure),
            ):
                audit.credential_identity({**IDENTITY, key: invalid}, "device-a")

    def test_replacing_the_owned_directory_invalidates_the_cursor(self):
        directory = self.directory / "owned"
        directory.mkdir(mode=0o700)
        path = directory / self.path.name
        self.write(line(denial()), path)
        cursor = audit.AuditCursor.capture(directory)
        directory.rename(self.directory / "retained-old-directory")
        directory.mkdir(mode=0o700)
        self.write(line(denial()), directory / self.path.name)
        with self.assertRaisesRegex(ProofFailure, "directory replaced"):
            cursor.find_denial(self.credential)

    def test_segment_count_is_bounded_even_with_empty_files(self):
        self.write(b"")
        self.write(b"", self.directory / "audit-20261111-01.jsonl")
        self.write(b"", self.directory / "audit-20261111-02.jsonl")
        with patch.object(audit, "MAX_SEGMENTS", 1):
            with self.assertRaisesRegex(ProofFailure, "count"):
                audit.AuditCursor.capture(self.directory)

    def test_invalid_segment_names_and_dates_fail_closed(self):
        for name in (
            "audit-20260230-00.jsonl",
            "audit-20261111-001.jsonl",
            "unexpected",
        ):
            with self.subTest(name=name):
                path = self.directory / name
                self.write(b"", path)
                with self.assertRaises(ProofFailure):
                    audit.AuditCursor.capture(self.directory)
                path.unlink()


class HealthTests(unittest.TestCase):
    @contextmanager
    def server(self, response):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "admin.sock"
            errors = []
            requests = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                listener.settimeout(3)

                def serve():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(3)
                            requests.append(connection.recv(1024))
                            connection.sendall(response)
                    except BaseException as error:
                        errors.append(error)

                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    yield path, requests
                finally:
                    thread.join(4)
                    self.assertFalse(
                        thread.is_alive(), "owned health responder did not join"
                    )
                    self.assertEqual(errors, [])

    def response(self, value=HEALTH, status="200 OK", headers=b""):
        body = json.dumps(value).encode()
        return (
            b"HTTP/1.1 " + status.encode() + b"\r\nContent-Type: application/json\r\n"
            b"Cache-Control: no-store\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n"
            + headers
            + b"\r\n"
            + body
        )

    def test_real_private_unix_get_health_and_all_owned_resources_join(self):
        with self.server(self.response()) as (path, requests):
            self.assertEqual(audit.read_health(path), HEALTH)
        self.assertEqual(
            requests,
            [
                b"GET /v1/metadata/health HTTP/1.1\r\nHost: unix\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
            ],
        )

    def test_sticky_failures_wrong_schema_redirect_and_oversize_are_not_healthy(self):
        responses = [
            self.response({**HEALTH, "audit_healthy": False, "audit_failures": 1}),
            self.response({**HEALTH, "metric_failures": 1}),
            self.response({**HEALTH, "audit_failures": False}),
            self.response({**HEALTH, "unknown": "field"}),
            self.response(status="302 Found", headers=b"Location: http://other/\r\n"),
            self.response({"padding": "x" * 9000}),
        ]
        for response in responses:
            with self.subTest(size=len(response)):
                with self.server(response) as (path, _):
                    with self.assertRaises(ProofFailure):
                        audit.read_health(path)

    def test_non_socket_and_missing_socket_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "not-socket"
            path.write_text("no connection")
            with self.assertRaises(ProofFailure):
                audit.read_health(path)
            path.unlink()
            with self.assertRaises(ProofFailure):
                audit.read_health(path)


if __name__ == "__main__":
    unittest.main()
