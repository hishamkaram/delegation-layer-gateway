"""Real bounded audit-file and Unix-HTTP reader tests; no provider execution."""

from contextlib import contextmanager
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
