"""Finite pipe/child proofs through the maintained Native Start/Wait owner."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import e2e_local as local
import e2e_remote_channel as channel

PYTHON = str(Path(sys.executable).resolve())
EOF_CHILD = """import os,select,sys
while select.select([0],[],[],3)[0]:
    if not os.read(0,65536): sys.exit(0)
sys.exit(9)
"""
ROUND_TRIP = """import json,os,select,sys
for event in ('initialized','enroll'):
    if not select.select([0],[],[],3)[0]: sys.exit(9)
    value=json.loads(sys.stdin.readline())
    print(json.dumps({'event':event,'answer':value['payload']['question']+1,'request_id':value['request_id']}),flush=True)
if not select.select([0],[],[],3)[0]: sys.exit(9)
sys.exit(0 if os.read(0,1)==b'' else 8)
"""


class ChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository = os.environ.get("DELEGATE_ACCEPTANCE_REPOSITORY")
        if not repository:
            raise unittest.SkipTest(
                "set DELEGATE_ACCEPTANCE_REPOSITORY for maintained owner tests"
            )
        cls.acceptance = local.load_acceptance(Path(repository))

    def setUp(self):
        self.owner = self.acceptance.directories.DirectoryOwner()
        self.root = Path(tempfile.mkdtemp(prefix="remote-channel-")).resolve()
        self.owner.adopt_created("channel test", self.root, self.root.parent)
        self.channels = []
        self.books = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for link in self.channels:
            link.close_input()
        unresolved = []
        for book in self.books:
            unresolved.extend(book.drain(timeout=5))
        for link in self.channels:
            link.capture.close()
        if unresolved:
            self.owner.release()
            raise RuntimeError("closure unconfirmed; retained " + str(self.root))
        self.owner.rollback()

    def prepare(self, source):
        link = channel.PeerChannel(self.acceptance.processes, (PYTHON, "-c", source))
        self.channels.append(link)
        book = self.acceptance.processes.Processes(
            self.root / str(len(self.books)),
            environment={},
            owner=self.owner,
            stdout_capture_factory=link.capture_factory,
        )
        self.books.append(book)
        return link, book

    def start(self, source):
        link, book = self.prepare(source)
        link.start(book, "peer", self.root)
        return link, book

    def test_two_way_frames_eof_and_exact_native_wait(self):
        link, book = self.start(ROUND_TRIP)
        self.assertFalse(os.get_inheritable(link._writer))
        for event, number in (("initialized", 40), ("enroll", 99)):
            link.send_json({"question": number}, expected_event=event)
            self.assertEqual(link.expect(event), {"event": event, "answer": number + 1})
        self.assertIsNone(link.process.poll(), "only caller EOF closes input")
        link.close_input()
        link.close_input()
        # Native's own exact Wait is counted; the channel never invokes it.
        with patch.object(
            link.process.process, "wait", wraps=link.process.process.wait
        ) as waited:
            result = link.join(timeout=3)
            self.assertEqual(link.join(timeout=3), result)
        waited.assert_called_once_with()
        self.assertTrue(result["natural_wait"])
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(book.finished_naturally())
        metadata = link.process.stdout_path.read_text()
        self.assertEqual(json.loads(metadata)["events"], ["initialized", "enroll"])
        self.assertNotIn('"answer"', metadata)

    def test_exited_child_has_no_hidden_parent_reader(self):
        link, _ = self.start("pass")
        self.assertEqual(link.join(timeout=3)["exit_code"], 0)
        with self.assertRaises(BrokenPipeError):
            link.write_bytes(b"x")
        self.assertIsNone(link._writer)

    def test_post_start_publication_failure_retains_handle_and_closes_writer(self):
        link, book = self.prepare(EOF_CHILD)
        operations = self.acceptance.processes
        original = operations.write_json

        def fail_publication(path, value):
            if path.name == "started.json":
                raise OSError("injected publication fault")
            original(path, value)

        with patch.object(operations, "write_json", side_effect=fail_publication):
            with self.assertRaisesRegex(OSError, "injected publication fault"):
                link.start(book, "peer", self.root)
        self.assertIs(book.entries[0], link.process)
        self.assertIsNone(link._writer)
        self.assertEqual(link.join(timeout=3)["exit_code"], 0)
        with self.assertRaisesRegex(channel.ChannelFailure, "already_attempted"):
            link.start(book, "again", self.root)
        self.assertEqual(len(book.entries), 1)

    def test_unrelated_child_keeps_ordinary_capture(self):
        link, book = self.prepare(EOF_CHILD)
        other = book.start("other", (PYTHON, "-c", "print('ordinary')"), self.root)
        self.assertEqual(other.wait(timeout=3), 0)
        self.assertEqual(other.output(), b"ordinary\n")
        self.assertFalse(link._capture_claimed)
        link.start(book, "peer", self.root)
        link.close_input()
        self.assertEqual(link.join(timeout=3)["exit_code"], 0)

    def test_backpressure_times_out_closes_input_and_pumps_owner(self):
        source = "import time;time.sleep(.2)\n" + EOF_CHILD
        link, _ = self.start(source)
        ticks = []
        with self.assertRaisesRegex(channel.ChannelFailure, "write_deadline"):
            link.write_bytes(
                b"x" * (1 << 20), timeout=0.06, pump=lambda: ticks.append(1)
            )
        self.assertGreaterEqual(len(ticks), 2)
        self.assertIsNone(link._writer)
        self.assertEqual(link.join(timeout=3)["exit_code"], 0)

    def test_partial_writes_deliver_all_bytes_before_eof(self):
        source = """import os,select,sys,json
count=0
while select.select([0],[],[],3)[0]:
    chunk=os.read(0,1024)
    if not chunk: break
    count+=len(chunk)
else: sys.exit(9)
print(json.dumps({'event':'bootstrap_ready','bytes':count}),flush=True)
"""
        link, _ = self.start(source)
        link.write_bytes(b"x" * (256 << 10), timeout=3)
        link.close_input()
        self.assertEqual(link.expect("bootstrap_ready", timeout=3)["bytes"], 256 << 10)
        self.assertEqual(link.join(timeout=3)["exit_code"], 0)

    def test_faulted_output_is_still_drained_and_joined(self):
        sources = {
            "malformed": "os.write(1,b'bad\\n')",
            "oversized": "os.write(1,b'x'*70000+b'\\n')",
            "continuous": "\nfor _ in range(1024): os.write(1,b'x'*8192)",
        }
        for name, output in sources.items():
            with self.subTest(name=name):
                link, _ = self.start("import os\n" + output)
                link.close_input()
                drained = []
                original = link.capture.drain

                def bounded_drain():
                    before = link.capture.bytes
                    original()
                    drained.append(link.capture.bytes - before)

                with patch.object(link.capture, "drain", side_effect=bounded_drain):
                    result = link.join(timeout=5)
                self.assertTrue(drained)
                self.assertLessEqual(max(drained), channel.DRAIN_BYTES)
                self.assertEqual(result["exit_code"], 0)
                self.assertTrue(result["natural_wait"])
                self.assertIsNotNone(result["capture_error"])
                self.assertTrue(link.capture.eof)
                self.assertGreater(link.capture.bytes, 0)
                self.assertNotIn("xxxxx", link.process.stdout_path.read_text())

    def test_strict_json_and_fixed_events_reject_without_raw_payload(self):
        invalid = [
            b'{"event":"initialized","event":"final"}\n',
            b'{"event":"initialized","secret":NaN}\n',
            b'{"event":"initialized","secret":1e999}\n',
            b'{"event":"initialized","secret":"\xff"}\n',
            b'{"event":"PRIVATE-CANARY"}\n',
            b"[]\n",
            b'{"event":"initialized"}',
        ]
        for data in invalid:
            with self.subTest(data=data):
                link, _ = self.start("import os;os.write(1," + repr(data) + ")")
                link.close_input()
                self.assertIsNotNone(link.join(timeout=3)["capture_error"])
                self.assertNotIn("PRIVATE-CANARY", link.process.stdout_path.read_text())

    def test_unexpected_terminal_and_duplicate_frames_are_retained(self):
        for events, first, expected in (
            (["final"], None, "initialized"),
            (["bootstrap_ready"], None, "initialized"),
            (
                ["bootstrap_ready", "bootstrap_ready"],
                "bootstrap_ready",
                "bootstrap_ready",
            ),
        ):
            with self.subTest(events=events):
                data = b"".join(
                    json.dumps({"event": e}).encode() + b"\n" for e in events
                )
                read_request = "os.read(0,65536);" if first is None else ""
                link, _ = self.start(
                    "import os;" + read_request + "os.write(1," + repr(data) + ")"
                )
                if first:
                    link.expect(first)
                else:
                    link.send_json({}, expected_event=expected)
                with self.assertRaisesRegex(channel.ChannelFailure, "unexpected"):
                    link.expect(expected)
                self.assertEqual(link.capture.peek()["event"], events[-1])
                self.assertEqual(link.join(timeout=3)["exit_code"], 0)

    def test_repeated_command_responses_require_fresh_requests(self):
        source = """import json,select,sys
for index in range(4):
    if not select.select([0],[],[],3)[0]: sys.exit(9)
    request=json.loads(sys.stdin.readline())
    print(json.dumps({'event':request['payload']['operation'],'sequence':index,'request_id':request['request_id']}),flush=True)
if not select.select([0],[],[],3)[0]: sys.exit(9)
sys.exit(0 if sys.stdin.readline()=='' else 8)
"""
        link, book = self.start(source)
        operations = (
            "inspect_closure",
            "inspect_closure",
            "wait_fixture_started",
            "wait_fixture_started",
        )
        for sequence, operation in enumerate(operations):
            link.send_json({"operation": operation}, expected_event=operation)
            self.assertEqual(
                link.expect(operation), {"event": operation, "sequence": sequence}
            )
        link.close_input()
        self.assertEqual(link.join(timeout=3)["exit_code"], 0)
        self.assertEqual(len(book.entries), 1)

    def test_unsolicited_repeated_command_response_is_retained(self):
        source = """import json,select,sys
if not select.select([0],[],[],3)[0]: sys.exit(9)
json.loads(sys.stdin.readline())
for _ in range(2): print('{"event":"inspect_closure","request_id":1}',flush=True)
if not select.select([0],[],[],3)[0]: sys.exit(9)
sys.exit(0 if sys.stdin.readline()=='' else 8)
"""
        link, _ = self.start(source)
        link.send_json(
            {"operation": "inspect_closure"}, expected_event="inspect_closure"
        )
        self.assertEqual(link.expect("inspect_closure"), {"event": "inspect_closure"})
        with self.assertRaises(channel.ChannelFailure):
            link.expect("inspect_closure")
        self.assertEqual(link.join(timeout=3)["exit_code"], 0)
        self.assertEqual(
            link.capture.peek(), {"event": "inspect_closure", "request_id": 1}
        )

    def test_stale_same_event_response_cannot_satisfy_fresh_request(self):
        for queued in (True, False):
            with self.subTest(queued=queued):
                source = """import json,select,sys
for index in (1,2):
    if not select.select([0],[],[],3)[0]: sys.exit(9)
    json.loads(sys.stdin.readline())
    if index==1:
        print('{"event":"inspect_closure","request_id":1}',flush=True)
        if QUEUED: print('{"event":"inspect_closure","request_id":1}',flush=True)
    else:
        if not QUEUED: print('{"event":"inspect_closure","request_id":1}',flush=True)
        print('{"event":"inspect_closure","request_id":2}',flush=True)
if not select.select([0],[],[],3)[0]: sys.exit(9)
sys.exit(0 if sys.stdin.readline()=='' else 8)
""".replace("QUEUED", repr(queued))
                link, book = self.start(source)
                link.send_json(
                    {"operation": "inspect_closure"}, expected_event="inspect_closure"
                )
                self.assertEqual(
                    link.expect("inspect_closure")["event"], "inspect_closure"
                )
                link.send_json(
                    {"operation": "inspect_closure"}, expected_event="inspect_closure"
                )
                with self.assertRaises(channel.ChannelFailure):
                    link.expect("inspect_closure")
                self.assertEqual(link.join(timeout=3)["exit_code"], 0)
                self.assertEqual(link.capture.peek()["request_id"], 1)
                self.assertEqual(len(book.entries), 1)

    def test_response_request_id_is_an_exact_matching_integer(self):
        frames = [{"event": "inspect_closure"}] + [
            {"event": "inspect_closure", "request_id": request_id}
            for request_id in (True, 1.0, "1", 0, 2, None)
        ]
        for frame in frames:
            with self.subTest(frame=frame):
                data = json.dumps(frame).encode() + b"\n"
                link, _ = self.start(
                    "import os;os.read(0,65536);os.write(1," + repr(data) + ")"
                )
                link.send_json(
                    {"operation": "inspect_closure"}, expected_event="inspect_closure"
                )
                with self.assertRaisesRegex(channel.ChannelFailure, "request_id"):
                    link.expect("inspect_closure")
                self.assertEqual(link.join(timeout=3)["exit_code"], 0)
                self.assertEqual(link.capture.peek(), frame)

    def test_unsolicited_event_must_not_have_a_request_id(self):
        for event in ("bootstrap_ready", "bootstrap_failed", "failed", "final"):
            with self.subTest(event=event):
                frame = {"event": event, "request_id": 1}
                data = json.dumps(frame).encode() + b"\n"
                link, _ = self.start("import os;os.write(1," + repr(data) + ")")
                with self.assertRaisesRegex(channel.ChannelFailure, "request_id"):
                    link.expect(event)
                self.assertEqual(link.join(timeout=3)["exit_code"], 0)
                self.assertEqual(link.capture.peek(), frame)

    def test_caller_cannot_supply_transport_envelope_fields(self):
        for payload in ({"request_id": 1}, {"payload": {}}, [], None):
            with self.subTest(payload=payload):
                link, book = self.start(EOF_CHILD)
                with self.assertRaisesRegex(channel.ChannelFailure, "request_payload"):
                    link.send_json(payload, expected_event="inspect_closure")
                self.assertEqual(link.join(timeout=3)["exit_code"], 0)
                self.assertEqual(len(book.entries), 1)

    def test_one_pending_request_and_no_automatic_retry(self):
        link, book = self.start(EOF_CHILD)
        link.send_json({}, expected_event="initialized")
        with self.assertRaisesRegex(channel.ChannelFailure, "request_pending"):
            link.send_json({}, expected_event="enroll")
        self.assertEqual(link.join(timeout=3)["exit_code"], 0)
        self.assertEqual(len(book.entries), 1)

    def test_capture_limits_frames_and_bounded_drain_without_starving_wait(self):
        # This directly probes per-drain progress using an actual pipe. The finite
        # child path above separately proves Native can drain faulted captures.
        capture = channel.JSONLCapture()
        self.addCleanup(capture.close)
        os.set_blocking(capture.writer.fileno(), False)
        line = b'{"event":"initialized"}\n'
        os.write(capture.writer.fileno(), line * 65)
        capture.drain()
        self.assertEqual(capture.error, "output_frame_count")
        self.assertEqual(len(capture._frames), 64)
        self.assertEqual(json.loads(capture.sanitized(0))["frames"], 64)


if __name__ == "__main__":
    unittest.main()
