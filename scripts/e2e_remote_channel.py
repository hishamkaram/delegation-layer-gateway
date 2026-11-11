"""Thin fixture I/O over a child owned exclusively by NativeProcesses.

PeerChannel owns stdin EOF and one pending response. JSONLCapture owns parsing;
Native owns Start, uncertain admission, output finalization and exact Wait. Neither
EOF nor a joined transport proves closure of tasks on the remote device.
"""

from __future__ import annotations

from collections import deque
import json
import math
import os
import select
import time

import e2e_remote_peer as peer

MAX_BYTES = 4 << 20
MAX_FRAMES = 64
DRAIN_BYTES = 64 << 10
EVENTS = frozenset(
    {
        "bootstrap_ready",
        "bootstrap_failed",
        "initialized",
        "enroll",
        "start_connector",
        "hold_fixture",
        "release_fixture",
        "wait_fixture_started",
        "inspect_closure",
        "shutdown",
        "failed",
        "final",
    }
)

UNSOLICITED_EVENTS = frozenset(
    {"bootstrap_ready", "bootstrap_failed", "failed", "final"}
)
LIFECYCLE_EVENTS = frozenset(
    {"bootstrap_ready", "bootstrap_failed", "initialized", "failed", "final"}
)


class ChannelFailure(RuntimeError):
    """Fixed public failure kind; never includes peer payload or raw errors."""


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("nonfinite_number")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite_number")
    return number


class JSONLCapture:
    """Bounded consumer capture; faults latch but never prevent native draining."""

    def __init__(self):
        reader, writer = os.pipe()
        try:
            os.set_blocking(reader, False)
            self.writer = os.fdopen(writer, "wb", buffering=0)
        except BaseException:
            os.close(reader)
            os.close(writer)
            raise
        self._reader = reader
        self.eof = False
        self.error = None
        self._buffer = bytearray()
        self._frames = deque()
        self._events = []
        self.bytes = 0

    def _fault(self, kind):
        if self.error is None:
            self.error = kind
        self._buffer.clear()

    def _accept(self, chunk):
        self.bytes += len(chunk)
        if self.bytes > MAX_BYTES:
            self._fault("output_byte_limit")
        if self.error is not None:
            return
        self._buffer.extend(chunk)
        while b"\n" in self._buffer:
            line, _, remainder = self._buffer.partition(b"\n")
            self._buffer = bytearray(remainder)
            if len(line) + 1 > peer.MAX_LINE:
                self._fault("output_frame_limit")
                return
            try:
                value = json.loads(
                    line.decode("utf-8"),
                    object_pairs_hook=unique_object,
                    parse_constant=reject_constant,
                    parse_float=finite_float,
                )
            except (ValueError, UnicodeError, RecursionError):
                self._fault("invalid_output_json")
                return
            if (
                type(value) is not dict
                or type(value.get("event")) is not str
                or value["event"] not in EVENTS
            ):
                self._fault("invalid_output_event")
                return
            if len(self._events) >= MAX_FRAMES:
                self._fault("output_frame_count")
                return
            self._events.append(value["event"])
            self._frames.append(value)
        if len(self._buffer) >= peer.MAX_LINE:
            self._fault("output_frame_limit")

    def drain(self):
        if self.eof:
            return
        remaining = DRAIN_BYTES
        while remaining:
            try:
                chunk = os.read(self._reader, min(remaining, 16384))
            except BlockingIOError:
                return
            except InterruptedError:
                return
            except OSError:
                self._fault("output_read_failed")
                self.eof = True
                return
            if not chunk:
                if self._buffer and self.error is None:
                    self._fault("incomplete_output_frame")
                self.eof = True
                return
            remaining -= len(chunk)
            self._accept(chunk)

    def peek(self):
        return self._frames[0] if self._frames else None

    def pop(self):
        """Transfer the next frame and its payload to the caller."""
        return self._frames.popleft() if self._frames else None

    def sanitized(self, code):
        return (
            json.dumps(
                {
                    "exit_code": code,
                    "events": self._events,
                    "frames": len(self._events),
                    "bytes": self.bytes,
                    "fault": self.error,
                },
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )

    def close(self):
        if self._reader is not None:
            os.close(self._reader)
            self._reader = None
        self.writer.close()
        self.eof = True


class PeerChannel:
    """Fresh sends await fresh correlated responses; no response cache or retries."""

    def __init__(self, native_processes_module, argv):
        if (
            type(argv) is not tuple
            or not argv
            or any(type(arg) is not str or not arg or "\0" in arg for arg in argv)
        ):
            raise ChannelFailure("immutable_argv_required")
        self.argv = argv
        self._borrowed_input = native_processes_module.BorrowedInput
        self.capture = JSONLCapture()
        self.process = None
        self._writer = None
        self._start_attempted = False
        self._capture_claimed = False
        self._pending: tuple[str, int] | None = None
        self._next_request_id = 1
        self._seen_lifecycle = set()
        self.failure = None

    def capture_factory(self, argv):
        if tuple(argv) != self.argv:
            return None
        if self._capture_claimed:
            raise ChannelFailure("channel_capture_already_claimed")
        self._capture_claimed = True
        return self.capture

    def _fail(self, kind):
        if self.failure is None:
            self.failure = kind
        self.close_input()
        raise ChannelFailure(self.failure)

    def start(self, processes, name, cwd):
        if self._start_attempted:
            self._fail("channel_start_already_attempted")
        self._start_attempted = True
        reader = None
        try:
            reader, self._writer = os.pipe()
            os.set_blocking(self._writer, False)
            if os.get_inheritable(self._writer):
                self._fail("inheritable_input_writer")

            def remember(process):
                self.process = process

            process = processes.start(
                name,
                self.argv,
                cwd,
                borrowed_input=self._borrowed_input(input_fd=reader),
                on_spawned=remember,
            )
            if not self._capture_claimed:
                self._fail("channel_capture_not_installed")
            return process
        except BaseException:
            self.close_input()
            # Native owns the capture once claimed, including uncertain starts.
            if not self._capture_claimed:
                self.capture.close()
            raise
        finally:
            if reader is not None:
                os.close(reader)

    def _poll(self, pump):
        if self.process is None:
            self._fail("channel_process_unavailable")
        result = self.process.poll()
        if pump is not None:
            pump()
        return result

    def _deadline(self, timeout):
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            self._fail("invalid_channel_timeout")
        return time.monotonic() + timeout

    def write_bytes(self, data, *, timeout=30.0, pump=None):
        """Write a bounded caller frame, without retrying an uncertain send."""
        deadline = self._deadline(timeout)
        if type(data) is not bytes:
            self._fail("channel_bytes_required")
        if self.failure is not None or self._writer is None:
            self._fail("channel_input_closed")
        offset = 0
        try:
            while offset < len(data):
                self._poll(pump)
                if self.capture.error is not None:
                    self._fail("channel_output_fault")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._fail("channel_write_deadline")
                try:
                    written = os.write(self._writer, memoryview(data)[offset:])
                    if written <= 0:
                        self._fail("channel_write_no_progress")
                    offset += written
                except (BlockingIOError, InterruptedError):
                    select.select([], [self._writer], [], min(remaining, 0.025))
        except BaseException:
            self.close_input()
            raise

    def send_json(self, value, *, expected_event, timeout=30.0, pump=None):
        if self._pending is not None:
            self._fail("channel_request_pending")
        if (
            type(expected_event) is not str
            or expected_event not in EVENTS
            or expected_event in UNSOLICITED_EVENTS
        ):
            self._fail("invalid_expected_event")
        if type(value) is not dict or peer.REQUEST_FIELDS & value.keys():
            self._fail("invalid_channel_request_payload")
        if self._next_request_id > 1 + peer.MAX_OPERATIONS:
            self._fail("channel_request_limit")
        request_id = self._next_request_id
        envelope = {"request_id": request_id, "payload": value}
        try:
            data = (
                json.dumps(envelope, allow_nan=False, separators=(",", ":")) + "\n"
            ).encode()
        except (ValueError, TypeError, RecursionError):
            self._fail("invalid_channel_json")
        if len(data) > peer.MAX_LINE:
            self._fail("channel_request_too_large")
        self._pending = (expected_event, request_id)
        # Advance before possibly sending bytes. Failure never reuses an identity.
        self._next_request_id += 1
        self.write_bytes(data, timeout=timeout, pump=pump)

    def expect(self, event, *, timeout=30.0, pump=None):
        deadline = self._deadline(timeout)
        if self.failure is not None:
            self._fail(self.failure)
        if (
            type(event) is not str
            or event not in EVENTS
            or (self._pending is not None and self._pending[0] != event)
        ):
            self._fail("channel_expectation_mismatch")
        if event not in UNSOLICITED_EVENTS and self._pending is None:
            self._fail("channel_response_without_request")
        expected_id = self._pending[1] if self._pending is not None else None
        try:
            while True:
                result = self._poll(pump)
                if self.capture.error is not None:
                    self._fail("channel_output_fault")
                frame = self.capture.peek()
                if frame is not None:
                    received = frame["event"]
                    if received != event or received in self._seen_lifecycle:
                        # Retain unexpected/final frames for later controller proof.
                        self._fail("unexpected_channel_event")
                    if expected_id is None:
                        if "request_id" in frame:
                            self._fail("unexpected_channel_request_id")
                    elif (
                        type(frame.get("request_id")) is not int
                        or frame["request_id"] != expected_id
                    ):
                        self._fail("unexpected_channel_request_id")
                    if received in LIFECYCLE_EVENTS:
                        self._seen_lifecycle.add(received)
                    self._pending = None
                    response = self.capture.pop()
                    if expected_id is not None:
                        del response["request_id"]
                    return response
                if result is not None or self.capture.eof:
                    self._fail("channel_response_eof")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._fail("channel_response_deadline")
                time.sleep(min(remaining, 0.025))
        except BaseException:
            self.close_input()
            raise

    def close_input(self):
        if self._writer is not None:
            descriptor, self._writer = self._writer, None
            os.close(descriptor)

    def join(self, *, timeout=30.0, pump=None):
        """Observe the same Native owner, including after capture/protocol faults."""
        deadline = self._deadline(timeout)
        try:
            while True:
                result = self._poll(pump)
                if result is not None:
                    return result
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._fail("channel_join_deadline")
                time.sleep(min(remaining, 0.025))
        except BaseException:
            self.close_input()
            raise
