"""Bounded, read-only evidence from the fixture's private Gateway audit owner.

A cursor owns immutable file identities, byte positions and prefix commitments.
Only complete records whose first byte follows that cursor can establish a new
registration denial. Missing or rewritten history invalidates the observation.
This reader never authenticates a device or decides a task outcome.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import time
from types import SimpleNamespace

from e2e_local import ProofFailure, require
from e2e_remote_channel import unique_object

SEGMENT_BYTES = 10 << 20
TOTAL_BYTES = 100 << 20
MAX_SEGMENTS = 700
MAX_RECORD_BYTES = 4096
SEGMENT_NAME = re.compile(r"audit-(\d{8})-(\d{2})\.jsonl\Z")
CREDENTIAL_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z")
ROUTING_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
CONTROL_CODES = frozenset(
    {
        "operation_prepared",
        "control_sent",
        "control_completed",
        "control_unknown",
        "authorization_denied",
        "resource_denied",
        "recovery_blocked",
    }
)
CONTROL_CLASSES = frozenset(
    {
        "prepare",
        "context_inspect",
        "admit",
        "resolve",
        "resume_existing",
        "fence_absent",
        "status",
        "collect",
        "result_chunk",
        "cancel",
        "origin_barrier",
        "origin_inventory",
        "origin_reopen",
        "resolve_project",
    }
)
# Go Event.validControlIdentity uses protocol.Operation.RootRouted for this scope.
ROOT_ROUTED_CONTROL_CLASSES = frozenset(
    {
        "context_inspect",
        "origin_barrier",
        "origin_inventory",
        "origin_reopen",
        "resolve_project",
    }
)
CONNECTION_CODES = frozenset(
    {"device_connected", "device_disconnected", "device_connection_failed"}
)
DECISIONS = frozenset({"not_evaluated", "allowed", "denied_or_missing", "unknown"})
RECORD_FIELDS = frozenset(
    {
        "at",
        "code",
        "root_only",
        "device",
        "principal",
        "operation",
        "credential",
        "project",
        "control",
        "connection",
        "connection_duration_ns",
    }
)
CONTROL_FIELDS = frozenset(
    {
        "class",
        "actor",
        "authorization",
        "recheck",
        "transport",
        "control_observation_duration_ns",
        "write_state",
        "request_frame_bytes",
        "response_frame_bytes",
        "response_known",
    }
)


def bounded_integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def routing_token(value):
    return type(value) is str and ROUTING_TOKEN.fullmatch(value) is not None


def connection_generation(value):
    require(
        type(value) is dict
        and set(value) == {"BootEpoch", "Counter"}
        and routing_token(value["BootEpoch"])
        and bounded_integer(value["Counter"], (1 << 64) - 1)
        and value["Counter"] > 0,
        "invalid audit connection",
    )


def control_metadata(value):
    require(
        type(value) is dict
        and CONTROL_FIELDS <= set(value)
        and set(value) <= CONTROL_FIELDS | {"connection", "request_id"}
        and value["class"] in CONTROL_CLASSES
        and value["actor"] in {"principal", "local_admin"}
        and value["authorization"] in DECISIONS
        and value["recheck"] in DECISIONS
        and bounded_integer(value["control_observation_duration_ns"], (1 << 63) - 1)
        and bounded_integer(value["request_frame_bytes"], 1 << 20)
        and bounded_integer(value["response_frame_bytes"], 1 << 20)
        and type(value["response_known"]) is bool
        and value["response_known"] == (value["response_frame_bytes"] > 0),
        "invalid audit control",
    )
    if "connection" in value:
        connection_generation(value["connection"])
    if "request_id" in value:
        require(routing_token(value["request_id"]), "invalid audit request identity")
    write = value["write_state"]
    require(
        write in {"not_started", "attempted_unknown", "write_completed"}
        and (write == "not_started" or value["request_frame_bytes"] > 0),
        "invalid audit write state",
    )
    transport = value["transport"]
    require(
        (
            transport in {"not_attempted", "not_sent"}
            and write == "not_started"
            and not value["response_known"]
        )
        or (transport == "write_unknown" and write == "attempted_unknown")
        or (
            transport == "written_no_reply"
            and write == "write_completed"
            and not value["response_known"]
        )
        or (
            transport in {"reply_received", "reply_invalid"}
            and write == "write_completed"
            and value["response_known"]
        ),
        "invalid audit transport observation",
    )
    if value["class"] == "prepare":
        require(
            value["recheck"] == "not_evaluated"
            and transport == "not_attempted"
            and value["request_frame_bytes"] == 0
            and value["response_frame_bytes"] == 0
            and "connection" not in value
            and "request_id" not in value,
            "preparation claims audit transport",
        )


def control_record(value):
    require(
        value["code"] in CONTROL_CODES
        and "control" in value
        and set(value)
        <= {
            "at",
            "code",
            "root_only",
            "principal",
            "device",
            "project",
            "operation",
            "control",
        },
        "invalid audit control record",
    )
    metadata = value["control"]
    control_metadata(metadata)
    if value.get("root_only", False):
        identity_valid = (
            "device" in value
            and "project" not in value
            and metadata["class"] in ROOT_ROUTED_CONTROL_CLASSES
        )
    else:
        identity_valid = ("device" in value) == ("project" in value)
    require(
        (metadata["actor"] == "principal") == ("principal" in value)
        and identity_valid
        and ("operation" not in value or "device" in value),
        "invalid audit control identity",
    )
    if value["code"] == "operation_prepared":
        require(
            {"principal", "device", "project", "operation"} <= set(value)
            and metadata["class"] == "prepare"
            and metadata["authorization"] == "allowed",
            "invalid prepared audit identity",
        )
    elif value["code"] in {"control_sent", "control_completed"}:
        require(metadata["class"] != "prepare", "invalid completed audit class")


def connection_record(value):
    require(
        set(value)
        <= {
            "at",
            "code",
            "device",
            "credential",
            "connection",
            "connection_duration_ns",
        }
        and bounded_integer(value.get("connection_duration_ns", 0), (1 << 63) - 1),
        "invalid connection audit record",
    )
    if "credential" not in value:
        require(
            value["code"] == "device_connection_failed"
            and "device" not in value
            and "connection" not in value,
            "unverified audit connection identity",
        )
        return
    credential_identity(value["credential"], value.get("device"))
    if "connection" in value:
        connection_generation(value["connection"])
    else:
        require(
            value["code"] == "device_connection_failed",
            "missing audit connection generation",
        )


def record_metadata(value):
    root_only = value.get("root_only", False)
    require(
        type(root_only) is bool and (not root_only or value["code"] in CONTROL_CODES),
        "invalid audit root scope",
    )
    if value["code"] == "device_credential_denied":
        require(
            set(value) == {"at", "code", "device", "credential"},
            "invalid denial record",
        )
        credential_identity(value["credential"], value["device"])
        return
    metadata = {"project", "control", "connection", "connection_duration_ns"}
    if not metadata.intersection(value) and "credential" not in value and not root_only:
        # Retained pre-metadata generic rows are historical observations only.
        return
    for key in ("device", "principal", "operation", "project"):
        if key in value:
            require(routing_token(value[key]), "invalid audit routing identity")
    if value["code"] in CONNECTION_CODES:
        connection_record(value)
    else:
        control_record(value)


def credential_identity(value, device):
    require(
        type(value) is dict
        and set(value) == {"device_id", "epoch", "generation"}
        and all(
            type(value.get(key)) is str and CREDENTIAL_TOKEN.fullmatch(value[key])
            for key in ("device_id", "epoch")
        )
        and value["device_id"] == device
        and type(value["generation"]) is int
        and 0 < value["generation"] < 1 << 64,
        "invalid audit credential identity",
    )
    # Immutable tuple, independent of the mutable decoded admin response.
    return value["device_id"], value["epoch"], value["generation"]


def require_healthy(value):
    require(
        type(value) is dict
        and set(value) == {"audit_healthy", "audit_failures", "metric_failures"}
        and value["audit_healthy"] is True
        and type(value["audit_failures"]) is int
        and value["audit_failures"] == 0
        and type(value["metric_failures"]) is int
        and value["metric_failures"] == 0,
        "metadata recorder health failed",
    )


def read_health(socket_path):
    """Fixed protected GET; the caller owns the private admin socket directory."""
    try:
        info = Path(socket_path).lstat()
        require(
            stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(),
            "invalid metadata health socket",
        )
        # Read a finite raw response before parsing. The absolute deadline also
        # bounds slow/dripping headers; socket inactivity alone would not.
        deadline = time.monotonic() + 3
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(socket_path))
            connection.sendall(
                b"GET /v1/metadata/health HTTP/1.1\r\n"
                b"Host: unix\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
            )
            raw = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "metadata health deadline expired")
                connection.settimeout(remaining)
                chunk = connection.recv(2 * MAX_RECORD_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
                require(
                    len(raw) <= 2 * MAX_RECORD_BYTES,
                    "metadata health response too large",
                )
        buffered = SimpleNamespace(makefile=lambda _mode: io.BytesIO(raw))
        with http.client.HTTPResponse(buffered) as response:
            response.begin()
            require(
                response.status == 200
                and response.getheader("Content-Type") == "application/json"
                and response.getheader("Cache-Control") == "no-store"
                and response.getheader("Content-Encoding") is None,
                "metadata health response rejected",
            )
            data = response.read(MAX_RECORD_BYTES + 1)
            require(len(data) <= MAX_RECORD_BYTES, "metadata health response too large")
        value = json.loads(data, object_pairs_hook=unique_object)
        require_healthy(value)
        return value
    except (OSError, ValueError, RecursionError, http.client.HTTPException) as error:
        raise ProofFailure("metadata health unavailable") from error


@dataclass(frozen=True)
class SegmentPosition:
    name: str
    device: int
    inode: int
    size: int
    sha256: str


def records(data):
    """Ignore an incomplete final write; never count its pre-cursor beginning."""
    offset = 0
    while offset < len(data):
        end = data.find(b"\n", offset)
        length = len(data) - offset if end < 0 else end + 1 - offset
        require(length <= MAX_RECORD_BYTES, "audit record exceeds bound")
        if end < 0:
            break
        line = data[offset : end + 1]
        try:
            value = json.loads(line, object_pairs_hook=unique_object)
            require(
                type(value) is dict
                and {"at", "code"} <= set(value)
                and set(value) <= RECORD_FIELDS
                and type(value["at"]) is str
                and TIMESTAMP.fullmatch(value["at"])
                and type(value["code"]) is str
                and re.fullmatch(r"[a-z_]{1,64}", value["code"]),
                "invalid audit record",
            )
            datetime.fromisoformat(value["at"].replace("Z", "+00:00"))
            record_metadata(value)
            for key in ("device", "principal", "operation"):
                if key in value:
                    require(
                        type(value[key]) is str
                        and 0 < len(value[key]) <= 128
                        and all(32 < ord(char) < 127 for char in value[key]),
                        "invalid audit handle",
                    )
        except (ValueError, TypeError, RecursionError) as error:
            raise ProofFailure("invalid complete audit record") from error
        yield offset, value
        offset += len(line)


def read_segments(directory):
    """Read finite snapshots through checked directory/file descriptors."""
    require(directory.is_absolute(), "absolute audit directory required")
    before = directory.lstat()
    require(
        stat.S_ISDIR(before.st_mode)
        and before.st_mode & 0o077 == 0
        and before.st_uid == os.getuid(),
        "invalid audit directory",
    )
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(directory_fd)
        require(
            os.path.samestat(before, opened)
            and opened.st_mode & 0o077 == 0
            and opened.st_uid == os.getuid(),
            "audit directory changed",
        )
        names = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                require(
                    len(names) < MAX_SEGMENTS + 1, "audit segment count exceeds bound"
                )
                names.append(entry.name)
        segments = []
        total = 0
        day_indexes = {}
        for name in sorted(names):
            if name == ".audit.lock":
                continue
            match = SEGMENT_NAME.fullmatch(name)
            require(match is not None, "invalid audit segment name")
            try:
                datetime.strptime(match[1], "%Y%m%d")
            except ValueError as error:
                raise ProofFailure("invalid audit segment date") from error
            index = int(match[2])
            require(index == day_indexes.get(match[1], 0), "audit rotation gap")
            day_indexes[match[1]] = index + 1
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_mode & 0o077 == 0
                and info.st_uid == os.getuid()
                and info.st_size <= SEGMENT_BYTES,
                "invalid audit segment",
            )
            total += info.st_size
            require(total <= TOTAL_BYTES, "audit total exceeds bound")
            fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
            )
            with os.fdopen(fd, "rb") as stream:
                actual = os.fstat(stream.fileno())
                require(
                    os.path.samestat(info, actual)
                    and stat.S_ISREG(actual.st_mode)
                    and actual.st_mode & 0o077 == 0
                    and actual.st_uid == os.getuid(),
                    "audit segment changed",
                )
                data = stream.read(info.st_size)
                after = os.fstat(stream.fileno())
                require(
                    len(data) == info.st_size
                    and after.st_size >= info.st_size
                    and after.st_size <= SEGMENT_BYTES
                    and after.st_mode & 0o077 == 0
                    and after.st_uid == os.getuid(),
                    "audit segment changed while reading",
                )
            segments.append((info, name, data))
        return opened, segments
    finally:
        os.close(directory_fd)


@dataclass(frozen=True)
class AuditCursor:
    directory: Path
    device: int
    inode: int
    positions: tuple[SegmentPosition, ...]

    @classmethod
    def capture(cls, directory):
        try:
            info, segments = read_segments(Path(directory))
            positions = []
            for file_info, name, data in segments:
                # Validate complete baseline records without accepting them.
                for _ in records(data):
                    pass
                positions.append(
                    SegmentPosition(
                        name,
                        file_info.st_dev,
                        file_info.st_ino,
                        len(data),
                        hashlib.sha256(data).hexdigest(),
                    )
                )
            return cls(Path(directory), info.st_dev, info.st_ino, tuple(positions))
        except OSError as error:
            raise ProofFailure("audit cursor unavailable") from error

    def receipt(self):
        return {
            "device": self.device,
            "inode": self.inode,
            "positions": [asdict(position) for position in self.positions],
        }

    def find_denial(self, credential):
        try:
            directory_info, segments = read_segments(self.directory)
            require(
                (directory_info.st_dev, directory_info.st_ino)
                == (self.device, self.inode),
                "audit directory replaced",
            )
            baseline = {position.name: position for position in self.positions}
            require(
                set(baseline) <= {name for _, name, _ in segments},
                "audit history disappeared",
            )
            found = None
            for info, name, data in segments:
                previous = baseline.get(name)
                offset = 0
                if previous is not None:
                    require(
                        (info.st_dev, info.st_ino) == (previous.device, previous.inode)
                        and len(data) >= previous.size
                        and hashlib.sha256(data[: previous.size]).hexdigest()
                        == previous.sha256,
                        "audit history changed",
                    )
                    offset = previous.size
                for start, record in records(data):
                    if start >= offset and record["code"] == "device_credential_denied":
                        observed = credential_identity(
                            record["credential"], record["device"]
                        )
                        if observed == credential and found is None:
                            encoded = data[start : data.find(b"\n", start) + 1]
                            found = {
                                "segment": name,
                                "offset": start,
                                "length": len(encoded),
                                "sha256": hashlib.sha256(encoded).hexdigest(),
                            }
            return found
        except OSError as error:
            raise ProofFailure("audit observation unavailable") from error
