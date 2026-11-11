#!/usr/bin/env python3
"""Private, single-use stdin staging before the remote fixture peer.

Wire: 4-byte big-endian JSON length, strict UTF-8 JSON manifest, then each
file's exact bytes in manifest order. No buffered input: the controller waits
for bootstrap_ready before sending the peer's manifest. Limits allow three
128 MiB candidate Go binaries plus small source files within 384 MiB total;
these are transfer ceilings, never permission to copy installed tools.

The bootstrap owns only its exclusively created gs-<run_id> directory. Failure
retains that directory and reports its known locator; it never adopts, cleans,
launches children, or claims peer/resource closure. The trusted controller owns
candidate provenance. SHA256 proves transfer integrity, not executable trust.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import stat
import struct
import sys
import time

MINIMUM_PYTHON = (3, 12, 0)
MAX_HEADER = 1 << 20
MAX_FILES = 4096
MAX_FILE_BYTES = 128 << 20
MAX_TOTAL_BYTES = 384 << 20
INPUT_TIMEOUT = 120.0
OUTPUT_TIMEOUT = 2.0
CHUNK_BYTES = 64 << 10
MAX_EVENT = 16 << 10
CANDIDATES = frozenset({"bin/gateway", "bin/delegate", "bin/delegate-run"})
GATEWAY_SOURCES = frozenset(
    "gateway/scripts/" + name + ".py"
    for name in ("e2e_remote_peer", "e2e_local", "e2e_contracts", "e2e_native_capture")
)
NATIVE_DATA_SOURCES = frozenset({"native/scripts/_data/unicode-simple-fold.json"})
PEER = "gateway/scripts/e2e_remote_peer.py"
# The code is constant; paths are argv data, never interpolated Python/shell code.
LAUNCHER = (
    "import runpy,sys; "
    "sys.path.insert(0,sys.argv[1]); "
    "runpy.run_path(sys.argv[2],run_name='__main__')"
)


class BootstrapFailure(Exception):
    """A bounded, public failure kind without raw paths or exception messages."""


@dataclass(frozen=True)
class FileSpec:
    path: str
    size: int
    sha256: str
    executable: bool


@dataclass(frozen=True)
class StagedFile:
    spec: FileSpec
    device: int
    inode: int


@dataclass(frozen=True)
class Manifest:
    run_id: str
    expected_home: str
    expected_uid: int
    files: tuple[FileSpec, ...]


def require(condition, kind):
    if not condition:
        raise BootstrapFailure(kind)


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), "invalid_fields")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def allowed_path(path):
    if type(path) is not str or len(path) > 1024:
        return False
    if path in CANDIDATES or path in GATEWAY_SOURCES or path in NATIVE_DATA_SOURCES:
        return True
    if path == "native/scripts/__init__.py":
        return True
    parts = path.split("/")
    return (
        parts[:3] == ["native", "scripts", "acceptance"]
        and len(parts) >= 4
        and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p) for p in parts[3:-1])
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.py", parts[-1]) is not None
    )


def validate_manifest(value, home, uid):
    """Validate all metadata before any filesystem mutation."""
    exact(value, {"schema_version", "run_id", "expected_home", "expected_uid", "files"})
    require(
        type(value["schema_version"]) is int and value["schema_version"] == 1,
        "invalid_schema",
    )
    run_id = value["run_id"]
    require(
        type(run_id) is str and re.fullmatch(r"[0-9a-f]{16}", run_id), "invalid_run_id"
    )
    require(
        type(value["expected_home"]) is str and value["expected_home"] == str(home),
        "home_mismatch",
    )
    require(
        type(value["expected_uid"]) is int and value["expected_uid"] == uid,
        "uid_mismatch",
    )
    files = value["files"]
    require(type(files) is list and 1 <= len(files) <= MAX_FILES, "invalid_file_count")
    parsed = []
    seen = set()
    total = 0
    for item in files:
        exact(item, {"path", "size", "sha256", "executable"})
        path = item["path"]
        require(allowed_path(path), "invalid_path")
        require(path not in seen, "duplicate_path")
        seen.add(path)
        require(
            type(item["executable"]) is bool
            and item["executable"] == (path in CANDIDATES),
            "invalid_executable",
        )
        require(
            type(item["size"]) is int and 0 <= item["size"] <= MAX_FILE_BYTES,
            "invalid_file_size",
        )
        total += item["size"]
        require(total <= MAX_TOTAL_BYTES, "total_size_exceeded")
        digest = item["sha256"]
        require(
            type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest),
            "invalid_sha256",
        )
        parsed.append(FileSpec(path, item["size"], digest, item["executable"]))
    require(PEER in seen, "missing_peer")
    return Manifest(run_id, str(home), uid, tuple(parsed))


def read_chunk(fd, count, deadline, clock=time.monotonic):
    remaining = deadline - clock()
    require(remaining > 0, "input_deadline")
    ready, _, _ = select.select([fd], [], [], remaining)
    require(bool(ready), "input_deadline")
    chunk = os.read(fd, min(count, CHUNK_BYTES))
    require(bool(chunk), "truncated_frame")
    return chunk


def read_exact(fd, count, deadline, clock=time.monotonic):
    result = bytearray()
    while len(result) < count:
        result.extend(read_chunk(fd, count - len(result), deadline, clock))
    return bytes(result)


def read_manifest(fd, home, uid, deadline, clock=time.monotonic):
    length = struct.unpack("!I", read_exact(fd, 4, deadline, clock))[0]
    require(0 < length <= MAX_HEADER, "invalid_header_size")
    try:
        value = json.loads(
            read_exact(fd, length, deadline, clock).decode("utf-8"),
            object_pairs_hook=unique_object,
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise BootstrapFailure("invalid_json") from error
    return validate_manifest(value, home, uid)


def actual_account():
    uid = os.getuid()
    require(uid == os.geteuid(), "account_mismatch")
    recorded = pwd.getpwuid(uid).pw_dir
    home = Path(recorded).resolve(strict=True)
    require(home.is_absolute() and str(home) == recorded, "noncanonical_home")
    require(home.stat().st_uid == uid and home.is_dir(), "invalid_home")
    return home, uid


def open_directory(path, *, dir_fd=None):
    return os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd
    )


def write_all(fd, data):
    remaining = memoryview(data)
    while remaining:
        written = os.write(fd, remaining)
        require(written > 0, "write_failed")
        remaining = remaining[written:]


def expected_directory_entries(specs):
    """Manifest paths are the authority for the exact staged directory contents."""
    entries = {}
    for spec in specs:
        parts = spec.path.split("/")
        for index, name in enumerate(parts):
            entries.setdefault(tuple(parts[:index]), set()).add(name)
    return {parts: frozenset(names) for parts, names in entries.items()}


def stage_files(
    manifest, stage_fd, input_fd, deadline, clock=time.monotonic, *, directory_stack
):
    # All traversal stays under held directory descriptors. No path resolution
    # after creation, link following, adoption, overwrites, or generic extraction.
    directories = {(): stage_fd}
    files = []
    for spec in manifest.files:
        parts = spec.path.split("/")
        key = ()
        parent = stage_fd
        for part in parts[:-1]:
            child = (*key, part)
            if child not in directories:
                os.mkdir(part, mode=0o700, dir_fd=parent)
                descriptor = open_directory(part, dir_fd=parent)
                directory_stack.callback(os.close, descriptor)
                os.fchmod(descriptor, 0o700)
                directories[child] = descriptor
            parent = directories[child]
            key = child
        fd = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode), "nonregular_file")
            digest = hashlib.sha256()
            remaining = spec.size
            while remaining:
                chunk = read_chunk(input_fd, remaining, deadline, clock)
                digest.update(chunk)
                write_all(fd, chunk)
                remaining -= len(chunk)
            require(digest.hexdigest() == spec.sha256, "hash_mismatch")
            os.fchmod(fd, 0o700 if spec.executable else 0o600)
            os.fsync(fd)
            info = os.fstat(fd)
            require(info.st_nlink == 1, "staging_binding_changed")
            files.append(StagedFile(spec, info.st_dev, info.st_ino))
        finally:
            os.close(fd)
    for fd in reversed(tuple(directories.values())):
        os.fsync(fd)
    return directories, tuple(files), expected_directory_entries(manifest.files)


def validate_bindings(
    home,
    home_fd,
    stage,
    directories,
    files,
    expected,
    uid,
    deadline,
    clock=time.monotonic,
):
    """Checked at handoff, not atomically protected against later loads/mutations."""
    try:
        require(clock() < deadline, "handoff_deadline")
        for retained in files:
            require(clock() < deadline, "handoff_deadline")
            parts = retained.spec.path.split("/")
            fd = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=directories[tuple(parts[:-1])],
            )
            try:
                info = os.fstat(fd)
                require(
                    stat.S_ISREG(info.st_mode)
                    and (info.st_dev, info.st_ino) == (retained.device, retained.inode)
                    and info.st_uid == uid
                    and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode)
                    == (0o700 if retained.spec.executable else 0o600)
                    and info.st_size == retained.spec.size,
                    "staging_binding_changed",
                )
                digest = hashlib.sha256()
                remaining = retained.spec.size
                while remaining:
                    require(clock() < deadline, "handoff_deadline")
                    chunk = os.read(fd, min(remaining, CHUNK_BYTES))
                    require(bool(chunk), "staging_binding_changed")
                    digest.update(chunk)
                    remaining -= len(chunk)
                final = os.fstat(fd)
                require(
                    digest.hexdigest() == retained.spec.sha256
                    and final.st_size == info.st_size
                    and final.st_mtime_ns == info.st_mtime_ns
                    and final.st_ctime_ns == info.st_ctime_ns,
                    "staging_binding_changed",
                )
                require(clock() < deadline, "handoff_deadline")
            finally:
                os.close(fd)
        require(home.resolve(strict=True) == home, "staging_binding_changed")
        visible_home = home.stat(follow_symlinks=False)
        held_home = os.fstat(home_fd)
        require(
            stat.S_ISDIR(visible_home.st_mode)
            and visible_home.st_uid == held_home.st_uid == uid
            and (visible_home.st_dev, visible_home.st_ino)
            == (held_home.st_dev, held_home.st_ino),
            "staging_binding_changed",
        )
        require(set(directories) == set(expected), "staging_binding_changed")
        for parts, fd in directories.items():
            require(clock() < deadline, "handoff_deadline")
            parent = directories[parts[:-1]] if parts else home_fd
            name = parts[-1] if parts else stage.name
            visible = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            require(
                stat.S_ISDIR(visible.st_mode)
                and visible.st_uid == held.st_uid == uid
                and stat.S_IMODE(visible.st_mode) == 0o700
                and (visible.st_dev, visible.st_ino) == (held.st_dev, held.st_ino),
                "staging_binding_changed",
            )
            seen = set()
            with os.scandir(fd) as entries:
                for entry in entries:
                    require(clock() < deadline, "handoff_deadline")
                    require(
                        entry.name in expected[parts] and entry.name not in seen,
                        "staging_binding_changed",
                    )
                    seen.add(entry.name)
            require(seen == expected[parts], "staging_binding_changed")
        require(clock() < deadline, "handoff_deadline")
    except (OSError, RuntimeError, ValueError) as error:
        raise BootstrapFailure("staging_binding_changed") from error


def emit(fd, event, *, clock=time.monotonic):
    """Publish within a separate finite budget; fd blocking mode stays borrowed."""
    data = (json.dumps(event, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    require(len(data) <= MAX_EVENT, "event_too_large")
    try:
        blocking = os.get_blocking(fd)
    except OSError as error:
        raise BootstrapFailure("publication_io_failed") from error
    deadline = clock() + OUTPUT_TIMEOUT
    offset = 0
    failure = None
    try:
        os.set_blocking(fd, False)
        while offset < len(data):
            remaining = deadline - clock()
            require(remaining > 0, "publication_deadline")
            try:
                written = os.write(fd, data[offset:])
                require(written > 0, "publication_no_progress")
                offset += written
            except (BlockingIOError, InterruptedError):
                select.select([], [fd], [], remaining)
    except BootstrapFailure as error:
        failure = error
    except OSError as error:
        failure = BootstrapFailure("publication_io_failed")
        failure.__cause__ = error
    finally:
        try:
            os.set_blocking(fd, blocking)
        except OSError as error:
            # Keep the original publication failure if restoration also fails.
            if failure is None:
                failure = BootstrapFailure("publication_restore_failed")
                failure.__cause__ = error
    if failure is not None:
        raise failure


def handoff(manifest, stage, *, execve=os.execve):
    scripts = stage / "gateway/scripts"
    environment = {
        "HOME": manifest.expected_home,
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONIOENCODING": "utf-8",
    }
    execve(
        sys.executable,
        [sys.executable, "-I", "-c", LAUNCHER, str(scripts), str(stage / PEER)],
        environment,
    )
    raise BootstrapFailure("exec_returned")


def bootstrap(
    input_fd=0, output_fd=1, *, execve=os.execve, clock=time.monotonic, deadline=None
):
    observation = {
        "python_executable": sys.executable,
        "python_version": list(sys.version_info[:3]),
    }
    locator = {}
    if deadline is None:
        deadline = clock() + INPUT_TIMEOUT
    try:
        require(tuple(sys.version_info[:3]) >= MINIMUM_PYTHON, "unsupported_python")
        home, uid = actual_account()
        manifest = read_manifest(input_fd, home, uid, deadline, clock)
        stage = home / ("gs-" + manifest.run_id)
        locator = {
            "run_id": manifest.run_id,
            "stage": str(stage),
            "home": str(home),
            "uid": uid,
        }
        with ExitStack() as stack:
            home_fd = open_directory(home)
            stack.callback(os.close, home_fd)
            require(os.fstat(home_fd).st_uid == uid, "invalid_home")
            os.mkdir(stage.name, mode=0o700, dir_fd=home_fd)
            stage_fd = open_directory(stage.name, dir_fd=home_fd)
            stack.callback(os.close, stage_fd)
            os.fchmod(stage_fd, 0o700)
            directories, files, expected = stage_files(
                manifest, stage_fd, input_fd, deadline, clock, directory_stack=stack
            )
            os.fsync(home_fd)
            validate_bindings(
                home, home_fd, stage, directories, files, expected, uid, deadline, clock
            )
            emit(
                output_fd,
                {
                    "event": "bootstrap_ready",
                    "schema_version": 1,
                    **observation,
                    **locator,
                },
            )
            validate_bindings(
                home, home_fd, stage, directories, files, expected, uid, deadline, clock
            )
            handoff(manifest, stage, execve=execve)
    except (BootstrapFailure, OSError, ValueError, KeyError, OverflowError) as error:
        kind = (
            str(error) if isinstance(error, BootstrapFailure) else "bootstrap_io_failed"
        )
        try:
            emit(
                output_fd,
                {
                    "event": "bootstrap_failed",
                    "schema_version": 1,
                    "kind": kind,
                    **observation,
                    **locator,
                },
            )
        except (OSError, BootstrapFailure):
            # No second output channel or raw exception leaks on a broken pipe.
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(bootstrap())
