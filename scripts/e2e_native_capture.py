#!/usr/bin/env python3
"""Private test-only Delegate capture. Observations never establish task closure."""

import argparse
import importlib
import importlib.machinery
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time

MAX_STDOUT = 256 << 10
MAX_STDERR = 16 << 10
COMMANDS = {
    "dispatch",
    "context",
    "resolve",
    "status",
    "collect",
    "cancel",
    "resume",
    "fence-absent",
    "origin",
    "result",
    "capabilities",
}
FAILURE_CODES = {
    "admission_deadline_expired",
    "check_status",
    "continuation_unavailable",
    "correct_request",
    "delegate_installation_incomplete",
    "dispatch_failed",
    "inspection_evidence_invalid",
    "inspection_failed",
    "inspection_journal_contended",
    "inspection_worker_failed",
    "invalid_request",
    "observation_canceled",
    "observation_deadline_exceeded",
    "provider_preflight_failed",
    "provider_preparation_failed",
    "provider_unavailable",
    "resource_pressure",
    "retry_later",
    "run_supervisor_migrate",
    "state_root_unavailable",
    "stop_and_report",
    "supervisor_migration_blocked",
    "supervisor_migration_unsupported",
    "supervisor_observation_failed",
    "supervisor_owner_incompatible",
    "supervisor_setup_failed",
    "supervisor_upgrade_required",
    "task_identity_mismatch",
    "task_launch_uncertain",
    "task_operation_failed",
    "task_request_conflict",
    "task_submission_preparation_failed",
    "task_submission_uncertain",
    "unsupported_continuation",
    "unsupported_option",
    "wait_for_legacy_work",
    "workspace_busy",
    "workspace_identity_changed",
    "workspace_preparation_failed",
    "workspace_released",
}
STAGES = {
    "check-continuation-capability",
    "finalize-provider",
    "inspect-provider",
    "load-continuation-session",
    "load-predecessor",
    "prepare-provider",
    "prepare-supervisor-executables",
    "prepare-supervisor-options",
    "prepare-task-submission",
    "prepare-workspace",
    "record-runtime-capability",
    "resolve-continuation-provider",
    "resolve-continuation-supervisor",
    "resolve-predecessor",
    "resolve-runner",
    "resolve-state-root",
    "select-provider",
    "start-supervisor",
    "validate-continuation",
    "validate-profile",
    "validate-request",
}
ACTIONS = {
    "check_status",
    "correct_request",
    "retry_later",
    "run_supervisor_migrate",
    "stop_and_report",
    "wait_for_legacy_work",
}

RESOURCE_ENUMS = {
    "status": {"clear", "pressure", "unknown"},
    "counter_unit": {"ticks", "seconds"},
    "classification": {"clear", "hot", "unavailable"},
    "unavailable_reason": {
        "target_unavailable",
        "target_changed",
        "scope_unresolved",
        "cgroup_unsupported",
        "pressure_unavailable",
        "unreadable",
        "malformed",
        "counter_reset",
        "no_elapsed_time",
        "deadline",
        "unsupported_platform",
    },
    "metric": {"host_cpu", "host_memory", "cgroup_cpu", "cgroup_memory"},
    "code": {"resource_observation_unavailable", "resource_advisory"},
    "reason_code": {"deadline", "unavailable", "sustained", "threshold", "pressure"},
}
RESOURCE_NUMBERS = {
    "elapsed_ms",
    "busy_fraction",
    "busy_threshold",
    "required_streak",
    "busy_delta",
    "total_delta",
    "busy_percent",
    "used_percent",
    "available_bytes",
    "total_bytes",
    "limit_bytes",
    "usage_bytes",
    "threshold_percent",
    "sample_count",
    "interval_milliseconds",
    "duration_milliseconds",
    "retry_after_seconds",
}
RESOURCE_OBJECTS = {
    "diagnostics",
    "host_cpu",
    "host_memory",
    "cgroup_cpu",
    "cgroup_memory",
}
RESOURCE_LISTS = {"warnings", "intervals"}


def resource_metadata(value, depth=0):
    if not isinstance(value, dict) or depth > 4:
        return {}
    output = {}
    for key, item in value.items():
        if (
            key in RESOURCE_ENUMS
            and isinstance(item, str)
            and item in RESOURCE_ENUMS[key]
        ):
            output[key] = item
        elif key in RESOURCE_NUMBERS and type(item) in (int, float):
            if 0 <= item <= 10**18 and math.isfinite(item):
                output[key] = item
        elif key in RESOURCE_OBJECTS:
            nested = resource_metadata(item, depth + 1)
            if nested:
                output[key] = nested
        elif key in RESOURCE_LISTS and isinstance(item, list) and len(item) <= 64:
            output[key] = [resource_metadata(entry, depth + 1) for entry in item]
    return output


def closed_metadata(data):
    try:
        response = json.loads(data)
    except (ValueError, UnicodeError):
        return {}
    if (
        not isinstance(response, dict)
        or type(response.get("schema_version")) is not int
    ):
        return {}
    if (
        response["schema_version"] != 1
        or not isinstance(response.get("command"), str)
        or response["command"] not in COMMANDS
    ):
        return {}
    output = {"schema_version": 1, "command": response["command"]}
    if response.get("task_record") in ("created", "not_created", "unknown"):
        output["task_record"] = response["task_record"]
    failure = response.get("failure")
    if isinstance(failure, dict):
        safe = {}
        for key, allowed in (
            ("code", FAILURE_CODES),
            ("stage", STAGES),
            ("next_action", ACTIONS),
        ):
            if isinstance(failure.get(key), str) and failure[key] in allowed:
                safe[key] = failure[key]
        if safe:
            output["failure"] = safe
    resource = resource_metadata(response.get("resource_admission"))
    if resource:
        output["resource_admission"] = resource
    return output


def private_directory(path):
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISDIR(info.st_mode):
        raise ValueError("private directory required")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private directory required")


def validate_acceptance_origin(repository):
    """Bind shared owner classes to one checkout without replacing live modules.

    Gateway and Native both use a top-level scripts namespace. Other namespace
    portions are harmless only when they cannot supply scripts.acceptance.
    """
    if not repository.is_absolute():
        raise ValueError("absolute repository required")
    repository = repository.resolve(strict=True)
    boundary = repository / "scripts/acceptance"
    initializer = boundary / "__init__.py"
    if not initializer.is_file() or not initializer.resolve().is_relative_to(boundary):
        raise ValueError("maintained acceptance package unavailable")
    for name, module in tuple(sys.modules.items()):
        if name != "scripts.acceptance" and not name.startswith("scripts.acceptance."):
            continue
        source = getattr(module, "__file__", None)
        if not source or not Path(source).resolve(strict=True).is_relative_to(boundary):
            raise ValueError("foreign cached acceptance module")
        for portion in getattr(module, "__path__", ()):
            if not Path(portion).resolve(strict=True).is_relative_to(boundary):
                raise ValueError("foreign acceptance search path")
    spec = importlib.util.find_spec("scripts")
    if spec is None or spec.submodule_search_locations is None:
        raise ValueError("maintained scripts namespace unavailable")
    if spec.origin is not None and not Path(spec.origin).resolve(
        strict=True
    ).is_relative_to(repository / "scripts"):
        raise ValueError("foreign scripts package shadows acceptance")
    paths = list(spec.submodule_search_locations)
    cached = sys.modules.get("scripts")
    if cached is not None:
        source = getattr(cached, "__file__", None)
        if source is not None and not Path(source).resolve(strict=True).is_relative_to(
            repository / "scripts"
        ):
            raise ValueError("foreign cached scripts package shadows acceptance")
        actual_paths = getattr(cached, "__path__", None)
        if actual_paths is None:
            raise ValueError("cached scripts package has no search path")
        # Imports use the live parent's __path__, which need not match its spec.
        paths.extend(actual_paths)
    for portion in paths:
        path = Path(portion).resolve(strict=True)
        if path == repository / "scripts":
            continue
        candidate = path / "acceptance"
        # Only probe the filesystem provider. An unqualified name also handles
        # namespace packages before the top-level scripts module is imported.
        provider = importlib.machinery.PathFinder.find_spec("acceptance", [str(path)])
        if provider is not None or candidate.is_symlink():
            raise ValueError("foreign scripts namespace supplies acceptance")


def prepare_acceptance_imports(repository):
    """Keep one explicit source entry and validate before importing owners."""
    source = str(repository)
    if source not in sys.path:
        sys.path.insert(0, source)
    validate_acceptance_origin(repository)


def load_owners(repository):
    if not repository.is_absolute():
        raise ValueError("absolute repository required")
    expected = repository / "scripts/acceptance/processes/operations.py"
    if not expected.is_file():
        raise ValueError("maintained process owner unavailable")
    prepare_acceptance_imports(repository)
    directories = importlib.import_module("scripts.acceptance.directories.operations")
    processes = importlib.import_module("scripts.acceptance.processes.operations")
    validate_acceptance_origin(repository)
    return directories.DirectoryOwner, processes.Processes


def write_metadata(path, value):
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, allow_nan=False)
        output.write("\n")


def forward(path, output):
    with path.open("rb") as source:
        while chunk := source.read(64 << 10):
            output.write(chunk)
    output.flush()


def capture(args, stdout, stderr):
    private_directory(args.capture_root)
    if not args.delegate.is_absolute() or not args.delegate.is_file():
        raise ValueError("absolute selected executable required")
    directory = Path(tempfile.mkdtemp(prefix="native-", dir=args.capture_root))
    DirectoryOwner, Processes = load_owners(args.repository)
    owner = DirectoryOwner()
    owner.adopt_created("private native diagnostic", directory, args.capture_root)
    processes = Processes(
        directory / "processes",
        environment=dict(os.environ),
        owner=owner,
        environment_keys_only=True,
    )
    interrupted = [False]

    def interrupted_signal(number, _frame):
        interrupted[0] = True

    previous = {
        number: signal.signal(number, interrupted_signal)
        for number in (signal.SIGINT, signal.SIGTERM)
    }
    process = None
    report = {"diagnostic_only": True, "cleanup_confirmed": False}
    try:
        process = processes.start(
            "delegate", [args.delegate, *args.arguments], Path.cwd()
        )
        result = process.poll()
        while result is None:
            time.sleep(0.025)
            result = process.poll()
        report["child_exit_code"] = result["exit_code"]
        report["direct_wait_confirmed"] = True
        report["interrupted"] = interrupted[0]
        report["cleanup_confirmed"] = processes.finished_naturally()
        report["capture_failed"] = bool(
            result.get("capture_error") or result.get("stdin_error")
        )
        bounded = (
            result["stdout_bytes"] <= MAX_STDOUT
            and result["stderr_bytes"] <= MAX_STDERR
        )
        report["output_within_limits"] = bounded
        if bounded:
            report["observation"] = closed_metadata(process.stdout_path.read_bytes())
        code = result["exit_code"]
        if (
            interrupted[0]
            or not report["cleanup_confirmed"]
            or report["capture_failed"]
            or not bounded
            or not 0 <= code <= 255
        ):
            write_metadata(directory / "metadata.json", report)
            return 3
        # All bytes are retained privately before forwarding. Parent parsing and
        # authoritative native proof remain responsible for task acceptance.
        forward(process.stdout_path, stdout)
        forward(process.stderr_path, stderr)
        write_metadata(directory / "metadata.json", report)
        return code
    except BaseException:
        # Process registry retains started/uncertain receipts and raw captures.
        # Attempt to join every returned handle, without forwarding any signal.
        for entry in processes.entries:
            while entry.poll() is None:
                time.sleep(0.025)
        report["capture_failed"] = True
        write_metadata(directory / "metadata.json", report)
        return 3
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delegate", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--capture-root", required=True, type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not args.arguments or args.arguments[0] != "--":
        parser.error("native arguments must follow --")
    args.arguments = args.arguments[1:]
    return args


def main(argv=None):
    try:
        return capture(arguments(argv), sys.stdout.buffer, sys.stderr.buffer)
    except Exception:
        # Fixed stderr only. Raw failures may contain private paths or argv.
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
