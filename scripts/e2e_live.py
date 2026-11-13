#!/usr/bin/env python3
"""Opt-in system-trusted MCP preflight and one installed-provider acceptance.

The driver owns private correlation receipts and finite helper observations.
Gateway owns routing; Delegate alone owns execution and canonical outcomes.
Task-count and time ceilings do not enforce a monetary budget. A provider run
requires an explicitly authorized environment and finite cost budget.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import stat
import time
import uuid

from e2e_native_capture import load_owners
from e2e_live_contracts import (
    CHUNK_BYTES,
    HEX32,
    MAX_HELPER_OUTPUT,
    MAX_JSON,
    MAX_RESULT,
    absolute_path,
    Config,
    Failure,
    descriptor,
    operation_observation,
    prepared_binding,
    require,
    require_capability,
)

MAX_PRIOR_ATTEMPTS = 128
SAFE_REASONS = frozenset(
    {
        "cleanup_authority_missing",
        "receipt_busy",
        "interrupted",
        "invalid_configuration",
        "task_observation_expired",
        "provider_opt_in_required",
        "preflight_opt_in_required",
        "prior_helpers_unverified",
        "controller_cleanup_unverified",
        "mcp_call_failed",
    }
)


def failure_reason(error):
    if (
        type(error) is Failure
        and len(error.args) == 1
        and type(error.args[0]) is str
        and error.args[0] in SAFE_REASONS
    ):
        return error.args[0]
    return "acceptance_failed"


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Failure("duplicate_json_key")
        result[key] = value
    return result


def reject_constant(_value):
    raise Failure("nonfinite_json_value")


def finite_float(value):
    parsed = float(value)
    require(math.isfinite(parsed), "nonfinite_json_value")
    return parsed


def decode_json(data):
    try:
        return json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Failure("invalid_json") from error


def private_directory(path):
    require(path.resolve(strict=True) == path, "noncanonical_directory")
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "invalid_private_directory",
    )


def private_json(path, bound=MAX_JSON):
    require(path.resolve(strict=True) == path, "noncanonical_private_file")
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == os.geteuid()
        and stat.S_IMODE(before.st_mode) == 0o600
        and before.st_size <= bound,
        "invalid_private_file",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(os.path.samestat(before, opened), "private_file_replaced")
        require(
            stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_uid == os.geteuid(),
            "invalid_private_file",
        )
        data = stream.read(bound + 1)
        after = os.fstat(stream.fileno())
        require(
            len(data) <= bound
            and after.st_size == opened.st_size == len(data)
            and after.st_mtime_ns == opened.st_mtime_ns,
            "private_file_changed",
        )
    return decode_json(data)


def durable_json(path, value):
    data = json.dumps(value, allow_nan=False, separators=(",", ":")).encode() + b"\n"
    require(len(data) <= MAX_JSON, "receipt_too_large")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def check_paths(config):
    require(
        config.native_repository.resolve(strict=True) == config.native_repository,
        "noncanonical_repository",
    )
    require(config.native_repository.is_dir(), "invalid_repository")
    require(
        config.helper.resolve(strict=True) == config.helper
        and config.helper.is_file()
        and os.access(config.helper, os.X_OK),
        "invalid_helper",
    )
    # The helper is selected in place. No executable contents are read.
    info = config.token_file.lstat()
    require(
        config.token_file.resolve(strict=True) == config.token_file
        and stat.S_ISREG(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == os.geteuid(),
        "invalid_token_file",
    )


class ReceiptLease:
    def __init__(self, directory):
        private_directory(directory)
        self.fd = os.open(
            directory / ".controller.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            info = os.fstat(self.fd)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1,
                "invalid_receipt_lock",
            )
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise Failure("receipt_busy") from error
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)


def prior_helper_cleanup(receipt):
    """Reuse only retained owner-written resource proof, never task outcomes.

    A crashed controller cannot manufacture its earlier helper's Wait. Missing
    or unjoined prior proof remains an explicit blocker even when a new control
    can establish the original task's canonical closure.
    """
    try:
        private_directory(receipt)
        attempts = []
        with os.scandir(receipt) as entries:
            for count, entry in enumerate(entries):
                if count >= MAX_PRIOR_ATTEMPTS + 3:
                    return "unverified"
                if entry.name in {"intent.json", "prepared.json", ".controller.lock"}:
                    continue
                if not re.fullmatch(r"attempt-[a-f0-9]{32}", entry.name):
                    return "unverified"
                attempts.append(receipt / entry.name)
        if len(attempts) > MAX_PRIOR_ATTEMPTS:
            return "unverified"
        for attempt in attempts:
            private_directory(attempt)
            summary = private_json(attempt / "summary.json", bound=4096)
            if not (
                type(summary) is dict
                and type(summary.get("schema_version")) is int
                and summary["schema_version"] == 1
                and summary.get("helpers_join_scope") == "current_controller"
                and summary.get("helpers_joined") is True
                and summary.get("controller_cleanup_confirmed") is True
            ):
                return "unverified"
        return "confirmed" if attempts else "not_applicable"
    except (Failure, OSError, RuntimeError):
        return "unverified"


class Interruptions:
    def __init__(self):
        self.requested = False
        self.previous = {}

    def install(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            self.previous[number] = signal.signal(number, self.request)

    def request(self, _number, _frame):
        # A running finite helper retains its owner; interruption never signals
        # a provider or skips the original operation's cleanup attempt.
        self.requested = True

    def restore(self):
        restored = True
        for number, handler in self.previous.items():
            try:
                signal.signal(number, handler)
            except Exception:
                restored = False
        require(restored, "controller_cleanup_unverified")


class Helpers:
    """Thin I/O through the maintained Native process registry."""

    def __init__(self, config, directory, owner, processes_type):
        self.config = config
        self.directory = directory
        self.sequence = 0
        self.last_started = 0.0
        self.processes = processes_type(
            directory / "processes", owner=owner, environment_keys_only=True
        )

    def call(self, action, value):
        require(action in {"mcp", "metadata"}, "invalid_helper_action")
        delay = 0.5 - (time.monotonic() - self.last_started)
        if delay > 0:
            time.sleep(delay)
        self.sequence += 1
        path = self.directory / f"input-{self.sequence:04d}.json"
        durable_json(path, value)
        self.last_started = time.monotonic()
        process = self.processes.run(
            "sdk",
            [self.config.helper, action, "--input", path],
            self.directory,
            timeout=45,
        )
        return process.json(bound=MAX_HELPER_OUTPUT)

    def mcp(self, tool, arguments):
        result = self.call(
            "mcp",
            {
                "endpoint": self.config.endpoint,
                "trust_mode": "system",
                "token_file": str(self.config.token_file),
                "tool": tool,
                "arguments": arguments,
            },
        )
        require(type(result) is dict, "invalid_mcp_response")
        envelope = result.get("structuredContent")
        require(
            type(envelope) is dict
            and set(envelope) == {"data"}
            and result.get("isError", False) is False,
            "mcp_call_failed",
        )
        require(type(envelope["data"]) is dict, "invalid_mcp_data")
        return envelope["data"]

    def metadata(self):
        return self.call(
            "metadata", {"endpoint": self.config.endpoint, "trust_mode": "system"}
        )

    def join(self):
        joined = True
        for process in self.processes.entries:
            try:
                # A foreign stateful MCP peer may make SDK Close perform a
                # second finite HTTP request. Observation expiry never proves
                # termination; keep this exact helper through that cleanup.
                process.wait(timeout=90, expected=None)
            except Exception:
                joined = False
        try:
            return self.processes.finished_naturally() and joined
        except Exception:
            return False


def read_result(
    helpers, binding, accepted, canary, *, clock=time.monotonic, checkpoint=lambda: None
):
    accepted = descriptor(accepted)
    end = clock() + 90
    result = bytearray()
    for _ in range((MAX_RESULT + CHUNK_BYTES - 1) // CHUNK_BYTES + 1):
        require(clock() < end, "result_observation_expired")
        checkpoint()
        offset = len(result)
        chunk = helpers.mcp(
            "read_result_chunk",
            {
                "operation_id": binding["operation_id"],
                "descriptor": accepted,
                "offset": offset,
                "limit": CHUNK_BYTES,
            },
        )
        require(
            type(chunk) is dict
            and set(chunk)
            == {"descriptor", "offset", "data_base64", "next_offset", "eof"}
            and descriptor(chunk["descriptor"]) == accepted
            and type(chunk["offset"]) is int
            and chunk["offset"] == offset
            and type(chunk["data_base64"]) is str
            and len(chunk["data_base64"]) <= 4 * ((CHUNK_BYTES + 2) // 3)
            and type(chunk["next_offset"]) is int
            and type(chunk["eof"]) is bool,
            "invalid_result_range",
        )
        try:
            data = base64.b64decode(chunk["data_base64"], validate=True)
        except ValueError as error:
            raise Failure("invalid_result_base64") from error
        require(
            base64.b64encode(data).decode() == chunk["data_base64"],
            "noncanonical_result_base64",
        )
        require(
            len(data) <= CHUNK_BYTES
            and offset + len(data) <= accepted["length"]
            and chunk["next_offset"] == offset + len(data)
            and chunk["eof"] == (chunk["next_offset"] == accepted["length"]),
            "invalid_result_cursor",
        )
        require(data or chunk["eof"], "result_range_stalled")
        result.extend(data)
        if chunk["eof"]:
            require(
                len(result) == accepted["length"]
                and hashlib.sha256(result).hexdigest() == accepted["sha256"]
                and canary.encode() in result,
                "accepted_result_verification_failed",
            )
            return accepted
    raise Failure("result_request_limit")


def intent_digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def read_original(receipt):
    value = private_json(receipt / "intent.json")
    require(
        type(value) is dict
        and set(value)
        == {"schema_version", "config", "cancellation_id", "canary", "brief"}
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and type(value["cancellation_id"]) is str
        and HEX32.fullmatch(value["cancellation_id"])
        and type(value["canary"]) is str
        and re.fullmatch(r"GATEWAY_PROVIDER_ACCEPTANCE_[a-f0-9]{32}", value["canary"])
        and value["brief"]
        == "Return exactly this text and do not use tools or change files: "
        + value["canary"],
        "invalid_original_intent",
    )
    config = Config.parse(value["config"], "provider")
    saved = private_json(receipt / "prepared.json")
    require(
        type(saved) is dict
        and set(saved)
        == {
            "schema_version",
            "operation_id",
            "task_id",
            "expires_at",
            "device_id",
            "project_alias",
            "cancellation_id",
            "intent_sha256",
        },
        "invalid_original_binding",
    )
    expected = prepared_binding(
        {key: saved.get(key) for key in ("operation_id", "task_id", "expires_at")},
        config,
        value["cancellation_id"],
        intent_digest(value),
        fresh=False,
    )
    require(
        type(saved["schema_version"]) is int and saved == expected,
        "original_binding_changed",
    )
    return config, value, expected


class LiveRun:
    def __init__(
        self,
        config,
        receipt,
        attempt,
        helpers,
        interruptions,
        *,
        cancel_on_cleanup: bool,
        clock=time.monotonic,
        sleep=time.sleep,
    ):
        self.config = config
        self.receipt = receipt
        self.attempt = attempt
        self.helpers = helpers
        self.interruptions = interruptions
        require(type(cancel_on_cleanup) is bool, "invalid_configuration")
        # Operator intent is fixed at construction. Observers own their helper
        # joins, never permission to cancel an existing Native-owned task.
        self._cancel_on_cleanup = cancel_on_cleanup
        self.clock = clock
        self.sleep = sleep
        self.binding = None
        self.intent = None
        self.task_cleanup_confirmed = False
        self.canonical_closure = False
        self.accepted = None
        self.phase = "starting"
        self.dispatch_attempts = 0

    def checkpoint(self):
        require(not self.interruptions.requested, "interrupted")

    def write_intent(self):
        canary = "GATEWAY_PROVIDER_ACCEPTANCE_" + uuid.uuid4().hex
        self.intent = {
            "schema_version": 1,
            "config": self.config.document(),
            "cancellation_id": uuid.uuid4().hex,
            "canary": canary,
            "brief": "Return exactly this text and do not use tools or change files: "
            + canary,
        }
        durable_json(self.receipt / "intent.json", self.intent)

    def load_original(self):
        config, intent, binding = read_original(self.receipt)
        require(config == self.config, "original_configuration_changed")
        self.intent, self.binding = intent, binding

    def provider(self):
        self.write_intent()
        self.checkpoint()
        value = self.helpers.mcp(
            "get_capabilities",
            {
                "device_id": self.config.targets[0][0],
                "project_alias": self.config.targets[0][1],
            },
        )
        require_capability(value, self.config, self.config.targets[0], dispatch=True)
        self.checkpoint()
        request = self.config.prepare_request(self.intent["brief"])
        self.phase = "prepare_possibly_sent"
        value = self.helpers.mcp("prepare_dispatch", request)
        binding = prepared_binding(
            value,
            self.config,
            self.intent["cancellation_id"],
            intent_digest(self.intent),
            fresh=True,
            now=datetime.now(timezone.utc),
        )
        durable_json(self.receipt / "prepared.json", binding)
        self.binding = binding
        self.phase = "prepared"
        self.checkpoint()
        self.phase = "dispatch_possibly_sent"
        self.dispatch_attempts += 1
        dispatched = self.helpers.mcp(
            "dispatch_task", {"operation_id": binding["operation_id"]}
        )
        operation_observation(dispatched, binding)
        self.checkpoint()
        self.verify_existing()

    def verify_existing(self):
        accepted = self.observe(self.config.budget_seconds + 60, acceptance=True)
        self.checkpoint()
        self.accepted = read_result(
            self.helpers,
            self.binding,
            accepted,
            self.intent["canary"],
            clock=self.clock,
            checkpoint=self.checkpoint,
        )
        self.phase = "provider_verified"

    def observe(self, seconds, *, acceptance):
        deadline = self.clock() + seconds
        for _ in range(2 * (seconds + 1)):
            require(self.clock() < deadline, "task_observation_expired")
            if acceptance:
                self.checkpoint()
            value = self.helpers.mcp(
                "resolve_operation", {"operation_id": self.binding["operation_id"]}
            )
            observation = operation_observation(value, self.binding)
            if observation is not None:
                if observation.get("execution_closure") is not None:
                    self.task_cleanup_confirmed = True
                    self.canonical_closure = True
                    if not acceptance:
                        return None
                    require(
                        observation.get("result") is not None,
                        "provider_closed_without_result",
                    )
                    return descriptor(observation["result"])
                if observation["kind"] == "refused" and value["reserved"] is False:
                    self.task_cleanup_confirmed = True
                    require(not acceptance, "provider_refused")
                    return None
            self.sleep(0.5)
        raise Failure("task_observation_limit")

    def cancel(self):
        self.phase = "cancel_possibly_sent"
        value = self.helpers.mcp(
            "cancel_task",
            {
                "operation_id": self.binding["operation_id"],
                "cancellation_id": self.binding["cancellation_id"],
            },
        )
        require(
            type(value) is dict
            and value.get("operation_id") == self.binding["operation_id"]
            and value.get("cancellation_id") == self.binding["cancellation_id"]
            and type(value.get("definitely_unsent")) is bool
            and type(value.get("closure_confirmed")) is bool,
            "invalid_cancellation_response",
        )
        if value["definitely_unsent"]:
            self.task_cleanup_confirmed = True
            self.phase = "cleanup_confirmed"
            return
        # Even a cancellation ACK claiming closure is followed by canonical
        # observation of the original task; ACK alone is never accepted here.
        self.observe(60, acceptance=False)
        self.phase = "cleanup_confirmed"

    def preflight(self):
        self.checkpoint()
        metadata = self.helpers.metadata()
        require(
            type(metadata) is dict
            and metadata.get("resource") == self.config.endpoint
            and metadata.get("authorization_servers") == [self.config.expected_issuer],
            "resource_metadata_mismatch",
        )
        for target in self.config.targets:
            self.checkpoint()
            value = self.helpers.mcp(
                "get_capabilities", {"device_id": target[0], "project_alias": target[1]}
            )
            require_capability(value, self.config, target, dispatch=False)
        self.phase = "preflight_verified"

    def cleanup(self):
        joined = self.helpers.join()
        if (
            self._cancel_on_cleanup
            and joined
            and self.binding is not None
            and not self.task_cleanup_confirmed
        ):
            try:
                self.cancel()
            except Exception:
                # The original identity remains in immutable prepared.json.
                # A failed cleanup never changes an acceptance into success.
                self.phase = "task_cleanup_unverified"
        return self.helpers.join() and joined


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    provider = subparsers.add_parser("provider")
    provider.add_argument("--run-real-provider", action="store_true")
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--run-external-preflight", action="store_true")
    for command in (provider, preflight):
        command.add_argument("--config", required=True)
        command.add_argument("--receipt-directory", required=True)
    resume = subparsers.add_parser("resume")
    resume.add_argument("--receipt-directory", required=True)
    action = resume.add_mutually_exclusive_group(required=True)
    action.add_argument("--observe", action="store_true")
    action.add_argument("--cancel", action="store_true")
    args = parser.parse_args(argv)
    require(
        args.mode != "provider" or args.run_real_provider, "provider_opt_in_required"
    )
    require(
        args.mode != "preflight" or args.run_external_preflight,
        "preflight_opt_in_required",
    )
    return args


def execute(args):
    receipt = absolute_path(args.receipt_directory)
    if args.mode == "resume":
        private_directory(receipt)
        # Validate original bindings before loading executable harness code;
        # load_original repeats the same reader after acquiring the lease.
        config, _, _ = read_original(receipt)
    else:
        config = Config.parse(private_json(absolute_path(args.config)), args.mode)
    check_paths(config)
    DirectoryOwner, Processes = load_owners(config.native_repository)
    owner = DirectoryOwner()
    lease = None
    interruptions = Interruptions()
    run = None
    attempt = None
    passed = False
    joined = False
    controller_clean = False
    prior_cleanup = "unverified"
    reason = "acceptance_failed"
    category = (
        "provider_recovery"
        if args.mode == "resume"
        else (
            "installed_provider_acceptance"
            if args.mode == "provider"
            else "system_https_authenticated_sdk_preflight"
        )
    )
    try:
        if args.mode != "resume":
            require(
                receipt.parent.resolve(strict=True) == receipt.parent,
                "noncanonical_receipt_parent",
            )
            owner.create(
                "live acceptance receipt",
                receipt,
                receipt.parent,
                mode=0o700,
                parents=False,
            )
        lease = ReceiptLease(receipt)
        prior_cleanup = prior_helper_cleanup(receipt)
        attempt = receipt / ("attempt-" + uuid.uuid4().hex)
        owner.create(
            "live acceptance attempt", attempt, receipt, mode=0o700, parents=False
        )
        helpers = Helpers(config, attempt, owner, Processes)
        run = LiveRun(
            config,
            receipt,
            attempt,
            helpers,
            interruptions,
            cancel_on_cleanup=args.mode == "provider"
            or (args.mode == "resume" and args.cancel),
        )
        interruptions.install()
        if args.mode == "provider":
            run.provider()
        elif args.mode == "preflight":
            run.preflight()
        else:
            run.load_original()
            if args.cancel:
                run.cancel()
            else:
                run.verify_existing()
        passed = not interruptions.requested
    except Exception as error:
        passed = False
        reason = failure_reason(error)
    finally:
        if run is not None:
            try:
                joined = run.cleanup()
            except Exception:
                joined = False
        controller_clean = joined
        # Every close is attempted even if an earlier close fails. Keep the
        # interruption owner until helper, directory and lease cleanup settle.
        closers = [owner.release]
        if lease is not None:
            closers.append(lease.close)
        closers.append(interruptions.restore)
        for close in closers:
            try:
                close()
            except Exception:
                controller_clean = False

    # Classification follows ALL cleanup, including signals handled while an
    # owner released its resources. No earlier candidate PASS is persisted.
    if interruptions.requested:
        passed = False
        reason = "interrupted"
    elif passed and not controller_clean:
        reason = "controller_cleanup_unverified"
    elif passed and prior_cleanup == "unverified":
        reason = "prior_helpers_unverified"
    passed = passed and joined and controller_clean and prior_cleanup != "unverified"
    summary = {
        "schema_version": 1,
        "category": category,
        "result": "passed" if passed else "failed",
        "helpers_joined": joined,
        "helpers_join_scope": "current_controller",
        "controller_cleanup_confirmed": controller_clean,
        "prior_helper_cleanup": prior_cleanup,
        "task_cleanup_confirmed": run.task_cleanup_confirmed
        if run is not None
        else False,
        "canonical_execution_closure": run.canonical_closure
        if run is not None
        else False,
        "provider_acceptance": "passed"
        if passed and run is not None and run.accepted is not None
        else "unverified",
        "chatgpt_cloud_acceptance": "unverified",
        "multi_network_acceptance": "unverified",
        "phase": run.phase if run is not None else "setup_failed",
        "dispatch_attempts_in_this_controller": run.dispatch_attempts
        if run is not None
        else 0,
    }
    if not passed:
        summary["reason"] = reason
    if args.mode == "resume" and args.cancel:
        summary["result"] = (
            "cleanup_confirmed" if passed and run.task_cleanup_confirmed else "failed"
        )
    if run is not None and run.accepted is not None:
        summary["result_descriptor"] = run.accepted
    if attempt is not None and attempt.is_dir():
        # Directory ownership was released without deletion. A concurrent resume
        # that beats this final write conservatively sees missing prior proof.
        durable_json(attempt / "summary.json", summary)
    return (0 if passed else 1), summary


def main(argv=None):
    try:
        code, summary = execute(arguments(argv))
    except Exception as error:
        code, summary = (
            1,
            {
                "schema_version": 1,
                "result": "failed",
                "code": "live_acceptance_unavailable",
                "reason": failure_reason(error),
            },
        )
    print(json.dumps(summary, allow_nan=False, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
