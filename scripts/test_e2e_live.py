"""Bounded driver invariants; no installed providers or network accounts run."""

import base64
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import signal
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

import e2e_live as live
import e2e_live_contracts as contracts


TASK = "a" * 32
OPERATION = "operation-one"


def configuration(mode="provider"):
    common = {
        "endpoint": "https://gateway.example/mcp",
        "helper": "/selected/gateway-sdk-helper",
        "token_file": "/private/access-token.json",
        "native_repository": "/selected/native",
    }
    if mode == "preflight":
        return {
            **common,
            "expected_issuer": "https://issuer.example/",
            "targets": [
                {"device_id": "home", "project_alias": "project"},
                {"device_id": "office", "project_alias": "project"},
            ],
        }
    return {
        **common,
        "device_id": "home",
        "project_alias": "project",
        "provider": "provider:exec",
        "permission": "read-only",
        "budget_seconds": 1,
        "max_tasks": 1,
    }


def capabilities(config, target=None):
    device, project = target or config.targets[0]
    return {
        "device_id": device,
        "project_alias": project,
        "online": True,
        "delegate_ready": True,
        "execution_readiness": "unknown",
        "task_read_allowed": True,
        "task_cancel_allowed": True,
        "providers": [
            {
                "provider": config.provider,
                "authentication": "unknown",
                "dispatch_allowed": True,
                "permissions": ["read-only"],
                "max_budget_seconds": 60,
                "models": ["model"],
                "efforts": ["high"],
            }
        ],
    }


class Clock:
    def __init__(self):
        self.value = 0.0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class BoundaryHelpers:
    """Script the external SDK boundary; the real driver owns every decision."""

    def __init__(self, config):
        self.config = config
        self.calls = []
        self.marker = b""
        self.fail = None
        self.closed = True
        self.joined = True
        self.cancel_unsent = False
        self.on_call = None

    def accepted(self):
        return {
            "sha256": hashlib.sha256(self.marker).hexdigest(),
            "length": len(self.marker),
        }

    def operation(self):
        observation = {
            "kind": "terminal" if self.closed else "existing",
            "observed_at": "2026-11-11T12:00:00Z",
            "result": self.accepted(),
        }
        if self.closed:
            observation["execution_closure"] = {
                "kind": "registered-native",
                "reference_sha256": "b" * 64,
            }
        return {
            "operation_id": OPERATION,
            "task_id": TASK,
            "device_id": self.config.targets[0][0],
            "project_alias": self.config.targets[0][1],
            "reserved": not self.closed,
            "observation": observation,
        }

    def mcp(self, tool, arguments):
        self.calls.append((tool, dict(arguments)))
        if self.on_call is not None:
            self.on_call(tool, arguments)
        if tool == self.fail:
            raise live.Failure("simulated_response_loss")
        if tool == "get_capabilities":
            return capabilities(
                self.config, (arguments["device_id"], arguments["project_alias"])
            )
        if tool == "prepare_dispatch":
            self.marker = arguments["brief"].split(": ", 1)[1].encode()
            return {
                "operation_id": OPERATION,
                "task_id": TASK,
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(minutes=1)
                ).isoformat(),
            }
        if tool in {"dispatch_task", "resolve_operation"}:
            return self.operation()
        if tool == "cancel_task":
            return {
                **arguments,
                "definitely_unsent": self.cancel_unsent,
                "closure_confirmed": True,
            }
        if tool == "read_result_chunk":
            start = arguments["offset"]
            data = self.marker[start : start + arguments["limit"]]
            return {
                "descriptor": self.accepted(),
                "offset": start,
                "data_base64": base64.b64encode(data).decode(),
                "next_offset": start + len(data),
                "eof": start + len(data) == len(self.marker),
            }
        raise AssertionError("unexpected tool")

    def metadata(self):
        self.calls.append(("metadata", {}))
        return {
            "resource": self.config.endpoint,
            "authorization_servers": [self.config.expected_issuer],
        }

    def join(self):
        return self.joined


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.receipt = Path(self.temporary.name) / "receipt"
        self.receipt.mkdir(mode=0o700)
        self.config = contracts.Config.parse(configuration(), "provider")
        self.helpers = BoundaryHelpers(self.config)
        self.interruptions = live.Interruptions()
        self.clock = Clock()
        self.run = live.LiveRun(
            self.config,
            self.receipt,
            self.receipt,
            self.helpers,
            self.interruptions,
            cancel_on_cleanup=True,
            clock=self.clock.now,
            sleep=self.clock.sleep,
        )

    def names(self):
        return [tool for tool, _ in self.helpers.calls]

    def test_prepare_request_omits_defaults_and_private_configuration_fields(self):
        original_document = contracts.Config.document

        def private_document(config):
            return {
                **original_document(config),
                "future_private_note": "PRIVATE_CONFIGURATION_CANARY",
            }

        with mock.patch.object(contracts.Config, "document", private_document):
            self.run.provider()
        prepared = [
            value for tool, value in self.helpers.calls if tool == "prepare_dispatch"
        ]
        self.assertEqual(
            prepared,
            [
                {
                    "device_id": "home",
                    "project_alias": "project",
                    "provider": "provider:exec",
                    "permission": "read-only",
                    "budget_seconds": 1,
                    "brief": self.run.intent["brief"],
                }
            ],
        )

    def test_prepare_request_contains_only_explicit_model_and_effort_selections(self):
        selected = replace(self.config, model="model", effort="high")
        self.run.config = selected
        self.helpers.config = selected
        self.run.provider()
        prepared = [
            value for tool, value in self.helpers.calls if tool == "prepare_dispatch"
        ]
        self.assertEqual(
            prepared,
            [
                {
                    "device_id": "home",
                    "project_alias": "project",
                    "provider": "provider:exec",
                    "permission": "read-only",
                    "budget_seconds": 1,
                    "brief": self.run.intent["brief"],
                    "model": "model",
                    "effort": "high",
                }
            ],
        )

    def test_success_requires_durable_ids_before_one_dispatch(self):
        def check_boundary(tool, _arguments):
            if tool == "prepare_dispatch":
                self.assertTrue((self.receipt / "intent.json").is_file())
            if tool == "dispatch_task":
                saved = live.private_json(self.receipt / "prepared.json")
                self.assertEqual(saved["operation_id"], OPERATION)
                self.assertEqual(saved["task_id"], TASK)
                self.assertEqual(
                    saved["cancellation_id"], self.run.intent["cancellation_id"]
                )

        self.helpers.on_call = check_boundary
        self.run.provider()
        self.assertEqual(self.names().count("prepare_dispatch"), 1)
        self.assertEqual(self.names().count("dispatch_task"), 1)
        self.assertEqual(self.run.accepted, self.helpers.accepted())
        self.assertTrue(self.run.canonical_closure)
        self.assertTrue(self.run.cleanup())
        self.assertNotIn("cancel_task", self.names())

    def test_fsync_failure_before_intent_or_prepared_forbids_dispatch(self):
        original = live.durable_json
        for filename in ("intent.json", "prepared.json"):
            with self.subTest(filename=filename):
                directory = self.receipt / filename.replace(".", "-")
                directory.mkdir(mode=0o700)
                helpers = BoundaryHelpers(self.config)
                run = live.LiveRun(
                    self.config,
                    directory,
                    directory,
                    helpers,
                    self.interruptions,
                    cancel_on_cleanup=True,
                )

                def writing(path, value):
                    if path.name == filename:
                        raise OSError("simulated sync failure")
                    return original(path, value)

                with mock.patch.object(live, "durable_json", side_effect=writing):
                    with self.assertRaises(OSError):
                        run.provider()
                self.assertFalse(
                    any(name == "dispatch_task" for name, _ in helpers.calls)
                )
                self.assertIsNone(run.binding)

    def test_file_and_parent_sync_complete_before_prepare_and_dispatch(self):
        synced = []
        original_sync = os.fsync

        def sync(descriptor):
            info = os.fstat(descriptor)
            if stat.S_ISREG(info.st_mode):
                self.assertGreater(info.st_size, 0, "flush before file sync")
                synced.append("file")
            else:
                self.assertTrue(stat.S_ISDIR(info.st_mode))
                synced.append("directory")
            return original_sync(descriptor)

        def check(tool, _arguments):
            if tool == "prepare_dispatch":
                self.assertEqual(synced, ["file", "directory"])
            if tool == "dispatch_task":
                self.assertEqual(synced, ["file", "directory", "file", "directory"])

        self.helpers.on_call = check
        with mock.patch.object(live.os, "fsync", side_effect=sync):
            self.run.provider()

    def test_actual_file_or_parent_sync_failure_never_reaches_dispatch(self):
        original_sync = os.fsync
        for fail_at in (1, 2, 3, 4):
            with self.subTest(fail_at=fail_at):
                receipt = self.receipt / f"sync-failure-{fail_at}"
                receipt.mkdir(mode=0o700)
                helpers = BoundaryHelpers(self.config)
                run = live.LiveRun(
                    self.config,
                    receipt,
                    receipt,
                    helpers,
                    self.interruptions,
                    cancel_on_cleanup=True,
                )
                calls = 0

                def failing_sync(descriptor):
                    nonlocal calls
                    calls += 1
                    if calls == fail_at:
                        raise OSError("simulated sync failure")
                    return original_sync(descriptor)

                with mock.patch.object(live.os, "fsync", side_effect=failing_sync):
                    with self.assertRaises(OSError):
                        run.provider()
                self.assertFalse(
                    any(tool == "dispatch_task" for tool, _ in helpers.calls)
                )

    def test_lost_prepare_reply_retains_intent_without_replacement(self):
        self.helpers.fail = "prepare_dispatch"
        with self.assertRaises(live.Failure):
            self.run.provider()
        self.assertTrue(self.run.cleanup())
        self.assertIsNone(self.run.binding)
        self.assertTrue((self.receipt / "intent.json").is_file())
        self.assertEqual(self.names(), ["get_capabilities", "prepare_dispatch"])

    def test_lost_dispatch_reply_cancels_only_saved_identity(self):
        self.helpers.fail = "dispatch_task"
        with self.assertRaises(live.Failure):
            self.run.provider()
        self.assertTrue(self.run.cleanup())
        cancelled = [args for tool, args in self.helpers.calls if tool == "cancel_task"]
        self.assertEqual(
            cancelled,
            [
                {
                    "operation_id": OPERATION,
                    "cancellation_id": self.run.binding["cancellation_id"],
                }
            ],
        )
        self.assertEqual(self.names().count("prepare_dispatch"), 1)
        self.assertEqual(self.names().count("dispatch_task"), 1)
        self.assertTrue(self.run.task_cleanup_confirmed)
        self.assertIsNone(self.run.accepted)

    def test_resume_rechecks_original_operation_and_never_prepares_or_dispatches(self):
        self.run.provider()
        helpers = BoundaryHelpers(self.config)
        helpers.marker = self.helpers.marker
        resumed = live.LiveRun(
            self.config,
            self.receipt,
            self.receipt,
            helpers,
            self.interruptions,
            cancel_on_cleanup=False,
        )
        resumed.load_original()
        resumed.verify_existing()
        self.assertEqual(
            [tool for tool, _ in helpers.calls],
            ["resolve_operation", "read_result_chunk"],
        )
        self.assertEqual(resumed.binding, self.run.binding)
        self.assertEqual(resumed.accepted, self.run.accepted)

    def test_resume_rejects_changed_original_binding_before_network(self):
        self.run.provider()
        saved = live.private_json(self.receipt / "prepared.json")
        saved["device_id"] = "other-device"
        path = self.receipt / "prepared.json"
        path.write_text(json.dumps(saved))
        resumed = live.LiveRun(
            self.config,
            self.receipt,
            self.receipt,
            self.helpers,
            self.interruptions,
            cancel_on_cleanup=False,
        )
        before = list(self.helpers.calls)
        with self.assertRaises(live.Failure):
            resumed.load_original()
        self.assertEqual(self.helpers.calls, before)

    def test_accepted_result_without_closure_is_never_success(self):
        self.helpers.closed = False
        with self.assertRaises(live.Failure):
            self.run.provider()
        self.assertIsNone(self.run.accepted)
        self.assertFalse(self.run.canonical_closure)
        self.assertFalse(self.run.task_cleanup_confirmed)
        self.assertNotIn("read_result_chunk", self.names())

    def test_cancellation_ack_without_canonical_observation_is_not_cleanup(self):
        self.helpers.fail = "dispatch_task"
        with self.assertRaises(live.Failure):
            self.run.provider()
        self.helpers.fail = "resolve_operation"
        self.assertTrue(self.run.cleanup())
        self.assertFalse(self.run.task_cleanup_confirmed)
        self.assertEqual(self.run.phase, "task_cleanup_unverified")

    def test_unjoined_helper_forbids_cleanup_helper_and_claims_no_closure(self):
        self.helpers.fail = "dispatch_task"
        with self.assertRaises(live.Failure):
            self.run.provider()
        self.helpers.joined = False
        self.assertFalse(self.run.cleanup())
        self.assertNotIn("cancel_task", self.names())
        self.assertFalse(self.run.task_cleanup_confirmed)

    def test_interruption_after_dispatch_keeps_identity_and_cleans_up(self):
        def interrupt(tool, _arguments):
            if tool == "dispatch_task":
                self.interruptions.request(2, None)

        self.helpers.on_call = interrupt
        with self.assertRaises(live.Failure):
            self.run.provider()
        self.assertTrue(self.run.cleanup())
        self.assertIn("cancel_task", self.names())
        self.assertTrue(self.run.task_cleanup_confirmed)
        self.assertIsNone(self.run.accepted)

    def test_preflight_has_exactly_two_selected_devices_and_zero_mutations(self):
        config = contracts.Config.parse(configuration("preflight"), "preflight")
        helpers = BoundaryHelpers(config)
        run = live.LiveRun(
            config,
            self.receipt,
            self.receipt,
            helpers,
            self.interruptions,
            cancel_on_cleanup=False,
        )
        run.preflight()
        self.assertEqual(
            [tool for tool, _ in helpers.calls],
            ["metadata", "get_capabilities", "get_capabilities"],
        )
        self.assertEqual(
            [
                args["device_id"]
                for tool, args in helpers.calls
                if tool == "get_capabilities"
            ],
            ["home", "office"],
        )
        self.assertIsNone(run.binding)

    def test_preflight_metadata_mismatch_never_launches_tools(self):
        config = contracts.Config.parse(configuration("preflight"), "preflight")
        helpers = BoundaryHelpers(config)
        helpers.metadata = lambda: {
            "resource": config.endpoint,
            "authorization_servers": ["https://other.example/"],
        }
        run = live.LiveRun(
            config,
            self.receipt,
            self.receipt,
            helpers,
            self.interruptions,
            cancel_on_cleanup=False,
        )
        with self.assertRaises(live.Failure):
            run.preflight()
        self.assertEqual(helpers.calls, [])


class ContractTests(unittest.TestCase):
    def test_explicit_opt_in_is_required_before_configuration_or_actors(self):
        for mode in ("provider", "preflight"):
            with self.subTest(mode=mode), mock.patch.object(live, "execute") as execute:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(
                        live.main(
                            [
                                mode,
                                "--config",
                                "/missing",
                                "--receipt-directory",
                                "/missing",
                            ]
                        ),
                        1,
                    )
                execute.assert_not_called()
                self.assertEqual(
                    json.loads(output.getvalue())["code"], "live_acceptance_unavailable"
                )

    def test_configuration_is_strict_and_count_budget_permission_are_explicit(self):
        base = configuration()
        changes = [
            {"max_tasks": 2},
            {"max_tasks": True},
            {"budget_seconds": 0},
            {"budget_seconds": 3601},
            {"budget_seconds": True},
            {"permission": "workspace-write"},
            {"unknown": "ignored"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(live.Failure):
                contracts.Config.parse({**base, **change}, "provider")
        external = configuration("preflight")
        external["targets"][1]["device_id"] = "home"
        with self.assertRaises(live.Failure):
            contracts.Config.parse(external, "preflight")

    def test_system_urls_reject_token_forwarding_or_fixture_destinations(self):
        for endpoint in (
            "http://gateway.example/mcp",
            "https://user@gateway.example/mcp",
            "https://gateway.example/mcp?",
            "https://gateway.example/mcp#",
            "https://gateway.example/%6dcp",
            "https://gateway.example:0/mcp",
            "https://gateway.example:/mcp",
            "https://127.0.0.1/mcp",
            "https://Gateway.example/mcp",
            "https://gateway.example/other",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(live.Failure):
                contracts.Config.parse(
                    {**configuration(), "endpoint": endpoint}, "provider"
                )
        self.assertEqual(
            contracts.https_url("https://gateway/mcp", endpoint=True),
            "https://gateway/mcp",
        )

    def test_cleanup_authority_and_provider_ceiling_fail_closed_independently(self):
        config = contracts.Config.parse(configuration(), "provider")
        for change in (
            {"task_read_allowed": False},
            {"task_cancel_allowed": False},
            {"online": False},
            {"device_id": "other"},
        ):
            value = capabilities(config)
            value.update(change)
            with self.subTest(change=change), self.assertRaises(live.Failure):
                contracts.require_capability(
                    value, config, config.targets[0], dispatch=True
                )
        value = capabilities(config)
        del value["task_cancel_allowed"]
        with self.assertRaises(live.Failure):
            contracts.require_capability(
                value, config, config.targets[0], dispatch=True
            )
        for change in (
            {"max_budget_seconds": 0},
            {"dispatch_allowed": False},
            {"permissions": ["workspace-write"]},
        ):
            value = capabilities(config)
            value["providers"][0].update(change)
            with self.subTest(change=change), self.assertRaises(live.Failure):
                contracts.require_capability(
                    value, config, config.targets[0], dispatch=True
                )
        contracts.require_capability(
            capabilities(config), config, config.targets[0], dispatch=True
        )
        with self.assertRaises(live.Failure):
            contracts.require_capability(
                capabilities(config),
                replace(config, model="other-model"),
                config.targets[0],
                dispatch=True,
            )

    def test_private_json_rejects_duplicates_nonfinite_symlinks_and_wide_permissions(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            for content in ('{"key":1,"key":2}', '{"key":NaN}', '{"key":1e999}'):
                path.write_text(content)
                path.chmod(0o600)
                with self.subTest(content=content), self.assertRaises(live.Failure):
                    live.private_json(path)
            path.write_text("{}")
            path.chmod(0o644)
            with self.assertRaises(live.Failure):
                live.private_json(path)
            path.chmod(0o600)
            alias = Path(temporary) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(live.Failure):
                live.private_json(alias)

    def test_receipt_lease_refuses_concurrent_controller(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            first = live.ReceiptLease(directory)
            try:
                with self.assertRaisesRegex(live.Failure, "receipt_busy"):
                    live.ReceiptLease(directory)
            finally:
                first.close()
            second = live.ReceiptLease(directory)
            second.close()

    def test_prior_resource_proof_rejects_missing_legacy_or_unhealthy_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary)
            receipt.chmod(0o700)
            attempt = receipt / ("attempt-" + "a" * 32)
            attempt.mkdir(mode=0o700)
            path = attempt / "summary.json"
            good = {
                "schema_version": 1,
                "helpers_join_scope": "current_controller",
                "helpers_joined": True,
                "controller_cleanup_confirmed": True,
                "result": "failed",
                "provider_acceptance": "unverified",
            }
            live.durable_json(path, good)
            self.assertEqual(live.prior_helper_cleanup(receipt), "confirmed")
            for change in (
                {"helpers_joined": False},
                {"controller_cleanup_confirmed": False},
                {"helpers_join_scope": "all_controllers"},
                {"schema_version": True},
            ):
                path.write_text(json.dumps({**good, **change}))
                with self.subTest(change=change):
                    self.assertEqual(live.prior_helper_cleanup(receipt), "unverified")
            legacy = dict(good)
            del legacy["controller_cleanup_confirmed"]
            path.write_text(json.dumps(legacy))
            self.assertEqual(live.prior_helper_cleanup(receipt), "unverified")
            path.write_text('{"incomplete":')
            self.assertEqual(live.prior_helper_cleanup(receipt), "unverified")
            path.unlink()
            self.assertEqual(live.prior_helper_cleanup(receipt), "unverified")

    def test_prior_resource_scan_refuses_symlinks_and_excess_attempts(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "receipt"
            receipt.mkdir(mode=0o700)
            attempt = receipt / ("attempt-" + "a" * 32)
            attempt.mkdir(mode=0o700)
            path = attempt / "summary.json"
            target = Path(temporary) / "foreign.json"
            good = {
                "schema_version": 1,
                "helpers_join_scope": "current_controller",
                "helpers_joined": True,
                "controller_cleanup_confirmed": True,
            }
            live.durable_json(target, good)
            path.symlink_to(target)
            self.assertEqual(live.prior_helper_cleanup(receipt), "unverified")
            path.unlink()
            live.durable_json(path, good)
            second = receipt / ("attempt-" + "b" * 32)
            second.mkdir(mode=0o700)
            live.durable_json(second / "summary.json", good)
            self.assertEqual(live.prior_helper_cleanup(receipt), "confirmed")
            with mock.patch.object(live, "MAX_PRIOR_ATTEMPTS", 1):
                self.assertEqual(live.prior_helper_cleanup(receipt), "unverified")

    def test_failure_reason_is_closed_and_never_echoes_unknown_local_values(self):
        self.assertEqual(
            live.failure_reason(live.Failure("receipt_busy")), "receipt_busy"
        )
        self.assertEqual(
            live.failure_reason(live.Failure("PRIVATE_CANARY")), "acceptance_failed"
        )
        self.assertEqual(
            live.failure_reason(live.Failure(["unhashable"])), "acceptance_failed"
        )
        self.assertEqual(
            live.failure_reason(RuntimeError("PRIVATE_CANARY")), "acceptance_failed"
        )


class ResultTests(unittest.TestCase):
    def setUp(self):
        self.config = contracts.Config.parse(configuration(), "provider")
        self.helpers = BoundaryHelpers(self.config)
        self.helpers.marker = b"marker"
        self.binding = {"operation_id": OPERATION}

    def test_verified_multiple_chunks_match_length_sha_and_marker(self):
        self.helpers.marker = b"x" * (live.CHUNK_BYTES + 20) + b"marker"
        accepted = self.helpers.accepted()
        self.assertEqual(
            live.read_result(self.helpers, self.binding, accepted, "marker"), accepted
        )
        self.assertEqual(
            [args["offset"] for _, args in self.helpers.calls], [0, live.CHUNK_BYTES]
        )

    def test_bad_ranges_hashes_base64_and_eof_never_pass(self):
        original = self.helpers.mcp
        changes = [
            {"offset": 1},
            {"next_offset": 1},
            {"eof": False},
            {"data_base64": "%%%"},
            {"data_base64": "bWFya2Vy="},
            {"descriptor": {"sha256": "0" * 64, "length": 6}},
        ]
        for change in changes:
            self.helpers.mcp = lambda tool, arguments, change=change: {
                **original(tool, arguments),
                **change,
            }
            with self.subTest(change=change), self.assertRaises(live.Failure):
                live.read_result(
                    self.helpers, self.binding, self.helpers.accepted(), "marker"
                )
        self.helpers.mcp = original
        with self.assertRaises(live.Failure):
            live.read_result(
                self.helpers, self.binding, self.helpers.accepted(), "different-marker"
            )

    def test_sha_is_verified_even_when_marker_and_length_still_match(self):
        original = self.helpers.mcp

        def corrupt(tool, arguments):
            response = original(tool, arguments)
            response["data_base64"] = base64.b64encode(b"markfr").decode()
            return response

        self.helpers.mcp = corrupt
        with self.assertRaisesRegex(
            live.Failure, "accepted_result_verification_failed"
        ):
            live.read_result(
                self.helpers, self.binding, self.helpers.accepted(), "mark"
            )

    def test_cross_task_or_device_observations_are_rejected(self):
        self.helpers.marker = b"marker"
        binding = {
            "operation_id": OPERATION,
            "task_id": TASK,
            "device_id": "home",
            "project_alias": "project",
            "cancellation_id": "c" * 32,
        }
        for change in (
            {"operation_id": "other"},
            {"task_id": "d" * 32},
            {"device_id": "office"},
            {"project_alias": "other"},
        ):
            with self.subTest(change=change), self.assertRaises(live.Failure):
                contracts.operation_observation(
                    {**self.helpers.operation(), **change}, binding
                )


class HelperTests(unittest.TestCase):
    def test_partial_start_and_wait_failure_keep_known_owner_and_report_unjoined(self):
        helper = object.__new__(live.Helpers)
        process = SimpleNamespace(
            wait=mock.Mock(side_effect=RuntimeError("wait failed"))
        )
        helper.processes = SimpleNamespace(
            entries=[process], finished_naturally=lambda: False
        )
        self.assertFalse(helper.join())
        process.wait.assert_called_once_with(timeout=90, expected=None)

    def test_fixed_sdk_argv_and_metadata_request_have_no_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = contracts.Config.parse(configuration(), "provider")
            process = SimpleNamespace(
                json=mock.Mock(return_value={"resource": config.endpoint})
            )
            registry = SimpleNamespace(run=mock.Mock(return_value=process))
            helper = live.Helpers(
                config, directory, object(), lambda *_args, **_options: registry
            )
            helper.metadata()
            invocation = registry.run.call_args
            self.assertEqual(
                invocation.args[1][:3], [config.helper, "metadata", "--input"]
            )
            payload = live.private_json(invocation.args[1][3])
            self.assertEqual(
                payload, {"endpoint": config.endpoint, "trust_mode": "system"}
            )
            process.json.assert_called_once_with(bound=2 << 20)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.native = self.base / "native"
        self.native.mkdir(mode=0o700)
        self.helper = self.base / "sdk-helper"
        self.helper.write_text("owned test fixture; never executed")
        self.helper.chmod(0o700)
        self.token = self.base / "private-token.json"
        live.durable_json(self.token, {"token": "PRIVATE_TOKEN_CANARY"})
        self.configuration = {
            **configuration(),
            "helper": str(self.helper),
            "token_file": str(self.token),
            "native_repository": str(self.native),
        }
        self.config_file = self.base / "operator.json"
        live.durable_json(self.config_file, self.configuration)
        self.receipt = self.base / "receipt"
        self.created_helpers = []
        self.owners = []
        self.helper_joined = True
        self.helper_failure = None
        test = self

        class DirectoryOwner:
            def __init__(self):
                self.released = False
                test.owners.append(self)

            def create(self, _label, directory, _parent, *, mode, parents):
                directory.mkdir(mode=mode, parents=parents)

            def release(self):
                self.released = True

        self.loader = mock.patch.object(
            live, "load_owners", return_value=(DirectoryOwner, object)
        )
        self.loader.start()
        self.addCleanup(self.loader.stop)

        def helpers(config, _directory, _owner, _processes):
            helper = BoundaryHelpers(config)
            helper.joined = self.helper_joined
            helper.fail = self.helper_failure
            if (self.receipt / "intent.json").exists():
                helper.marker = live.private_json(self.receipt / "intent.json")[
                    "canary"
                ].encode()
            self.created_helpers.append(helper)
            return helper

        self.helper_factory = mock.patch.object(live, "Helpers", side_effect=helpers)
        self.helper_factory.start()
        self.addCleanup(self.helper_factory.stop)

    def provider_args(self):
        return live.arguments(
            [
                "provider",
                "--run-real-provider",
                "--config",
                str(self.config_file),
                "--receipt-directory",
                str(self.receipt),
            ]
        )

    def test_command_retains_private_evidence_and_resume_has_no_new_dispatch(self):
        code, summary = live.execute(self.provider_args())
        self.assertEqual(code, 0)
        self.assertEqual(summary["provider_acceptance"], "passed")
        self.assertEqual(summary["dispatch_attempts_in_this_controller"], 1)
        before = {
            name: (self.receipt / name).read_bytes()
            for name in ("intent.json", "prepared.json")
        }
        args = live.arguments(
            ["resume", "--observe", "--receipt-directory", str(self.receipt)]
        )
        code, summary = live.execute(args)
        self.assertEqual(code, 0)
        self.assertEqual(summary["category"], "provider_recovery")
        self.assertEqual(summary["dispatch_attempts_in_this_controller"], 0)
        self.assertEqual(
            [name for name, _ in self.created_helpers[-1].calls],
            ["resolve_operation", "read_result_chunk"],
        )
        self.assertEqual(
            before, {name: (self.receipt / name).read_bytes() for name in before}
        )
        self.assertEqual(len(list(self.receipt.glob("attempt-*/summary.json"))), 2)
        self.assertTrue(all(owner.released for owner in self.owners))
        for path in self.receipt.rglob("*.json"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_resume_cancel_reports_recovery_cleanup_never_provider_acceptance(self):
        self.assertEqual(live.execute(self.provider_args())[0], 0)
        args = live.arguments(
            ["resume", "--cancel", "--receipt-directory", str(self.receipt)]
        )
        code, summary = live.execute(args)
        self.assertEqual(code, 0)
        self.assertEqual(summary["result"], "cleanup_confirmed")
        self.assertEqual(summary["provider_acceptance"], "unverified")
        self.assertNotIn(
            "dispatch_task", [name for name, _ in self.created_helpers[-1].calls]
        )
        self.assertNotIn(
            "prepare_dispatch", [name for name, _ in self.created_helpers[-1].calls]
        )

    def test_resume_observe_failure_never_mutates_the_original_task(self):
        self.assertEqual(live.execute(self.provider_args())[0], 0)
        self.helper_failure = "resolve_operation"
        args = live.arguments(
            ["resume", "--observe", "--receipt-directory", str(self.receipt)]
        )
        code, summary = live.execute(args)
        self.assertEqual(code, 1)
        self.assertFalse(summary["task_cleanup_confirmed"])
        self.assertEqual(
            [name for name, _ in self.created_helpers[-1].calls], ["resolve_operation"]
        )
        self.assertTrue(summary["helpers_joined"])

    def test_resume_observe_interruption_never_mutates_the_original_task(self):
        self.assertEqual(live.execute(self.provider_args())[0], 0)
        original = live.LiveRun.verify_existing

        def interrupted(run):
            run.interruptions.request(signal.SIGINT, None)
            return original(run)

        args = live.arguments(
            ["resume", "--observe", "--receipt-directory", str(self.receipt)]
        )
        with mock.patch.object(live.LiveRun, "verify_existing", interrupted):
            code, summary = live.execute(args)
        self.assertEqual(code, 1)
        self.assertEqual(summary["reason"], "interrupted")
        self.assertFalse(summary["task_cleanup_confirmed"])
        self.assertEqual(self.created_helpers[-1].calls, [])
        self.assertTrue(summary["helpers_joined"])

    def test_resume_cancel_failure_preserves_automatic_same_identity_cleanup(self):
        self.assertEqual(live.execute(self.provider_args())[0], 0)
        original = live.private_json(self.receipt / "prepared.json")
        self.helper_failure = "cancel_task"
        args = live.arguments(
            ["resume", "--cancel", "--receipt-directory", str(self.receipt)]
        )
        code, summary = live.execute(args)
        self.assertEqual(code, 1)
        self.assertFalse(summary["task_cleanup_confirmed"])
        self.assertEqual(
            self.created_helpers[-1].calls,
            [
                (
                    "cancel_task",
                    {
                        "operation_id": original["operation_id"],
                        "cancellation_id": original["cancellation_id"],
                    },
                ),
                (
                    "cancel_task",
                    {
                        "operation_id": original["operation_id"],
                        "cancellation_id": original["cancellation_id"],
                    },
                ),
            ],
        )

    def test_setup_failure_releases_lease_and_directory_owner(self):
        with mock.patch.object(
            live, "Helpers", side_effect=RuntimeError("PRIVATE_SETUP_CANARY")
        ):
            code, summary = live.execute(self.provider_args())
        self.assertEqual(code, 1)
        self.assertFalse(summary["helpers_joined"])
        self.assertTrue(all(owner.released for owner in self.owners))
        lease = live.ReceiptLease(self.receipt)
        lease.close()
        self.assertNotIn("PRIVATE_SETUP_CANARY", json.dumps(summary))

    def test_public_failure_never_prints_raw_errors_or_configuration(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                live,
                "execute",
                side_effect=RuntimeError("PRIVATE_TOKEN_CANARY " + str(self.base)),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(
                live.main(
                    [
                        "provider",
                        "--run-real-provider",
                        "--config",
                        str(self.config_file),
                        "--receipt-directory",
                        str(self.receipt),
                    ]
                ),
                1,
            )
        self.assertNotIn("PRIVATE_TOKEN_CANARY", output.getvalue())
        self.assertNotIn(str(self.base), output.getvalue())

    def test_success_summary_excludes_token_config_prompt_and_result_bytes(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                live.main(
                    [
                        "provider",
                        "--run-real-provider",
                        "--config",
                        str(self.config_file),
                        "--receipt-directory",
                        str(self.receipt),
                    ]
                ),
                0,
            )
        self.assertNotIn("PRIVATE_TOKEN_CANARY", output.getvalue())
        self.assertNotIn(str(self.base), output.getvalue())
        self.assertNotIn("GATEWAY_PROVIDER_ACCEPTANCE_", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["provider_acceptance"], "passed")

    def test_concurrent_resume_refuses_before_creating_sdk_owner(self):
        self.assertEqual(live.execute(self.provider_args())[0], 0)
        before = len(self.created_helpers)
        lease = live.ReceiptLease(self.receipt)
        try:
            args = live.arguments(
                ["resume", "--observe", "--receipt-directory", str(self.receipt)]
            )
            self.assertEqual(live.execute(args)[0], 1)
        finally:
            lease.close()
        self.assertEqual(len(self.created_helpers), before)

    def test_signal_during_helper_cleanup_cannot_report_provider_success(self):
        original = live.LiveRun.cleanup

        def cleanup(run):
            run.interruptions.request(2, None)
            return original(run)

        with mock.patch.object(live.LiveRun, "cleanup", cleanup):
            code, summary = live.execute(self.provider_args())
        self.assertEqual(code, 1)
        self.assertEqual(summary["result"], "failed")
        self.assertEqual(summary["provider_acceptance"], "unverified")

    def test_signal_during_owner_release_cannot_leave_a_private_pass_receipt(self):
        interruptions = live.Interruptions()
        owner_type = live.load_owners.return_value[0]
        original = owner_type.release

        def release(owner):
            result = original(owner)
            interruptions.request(2, None)
            return result

        with (
            mock.patch.object(live, "Interruptions", return_value=interruptions),
            mock.patch.object(owner_type, "release", release),
        ):
            code, summary = live.execute(self.provider_args())
        self.assertEqual(code, 1)
        self.assertEqual(summary["provider_acceptance"], "unverified")
        saved = live.private_json(next(self.receipt.glob("attempt-*/summary.json")))
        self.assertEqual(saved["result"], "failed")

    def test_resume_never_turns_unjoined_prior_helper_into_overall_pass(self):
        self.helper_joined = False
        self.assertEqual(live.execute(self.provider_args())[0], 1)
        self.helper_joined = True
        args = live.arguments(
            ["resume", "--observe", "--receipt-directory", str(self.receipt)]
        )
        code, summary = live.execute(args)
        self.assertEqual(code, 1)
        self.assertEqual(summary["provider_acceptance"], "unverified")
        self.assertEqual(summary["prior_helper_cleanup"], "unverified")
        self.assertTrue(summary["canonical_execution_closure"])

    def test_missing_prior_controller_summary_blocks_pass_but_not_same_id_cancel(self):
        self.assertEqual(live.execute(self.provider_args())[0], 0)
        next(self.receipt.glob("attempt-*/summary.json")).unlink()
        args = live.arguments(
            ["resume", "--cancel", "--receipt-directory", str(self.receipt)]
        )
        code, summary = live.execute(args)
        self.assertEqual(code, 1)
        self.assertEqual(summary["prior_helper_cleanup"], "unverified")
        self.assertTrue(summary["task_cleanup_confirmed"])
        self.assertEqual(
            [name for name, _ in self.created_helpers[-1].calls],
            ["cancel_task", "resolve_operation"],
        )

    def test_directory_release_failure_still_closes_lease_and_restores_handlers(self):
        owner_type = live.load_owners.return_value[0]
        previous = {
            number: signal.getsignal(number)
            for number in (signal.SIGINT, signal.SIGTERM)
        }
        with mock.patch.object(
            owner_type, "release", side_effect=RuntimeError("PRIVATE_RELEASE_CANARY")
        ):
            code, summary = live.execute(self.provider_args())
        self.assertEqual(code, 1)
        self.assertTrue(summary["helpers_joined"])
        self.assertFalse(summary["controller_cleanup_confirmed"])
        self.assertEqual(summary["reason"], "controller_cleanup_unverified")
        self.assertNotIn("PRIVATE_RELEASE_CANARY", json.dumps(summary))
        for number, handler in previous.items():
            self.assertIs(signal.getsignal(number), handler)
        lease = live.ReceiptLease(self.receipt)
        lease.close()

    def test_handler_restore_attempts_every_handler_after_one_failure(self):
        interruptions = live.Interruptions()
        interruptions.previous = {
            signal.SIGINT: signal.SIG_DFL,
            signal.SIGTERM: signal.SIG_DFL,
        }
        with mock.patch.object(
            live.signal, "signal", side_effect=[RuntimeError("restore failed"), None]
        ) as restore:
            with self.assertRaisesRegex(live.Failure, "controller_cleanup_unverified"):
                interruptions.restore()
        self.assertEqual(restore.call_count, 2)


if __name__ == "__main__":
    unittest.main()
