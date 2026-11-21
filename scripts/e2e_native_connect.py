#!/usr/bin/env python3
"""Actual local Native connect/workspace acceptance with bounded literal fixtures.

Uses e2e_local's existing process, fixture and canonical cleanup owners. No
browser approval, desktop service, installed provider or Cloud proof is implied.
All executable paths are explicit; installed executable contents are not read.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time
import uuid

from e2e_local import (
    DelegateRoot,
    Harness,
    Interruptions,
    arguments,
    require,
    require_requested_closure,
    context_guard,
)

FILESYSTEM_RANGE_BYTES = 17


def preparation_identity(value):
    identity = dict(value)
    # Go may return a local offset before persistence and UTC after lookup.
    # Compare the same exact instant without discarding nanosecond precision.
    expiry = re.fullmatch(
        r"(.{19})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})", identity["expires_at"]
    )
    require(expiry is not None, "preparation expiry is not RFC3339Nano")
    whole = datetime.fromisoformat(expiry[1] + expiry[3].replace("Z", "+00:00"))
    require(whole.tzinfo is not None, "preparation expiry has no timezone")
    identity["expires_at"] = (
        whole.astimezone(timezone.utc),
        int((expiry[2] or "").ljust(9, "0")),
    )
    return identity


class NativeConnectHarness(Harness):
    success_result = "native_connect_passed"
    expected_fixture_attempts = 3

    def __init__(self, args, interruptions):
        super().__init__(args, interruptions)
        self.embedded_connector_invocations = []
        # The existing directory owner retains temp fixtures until every owned
        # process and canonical Native lifetime has joined successfully.
        self.filesystem_temp_roots = []
        self.filesystem_canary = ("E2E_REQUESTED_FILE_" + uuid.uuid4().hex).encode()
        self.summary.update(
            category="actual local Gateway and Native embedded connector with literal Pi fixture",
            browser_authorization="unverified",
            desktop_service_acceptance="unverified",
            snapshot_restore_acceptance="not part of this scenario",
            fixture_tasks_planned=3,
            preparation_contract=(
                "compact_v4_scope_relative"
                if self.compact_routes
                else "legacy_project_alias"
            ),
            continuation_process_acceptance="unverified: literal Pi fixture has no saved/reloaded provider checkpoint",
        )

    def start_gateway(self):
        self.gateway_config["device_login"] = {
            "native_client_id": "local-native-connect-client",
            "device_wss_url": "wss://"
            + self.gateway_config["device_address"]
            + "/device",
        }
        self.gateway_config_path = self.input_file(self.gateway_config)
        super().start_gateway()

    def start_connectors(self):
        self.command(
            self.args.gateway,
            [
                "users",
                "allow",
                "--config",
                self.gateway_config_path,
                "--subject",
                "local-e2e-subject",
                "--max-devices",
                "2",
            ],
        )
        for index in range(2):
            root = DelegateRoot(self, f"d{index + 1}", workspace_constrained=True)
            self.roots.append(root)
            root.start()
            token = root.base / "native-enrollment.json"
            self.sequence += 1
            self.processes.run(
                f"native-enrollment-{self.sequence:04d}",
                [
                    self.args.gateway,
                    "devices",
                    "enrollment-token",
                    "--config",
                    self.gateway_config_path,
                    "--subject",
                    "local-e2e-subject",
                    "--name",
                    f"native-fixture-{index + 1}",
                    "--output-file",
                    token,
                ],
                self.base,
                timeout=40,
                environment=self.env,
            )
            root.device = json.loads(token.read_text())["device_id"]
            self.start_native_connector(root, token)
            self.until(
                lambda: self.device_online(root.device),
                20,
                "Native embedded connector authenticated handshake",
            )
            approved = root.command(
                ["gateway", "workspace", "allow", root.workspace, "--alias", "work"]
            )["workspace"]
            root.approval = approved
            root.project_directory = root.workspace / "nested"
            root.project_directory.mkdir(mode=0o700)
            workspace = self.until(
                lambda: self.advertised_workspace(root.device, approved["id"]),
                10,
                "approved workspace publication",
            )
            self.filesystem_scenarios(root, workspace["workspace_id"])
            root.selection = {
                "scope_id": workspace["workspace_id"],
                "relative_path": "nested",
            }
            if self.compact_routes:
                root.context = root.command(
                    ["context", "inspect", "--cwd", root.project_directory]
                )["connector"]
                self.until(
                    lambda: self.mcp(
                        "get_capabilities",
                        {"device_id": root.device, "selection": root.selection},
                    )["delegate_ready"],
                    10,
                    "scope-relative Native capability",
                )
                self.assert_no_project_pins(root)
            else:
                root.resolution = {
                    "device_id": root.device,
                    "workspace_id": workspace["workspace_id"],
                    "request_id": uuid.uuid4().hex,
                    "relative_path": "nested",
                }
                resolved = self.until(
                    lambda: self.resolve_selected(root.resolution),
                    25,
                    "same-identity dynamic project resolution",
                )
                root.resolved = resolved
                root.alias = resolved["project_alias"]
                require(
                    root.alias == root.resolution["request_id"],
                    "resolution identity changed",
                )
                require(
                    self.mcp("resolve_project", root.resolution) == resolved,
                    "completed resolution replay changed its immutable binding",
                )
                root.context = root.command(
                    ["context", "inspect", "--cwd", root.project_directory]
                )["connector"]
                self.until(
                    lambda: self.mcp(
                        "get_capabilities",
                        {"device_id": root.device, "project_alias": root.alias},
                    )["delegate_ready"],
                    10,
                    "targeted project capability",
                )

        require(
            {item["device_id"] for item in self.mcp("list_devices", {})["devices"]}
            == {root.device for root in self.roots},
            "owned discovery changed selected devices",
        )
        self.summary["stages"].append(
            "two_token_enrollments_native_connect_scope_selection_no_pins"
            if self.compact_routes
            else "two_token_enrollments_native_connect_dynamic_projects"
        )

    @property
    def compact_routes(self):
        return bool(getattr(self.args, "compact_routes", False))

    def assert_no_project_pins(self, root):
        preview = root.command(["gateway", "upgrade", "--preview"])
        require(not preview.get("failure"), "profile preview failed")
        profile = preview["upgrade"]["profile"]
        require(
            preview["upgrade"]["phase"] == "preview"
            and profile["from_version"] == profile["to_version"] == 3
            and profile["pins"] == 0,
            "compact preparation created a local pin or changed profile schema",
        )
        inventory = self.mcp("list_workspaces", {"device_id": root.device})
        require(
            inventory["project_budget"]["used"] == 0,
            "compact preparation created a local pin",
        )
        projects = self.mcp("list_projects", {"device_id": root.device})
        require(
            projects["projects"] == [] and not projects.get("next_cursor"),
            "compact preparation created a Gateway project",
        )

    def prepare_selected(self, request):
        self.pace_mcp()
        response = self.helper("mcp", self.mcp_input("prepare_dispatch", request))
        if not response.get("isError"):
            return self.consume_mcp(response)
        failure = self.consume_mcp(response, failure=True)
        require(
            failure.get("request_id") == request["request_id"],
            "lost compact preparation request identity",
        )
        require(
            failure["code"] in {"pending", "device_not_ready", "device_offline"},
            "unexpected compact preparation failure",
        )
        return None

    def prepare(self, root, brief):
        if not self.compact_routes:
            return super().prepare(root, brief)
        request = {
            "device_id": root.device,
            "request_id": uuid.uuid4().hex,
            "selection": dict(root.selection),
            "brief": brief,
            "native_options": {
                "provider": "pi:json",
                "permission": "read-only",
                "budget": "30s",
                "model": "openai/gpt-4.1",
            },
        }
        prepared = self.until(
            lambda: self.prepare_selected(request),
            25,
            "same-identity compact preparation",
        )
        root.tasks.append(prepared["task_id"])
        self.operations[prepared["operation_id"]] = {
            "cancellation_id": uuid.uuid4().hex,
            "task_id": prepared["task_id"],
            "prepare_request": request,
        }
        replay = self.mcp("prepare_dispatch", request)
        require(
            preparation_identity(replay) == preparation_identity(prepared),
            "compact preparation replay changed immutable identity",
        )
        self.assert_no_project_pins(root)
        return prepared

    def assert_compact_receipt(self, root, prepared):
        # Observe Native's actual receipt through its public control CLI. The
        # process proof never constructs or edits task, Origin or closure data.
        inspected = root.command(
            ["context", "inspect", "--gateway-id", self.gateway_id]
        )["connector"]
        generation = inspected["origin_barrier"]["generation"]
        cursor, seen = "", set()
        for _ in range(len(root.tasks) + 1):
            page = root.command(
                [
                    "origin",
                    "inventory",
                    "--gateway-id",
                    self.gateway_id,
                    "--generation",
                    generation,
                    "--expected-root",
                    root.context["root_token"],
                    "--cursor",
                    cursor,
                    "--limit",
                    "1",
                    "--include-workspace-constraint",
                ]
            )["connector"]["inventory"]
            require(
                len(page["entries"]) <= 1, "Native inventory ignored the bounded page"
            )
            for entry in page["entries"]:
                if entry["task_id"] == prepared["task_id"]:
                    self.check_compact_receipt(root, prepared, entry["receipt"])
                    return
            following = page.get("next_cursor", "")
            if page["complete"]:
                break
            require(
                following and following not in seen,
                "Native inventory cursor did not advance",
            )
            seen.add(following)
            cursor = following
        require(False, "Native inventory omitted the compact task receipt")

    def check_compact_receipt(self, root, prepared, receipt):
        request = self.operations[prepared["operation_id"]]["prepare_request"]
        origin = receipt["origin"]
        encoded = origin["binding"]
        binding = json.loads(encoded)
        require(
            binding["v"] == 4
            and binding["kind"] == "dispatch"
            and binding["gateway"] == self.gateway_id
            and binding["device"] == root.device
            and binding["operation"] == prepared["operation_id"]
            and binding["task"] == prepared["task_id"] == receipt["task_id"]
            and binding["project_alias"] == prepared["operation_id"],
            "Native receipt changed compact operation identity",
        )
        route = binding["route"]
        require(
            route["request_id"] == request["request_id"]
            and route["input_format"] == "dispatch-v1"
            and {"scope_id": route["scope_id"], "relative_path": route["relative_path"]}
            == request["selection"],
            "Native receipt changed compact preparation selection",
        )
        constraint = receipt["workspace_constraint"]
        require(
            receipt["root_token"] == root.context["root_token"]
            and binding["context"]
            == {
                "root": context_guard(receipt["root_token"]),
                "project": context_guard(receipt["project_token"]),
            }
            and route["workspace_guard"] == context_guard(constraint["token"])
            and constraint["relative_project"] == request["selection"]["relative_path"]
            and binding["brief"]
            == {
                "present": True,
                "sha256": hashlib.sha256(request["brief"].encode()).hexdigest(),
            }
            and receipt["brief_sha256"] == binding["brief"]["sha256"]
            and origin["gateway_request_sha256"]
            == hashlib.sha256(encoded.encode()).hexdigest(),
            "Native receipt changed immutable context, brief or Origin commitment",
        )
        require(
            receipt["execution_options"]["provider"] == "pi:json",
            "Native observed execution facts were lost",
        )
        self.summary.setdefault("compact_receipts", []).append(
            {
                "device_id": root.device,
                "operation_id": prepared["operation_id"],
                "task_id": prepared["task_id"],
                "request_id": request["request_id"],
                "request_version": binding["v"],
                "request_kind": binding["kind"],
                "scope_id": route["scope_id"],
                "relative_path": route["relative_path"],
                "spec_sha256": receipt["spec_sha256"],
            }
        )

    def require_read_only_state(self, root):
        # Public preview reads the current existing profile without applying a
        # migration or consulting the dated WSS inventory for its pin count.
        preview = root.command(["gateway", "upgrade", "--preview"])
        require(not preview.get("failure"), "profile preview failed")
        require(preview["upgrade"]["phase"] == "preview", "profile preview applied")
        profile = preview["upgrade"]["profile"]
        require(
            profile["from_version"] == profile["to_version"] == 3
            and profile["pins"] == 0,
            "read created a local pin or changed the current profile schema",
        )
        inventory = self.mcp("list_workspaces", {"device_id": root.device})
        require(not inventory.get("scope_discovery_error"), "scope discovery failed")
        require(inventory["project_budget"]["used"] == 0, "read created a local pin")
        projects = self.mcp("list_projects", {"device_id": root.device})
        require(
            projects["projects"] == [] and not projects.get("next_cursor"),
            "read created a Gateway project",
        )
        operations = self.mcp("list_operations", {})
        require(
            operations["operations"] == [] and not operations.get("next_cursor"),
            "read created a Gateway operation",
        )
        closure = self.acceptance.supervisor.read_managed_closure(root.state, ())
        require(closure["tasks"] == {}, "read created a Native task")
        self.assert_fixture_attempts(0)
        return inventory

    def directory_pages(self, selection, expected_names):
        entries = []
        cursors = set()
        cursor = ""
        # An independent fixture entry count bounds observations, including a
        # broken peer that repeats a nonempty cursor or never reaches EOF.
        for _ in range(len(expected_names) + 1):
            page = self.mcp(
                "list_directory", {**selection, "cursor": cursor, "limit": 2}
            )["list"]
            require(0 < len(page["entries"]) <= 2, "directory page did not advance")
            entries.extend(page["entries"])
            following = page.get("next_cursor", "")
            require(page["eof"] == (following == ""), "directory EOF disagreed")
            if page["eof"]:
                break
            require(following not in cursors, "directory cursor repeated")
            cursors.add(following)
            cursor = following
        else:
            require(False, "directory pagination exceeded fixture bound")
        names = [base64.b64decode(row["name_base64"], validate=True) for row in entries]
        require(names == sorted(expected_names), "directory names changed or omitted")
        require(len(cursors) > 0, "directory fixture did not exercise pagination")
        return {name: row for name, row in zip(names, entries, strict=True)}

    def read_exact_file(self, selection, expected):
        received = bytearray()
        version = ""
        for _ in range(len(expected) // FILESYSTEM_RANGE_BYTES + 2):
            part = self.mcp(
                "read_file",
                {
                    **selection,
                    "offset": len(received),
                    "limit": FILESYSTEM_RANGE_BYTES,
                    "expected_version": version,
                },
            )["read"]
            require(part["offset"] == len(received), "file offset changed")
            data = base64.b64decode(part["data_base64"], validate=True)
            require(
                len(data) <= FILESYSTEM_RANGE_BYTES,
                "file range exceeded requested limit",
            )
            require(bool(data) or part["eof"], "file range did not advance")
            if version:
                require(part["version"] == version, "file version changed")
            version = part["version"]
            received.extend(data)
            require(part["next_offset"] == len(received), "file next offset changed")
            if part["eof"]:
                break
        else:
            require(False, "file range exceeded fixture bound")
        require(bytes(received) == expected, "requested file bytes changed")

    def filesystem_file_bytes(self):
        return self.filesystem_canary + b"\nexact requested bytes\x00\xff\n"

    def filesystem_scenarios(self, root, workspace_id):
        inventory = self.require_read_only_state(root)
        if sys.platform.startswith("linux"):
            require(
                {(scope["id"], scope["kind"]) for scope in inventory["scopes"]}
                == {(workspace_id, "workspace"), ("system-shared-temp", "shared_temp")},
                "Linux whole temporary scope missing or unexpected",
            )
        # Approval already exists. These descendants must become visible without
        # another allow/resolve call; the harness base owns their eventual cleanup.
        directory = root.workspace / "browse-after-approval"
        directory.mkdir(mode=0o700)
        expected = self.filesystem_file_bytes()
        unusual = b".requested-\xff.bin"
        (directory / os.fsdecode(unusual)).write_bytes(expected)
        (directory / "plain.txt").write_bytes(b"ordinary\n")
        git = directory / ".git"
        git.mkdir(mode=0o700)
        head = b"ref: refs/heads/fixture\n"
        (git / "HEAD").write_bytes(head)
        escape = directory / "escape"
        escape.symlink_to(root.base / "outside-workspace")
        (root.base / "outside-workspace").write_bytes(b"must not be returned\n")
        selection = {
            "device_id": root.device,
            "scope_id": workspace_id,
            "relative_path": directory.name,
        }
        rows = self.directory_pages(
            selection, {unusual, b"plain.txt", b".git", b"escape"}
        )
        require("name" not in rows[unusual], "non-UTF-8 name became lossy text")
        self.read_exact_file(
            {
                "device_id": root.device,
                "scope_id": workspace_id,
                "relative_path_base64": rows[unusual]["relative_path_base64"],
            },
            expected,
        )
        inspected = self.mcp("inspect_git", selection)["inspect"]["git"]
        require(
            inspected["status"] == "candidate"
            and inspected["kind"] == "worktree"
            and inspected["marker"] == "dot_git"
            and inspected["head_shape"] == "symbolic"
            and base64.b64decode(inspected["head_base64"], validate=True) == head,
            "structural Git evidence changed or claimed validation",
        )
        for relative, code in (
            ("../outside-workspace", "invalid_request"),
            (directory.name + "/escape", "outside_scope"),
        ):
            failure = self.mcp(
                "read_file", {**selection, "relative_path": relative}, failure=True
            )
            require(failure["code"] == code, "filesystem escape was not denied")
        if sys.platform.startswith("linux"):
            temporary = self.ownership.create(
                "filesystem automatic temp fixture",
                Path("/tmp") / ("gateway-filesystem-" + uuid.uuid4().hex),
                Path("/tmp"),
            )
            self.filesystem_temp_roots.append(temporary)
            (temporary.directory / "requested.bin").write_bytes(expected)
            (temporary.directory / ".hidden").write_bytes(b"hidden\n")
            (temporary.directory / "third").write_bytes(b"third\n")
            temporary_selection = {
                "device_id": root.device,
                "scope_id": "system-shared-temp",
                "relative_path": temporary.directory.name,
            }
            self.directory_pages(
                temporary_selection, {b"requested.bin", b".hidden", b"third"}
            )
            self.read_exact_file(
                {
                    **temporary_selection,
                    "relative_path": temporary.directory.name + "/requested.bin",
                },
                expected,
            )
        self.require_read_only_state(root)
        self.summary.setdefault("filesystem_observations", []).append(
            {
                "device_id": root.device,
                "fresh_profile_pin_count": 0,
                "advertised_project_budget_used": 0,
                "gateway_project_count": 0,
                "gateway_operation_count": 0,
                "native_task_count": 0,
                "fixture_attempts": 0,
                "automatic_linux_whole_tmp": sys.platform.startswith("linux"),
            }
        )
        self.summary["stages"].append(
            "native_filesystem_exact_bytes_pages_git_escape_no_pin_or_task"
        )

    def start_native_connector(self, root, token):
        # This plan identifies owned intake in the shared registry even when a
        # post-Start fault prevents callback handoff or the normal return.
        argv = tuple(
            str(value)
            for value in (
                self.args.delegate,
                "--root",
                root.state,
                "gateway",
                "connect",
                self.public,
                "--token-file",
                token,
                "--foreground",
                "--ca",
                self.material["ca_file"],
                "--json",
            )
        )
        self.embedded_connector_invocations.append(argv)
        self.processes.start(
            "native-gateway-connect",
            argv,
            root.workspace,
            environment=root.env,
            on_spawned=self.connectors.append,
        )

    def connector_intake_faults(self):
        reports = []
        observed_invocations = set()
        for process in self.processes.entries:
            invocation = tuple(process.argv)
            if invocation not in self.embedded_connector_invocations:
                continue
            observed_invocations.add(invocation)
            result = process.poll()
            if result is not None and result["exit_code"] != 0:
                self.record_process_failure(process, result["exit_code"])
            if (
                result is None
                or result.get("natural_wait") is not True
                or result["exit_code"] != 0
            ):
                reports.append(
                    {
                        "stage": "native_connector_intake_unconfirmed",
                        "pid": process.pid,
                        "exit_code": result["exit_code"] if result else None,
                        "direct_wait_confirmed": result is not None,
                    }
                )
        for pending in self.processes.pending(exclude=self.processes.entries):
            invocation = tuple(pending["argv"])
            if invocation in self.embedded_connector_invocations:
                observed_invocations.add(invocation)
                reports.append({"stage": "native_connector_start_unconfirmed"})
        for invocation in self.embedded_connector_invocations:
            if invocation not in observed_invocations:
                # A registration fault may follow Start. Missing registry
                # evidence cannot prove the planned child was never created.
                reports.append({"stage": "native_connector_owner_unconfirmed"})
        return reports

    def device_online(self, device):
        return any(
            row["device_id"] == device and row["online"]
            for row in self.mcp("list_devices", {})["devices"]
        )

    def advertised_workspace(self, device, workspace):
        rows = self.mcp("list_workspaces", {"device_id": device})["workspaces"]
        return next((row for row in rows if row["workspace_id"] == workspace), None)

    def resolve_selected(self, request):
        self.pace_mcp()
        response = self.helper("mcp", self.mcp_input("resolve_project", request))
        if not response.get("isError"):
            return self.consume_mcp(response)
        error = self.consume_mcp(response, failure=True)
        require(
            error.get("request_id") == request["request_id"],
            "lost resolution correlation",
        )
        require(
            error["code"] in {"pending", "device_not_ready", "device_offline"},
            "unexpected resolution failure",
        )
        return None

    def read_filesystem_metrics(self):
        # This is the test-owned private admin endpoint, not a new listener or
        # background observation owner. Both response and socket close here.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(self.admin_socket))
            connection.sendall(
                b"GET /v1/metadata/metrics HTTP/1.1\r\nHost: unix\r\n"
                b"Connection: close\r\n\r\n"
            )
            with http.client.HTTPResponse(connection) as response:
                response.begin()
                require(response.status == 200, "private metrics request failed")
                data = response.read((1 << 20) + 1)
        require(len(data) <= 1 << 20, "private metrics exceeded evidence bound")
        require(b"gateway_" in data, "private metrics body missing")
        return data

    def check_filesystem_diagnostics(self):
        # Derive expected ranges from fixture bytes, independently of returned
        # data. A logger can leak individual ranges without the whole marker.
        expected = self.filesystem_file_bytes()
        ranges = tuple(
            expected[offset : offset + FILESYSTEM_RANGE_BYTES]
            for offset in range(0, len(self.filesystem_canary), FILESYSTEM_RANGE_BYTES)
        )
        forbidden = tuple(
            value
            for fragment in (self.filesystem_canary, *ranges)
            for value in (fragment, base64.b64encode(fragment))
        )
        paths = [path for path in (self.base / "audit").glob("*") if path.is_file()]
        audit_files = len(paths)
        streams = 0
        for process in self.processes.entries:
            if (
                tuple(process.argv[:2]) == (str(self.args.gateway), "serve")
                or tuple(process.argv) in self.embedded_connector_invocations
            ):
                paths.extend((process.stdout_path, process.stderr_path))
                streams += 2
        # SDK helper responses are authorized requested data and deliberately
        # excluded. Only product diagnostics/audit and the bounded metrics body
        # are subject to this assertion; no content scanning enters the product.
        for path in paths:
            data = path.read_bytes()
            require(
                all(value not in data for value in forbidden),
                "requested file canary escaped product diagnostics",
            )
        if hasattr(self, "filesystem_metrics"):
            require(
                all(value not in self.filesystem_metrics for value in forbidden),
                "requested file canary escaped metrics",
            )
        self.summary["filesystem_canary_observation"] = {
            "audit_files": audit_files,
            "product_log_streams": streams,
            "metrics_bytes": len(getattr(self, "filesystem_metrics", b"")),
            "canary_range_count": len(ranges),
            "canary_pattern_count": len(forbidden),
            "authorized_helper_response_captures": "excluded requested data",
        }

    def check_canaries(self):
        super().check_canaries()
        self.filesystem_metrics = self.read_filesystem_metrics()
        (self.base / "filesystem-metrics.prom").write_bytes(self.filesystem_metrics)
        self.check_filesystem_diagnostics()
        self.summary["stages"].append(
            "requested_file_canary_absent_product_logs_audit_metrics"
        )

    def _finish_owned(self):
        closed = super()._finish_owned()
        temporary_roots = getattr(self, "filesystem_temp_roots", ())
        if not temporary_roots:
            return closed
        # No fixture directory is deleted until the inherited owner has proved
        # intake joins, canonical Native closure and all direct process waits.
        if closed:
            try:
                self.check_filesystem_diagnostics()
            except Exception as error:
                self.summary["result"] = "failed"
                self.summary["filesystem_diagnostic_failure"] = type(error).__name__
            faults = []
            deadline = time.monotonic() + 10
            for directory in reversed(temporary_roots):
                try:
                    self.acceptance.directories.remove_owned_directory(
                        directory, deadline
                    )
                except Exception as error:
                    faults.append(
                        {
                            "stage": "filesystem_temp_cleanup",
                            "kind": type(error).__name__,
                        }
                    )
            self.summary["filesystem_temp_cleanup_confirmed"] = not faults
            self.summary["cleanup_errors"].extend(faults)
            closed = not faults
            self.summary["cleanup_confirmed"] = closed
        else:
            self.summary["filesystem_temp_cleanup_confirmed"] = False
        # The inherited owner already created this private summary. Reconcile
        # only the additional owned directory cleanup result in the same file.
        (self.base / "summary.json").write_text(json.dumps(self.summary) + "\n")
        return closed

    def task_scenarios(self):
        self.brief_canary = "E2E_PRIVATE_BRIEF_" + uuid.uuid4().hex
        for index, root in enumerate(self.roots):
            held = index == 1
            if held:
                root.acquire_fixture_gate()
                before = root.fixture_execution_snapshot()
            prepared = self.prepare(
                root,
                (
                    "DELEGATE_PRIVATE_SILENCE_WAIT "
                    if held
                    else "Return the fixture sentence. "
                )
                + self.brief_canary,
            )
            handle = {"operation_id": prepared["operation_id"]}
            # Admission retains the approved path. Its next launch selects the
            # replacement currently at that path, without resolving a new handle.
            self.replace_project_directory(root, ancestor=not held)
            self.mcp("dispatch_task", handle)
            if held:
                root.wait_fixture_execution(before, prepared["task_id"])
                # An already running provider keeps its cwd. Removing its visible
                # path must not invalidate the eventual accepted result.
                self.replace_project_directory(root, ancestor=False)
                root.release_fixture_gate()
            final = self.await_operation(prepared["operation_id"], result=True)
            descriptor = final["observation"]["result"]
            chunk = self.mcp(
                "read_result_chunk",
                {**handle, "descriptor": descriptor, "offset": 0, "limit": 65536},
            )
            expected = b"private supervisor acceptance passed"
            require(
                base64.b64decode(chunk["data_base64"], validate=True) == expected,
                "result bytes changed",
            )
            require(
                descriptor["sha256"] == hashlib.sha256(expected).hexdigest(),
                "result digest changed",
            )
            require(descriptor["length"] == len(expected), "result length changed")
            if self.compact_routes:
                self.assert_compact_receipt(root, prepared)
            else:
                require(
                    self.mcp("resolve_project", root.resolution) == root.resolved,
                    "same-path replacement changed the original project binding",
                )
            self.mcp("dispatch_task", handle)
            require(
                root.invocations() == 1, "same-operation retry executed another task"
            )
        self.assert_fixture_attempts(2)
        self.summary["stages"].append(
            "both_selected_projects_results_closure_duplicate_retry"
        )
        self.summary["stages"].append(
            "same_path_ancestor_and_leaf_replacement_before_launch_and_during_execution"
        )

    def replace_project_directory(self, root, *, ancestor):
        directory = root.workspace if ancestor else root.project_directory
        original = directory.stat(follow_symlinks=False)
        retired = directory.with_name(directory.name + "-retired-" + uuid.uuid4().hex)
        directory.rename(retired)
        directory.mkdir(mode=0o700)
        if ancestor:
            root.project_directory.mkdir(mode=0o700)
        current = directory.stat(follow_symlinks=False)
        require(
            (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino),
            "replacement did not create a distinct directory",
        )
        # Retain the old directory under the same test resource owner until
        # task closure and process joins; cleanup never deletes an active cwd.

    def recovery_scenarios(self):
        root = self.roots[0]
        root.acquire_fixture_gate()
        before = root.fixture_execution_snapshot()
        prepared = self.prepare(root, "DELEGATE_PRIVATE_SILENCE_WAIT")
        handle = {"operation_id": prepared["operation_id"]}
        self.mcp("dispatch_task", handle)
        root.wait_fixture_execution(before, prepared["task_id"])
        self.restart_gateway()
        self.until(lambda: self.device_online(root.device), 15, "same-device reconnect")
        self.mcp("resolve_operation", handle)
        removed = root.command(
            [
                "gateway",
                "workspace",
                "remove",
                root.approval["id"],
                "--expected-revision",
                str(root.approval["revision"]),
            ]
        )["workspace"]
        require(not removed["enabled"], "workspace removal did not narrow policy")
        if self.compact_routes:
            original = self.operations[prepared["operation_id"]]["prepare_request"]
            require(
                preparation_identity(self.mcp("prepare_dispatch", original))
                == preparation_identity(prepared),
                "removed approval changed compact preparation replay",
            )
            self.assert_compact_receipt(root, prepared)
        else:
            require(
                self.mcp("resolve_project", root.resolution) == root.resolved,
                "removal invalidated retained immutable resolution",
            )
        self.mcp("get_task_status", handle)
        cancellation = self.operations[prepared["operation_id"]]["cancellation_id"]
        cancel = {**handle, "cancellation_id": cancellation}
        self.mcp("cancel_task", cancel)
        self.await_operation(prepared["operation_id"])
        closure = self.acceptance.supervisor.read_managed_closure(
            root.state, tuple(root.tasks)
        )
        require_requested_closure(closure, prepared["task_id"])
        self.mcp("cancel_task", cancel)
        self.assert_fixture_attempts(3)
        root.release_fixture_gate()
        self.summary["stages"].append(
            "restart_reconnect_retained_identity_removed_workspace_passive_cancel"
        )
        self.check_canaries()


def configure_arguments(parser):
    parser.add_argument(
        "--compact-routes",
        action="store_true",
        help="prove scope-relative compact v4 Native dispatch; default retains the legacy project-alias scenario",
    )


def main(argv=None):
    os.umask(0o077)
    interruptions = Interruptions()
    previous = {
        number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
    }
    for number in previous:
        signal.signal(number, interruptions.handle)
    try:
        args = arguments(argv, configure_parser=configure_arguments)
        require(
            not args.capture_native,
            "Native connect requires direct candidate execution",
        )
        return NativeConnectHarness(args, interruptions).run()
    except Exception as error:
        print(
            json.dumps(
                {
                    "result": "fixture_setup_failed",
                    "failure_kind": type(error).__name__,
                    "cleanup_confirmed": False,
                }
            ),
            flush=True,
        )
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
