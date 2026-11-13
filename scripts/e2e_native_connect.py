#!/usr/bin/env python3
"""Actual local Native connect/workspace acceptance with bounded literal fixtures.

Uses e2e_local's existing process, fixture and canonical cleanup owners. No
browser approval, desktop service, installed provider or Cloud proof is implied.
All executable paths are explicit; installed executable contents are not read.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import uuid

from e2e_local import (
    DelegateRoot,
    Harness,
    Interruptions,
    arguments,
    require,
    require_requested_closure,
)


class NativeConnectHarness(Harness):
    success_result = "native_connect_passed"
    expected_fixture_attempts = 3

    def __init__(self, args, interruptions):
        super().__init__(args, interruptions)
        self.embedded_connector_invocations = []
        self.summary.update(
            category="actual local Gateway and Native embedded connector with literal Pi fixture",
            browser_authorization="unverified",
            desktop_service_acceptance="unverified",
            snapshot_restore_acceptance="not part of this scenario",
            fixture_tasks_planned=3,
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
                "--provider",
                "pi:json",
                "--max-budget-seconds",
                "30",
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
            "two_token_enrollments_native_connect_dynamic_projects"
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
                "--provider",
                "pi:json",
                "--model",
                "openai/gpt-4.1",
                "--max-budget",
                "30s",
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

    def task_scenarios(self):
        self.brief_canary = "E2E_PRIVATE_BRIEF_" + uuid.uuid4().hex
        for root in self.roots:
            prepared = self.prepare(
                root, "Return the fixture sentence. " + self.brief_canary
            )
            handle = {"operation_id": prepared["operation_id"]}
            self.mcp("dispatch_task", handle)
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
            self.mcp("dispatch_task", handle)
            require(
                root.invocations() == 1, "same-operation retry executed another task"
            )
        self.assert_fixture_attempts(2)
        self.summary["stages"].append(
            "both_selected_projects_results_closure_duplicate_retry"
        )

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


def main(argv=None):
    os.umask(0o077)
    interruptions = Interruptions()
    previous = {
        number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
    }
    for number in previous:
        signal.signal(number, interruptions.handle)
    try:
        args = arguments(argv)
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
