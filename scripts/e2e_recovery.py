"""Explicit same-registry recovery proof using the local harness's owned roots.

Gateway owns reservations and recovery progress. Delegate owns task creation and
closure. This module uses their public interfaces and never edits task records.
"""

import base64
import hashlib
import http.client
import json
import socket
import uuid

from e2e_local import (
    FixtureLeaseObservation,
    context_guard,
    require,
    require_requested_closure,
)


MAX_RESPONSE = 65536


def private_request(socket_path, path, value):
    """One bounded HTTP request on the fixture-owned private Unix listener."""
    encoded = json.dumps(value).encode()
    require(len(encoded) <= MAX_RESPONSE, "private request exceeds bound")
    connection = http.client.HTTPConnection("localhost", timeout=35)
    owned = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        owned.settimeout(35)
        owned.connect(str(socket_path))
        connection.sock = owned
        connection.request(
            "POST", path, body=encoded, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        try:
            data = response.read(MAX_RESPONSE + 1)
            require(len(data) <= MAX_RESPONSE, "private response exceeds bound")
            require(
                response.getheader("Content-Type", "").split(";", 1)[0]
                == "application/json",
                "private response media type changed",
            )
            value = json.loads(data)
            require(isinstance(value, dict), "private response is not an object")
            return response.status, value
        finally:
            response.close()
    finally:
        connection.close()
        owned.close()


def require_denial(status, value):
    require(
        status == 409
        and value
        in (
            {"code": "pending", "committed": False},
            {"code": "conflict", "committed": False},
        ),
        "recovery gate did not return an explicit uncommitted denial",
    )


def root_input(root):
    return {
        "device_id": root.device,
        "project_alias": root.alias,
        "root_guard": context_guard(root.context["root_token"]),
        "project_guard": context_guard(root.context["project_token"]),
    }


def task_key(root, task):
    return {
        "device_id": root.device,
        "root_guard": context_guard(root.context["root_token"]),
        "task_id": task,
    }


def native_guards(root, origin_file):
    return [
        "--expected-root",
        root.context["root_token"],
        "--expected-project",
        root.context["project_token"],
        "--expected-origin",
        origin_file,
    ]


def require_same_live_fixture(before, after):
    require(
        isinstance(before, FixtureLeaseObservation)
        and isinstance(after, FixtureLeaseObservation)
        and before == after,
        "Gateway restart changed or omitted the validated fixture lease identity",
    )


def require_active_operation(value, root, prepared):
    require(isinstance(value, dict), "active operation response is not an object")
    require(
        value.get("operation_id") == prepared["operation_id"]
        and value.get("task_id") == prepared["task_id"]
        and value.get("device_id") == root.device
        and value.get("project_alias") == root.alias
        and value.get("reserved") is True
        and value.get("delivery") in ("possible_send", "resolved"),
        "Gateway restart changed the active operation binding or reservation",
    )
    observation = value.get("observation")
    require(
        isinstance(observation, dict)
        and observation.get("kind") == "existing"
        and observation.get("execution_closure") is None,
        "Gateway restart did not preserve an existing task without closure",
    )


class RecoveryScenario:
    def __init__(self, harness):
        self.h = harness
        self.recovery = "fixture-restore-" + uuid.uuid4().hex

    def run(self):
        h = self.h
        require(len(h.roots) == 2, "recovery requires the two-root fixture roster")
        require(self.invocations() == 2, "recovery requires the two-task baseline")
        h.assert_fixture_attempts(2)
        attributed = self.reserved_attributed()
        h.assert_fixture_attempts(3)
        unattributed = self.native_unattributed()
        require(self.invocations() == 4, "recovery fixture attempt count changed")
        h.assert_fixture_attempts(4)
        self.start_recovery()
        h.admin(
            "register-routing-recovery-roster",
            {"recovery_id": self.recovery, "device_ids": [r.device for r in h.roots]},
        )
        for root in h.roots:
            h.admin(
                "register-recovery-root",
                {
                    "recovery_id": self.recovery,
                    "device_id": root.device,
                    "root_guard": root_input(root)["root_guard"],
                },
            )
        h.admin(
            "seal-recovery",
            {"recovery_id": self.recovery, "expected_destinations": len(h.roots)},
        )
        self.replace_credentials("recovery_only", 2)
        self.inventory()
        root = h.roots[0]
        self.assert_reserved(root, attributed["key"]["task_id"], True)
        self.assert_reserved(root, unattributed["task_id"], False)
        self.denial("/v1/recovery/finish", {"recovery_id": self.recovery})
        self.denial(
            "/v1/enrollment-tokens",
            {"device_id": root.device, "mode": "regular", "generation": 3},
        )
        self.drain(root, attributed["key"]["task_id"], attributed["origin"])
        self.drain(root, unattributed["task_id"], unattributed["origin"])
        h.closed_operations.add(attributed["origin"]["operation_id"])
        progress = self.progress()
        require(
            all(row["missing_mappings"] == 0 for row in progress["destinations"]),
            "verified closure did not discharge recovery mapping debt",
        )
        self.replace_credentials("regular", 3)
        for root in h.roots:
            h.grant_root(root)
        self.reopen()
        h.admin("finish-recovery", {"recovery_id": self.recovery})
        final = self.progress()
        require(
            final["status"] == "finished"
            and all(row["stage"] == "ready" for row in final["destinations"]),
            "explicit recovery did not finish with every root ready",
        )
        self.verify_execution_readiness()
        self.verify_public_result()
        hidden = h.mcp(
            "resolve_operation",
            {"operation_id": unattributed["origin"]["operation_id"]},
            failure=True,
        )
        require(
            hidden["code"] == "not_found", "unattributed task gained public identity"
        )
        require(self.invocations() == 4, "recovery or retry launched another fixture")
        h.assert_fixture_attempts(4)
        h.summary["fixture_tasks_executed"] = 4
        h.summary["recovery"] = {
            "kind": "same_registry_explicit_recovery",
            "recovery_id": self.recovery,
            "attributed_task_id": attributed["key"]["task_id"],
            "unattributed_task_id": unattributed["task_id"],
            "status": final["status"],
            "fixture_attempts": 4,
        }
        h.summary["stages"].append("real_process_inventory_import_drain_reopen_finish")

    def invocations(self):
        return sum(root.invocations() for root in self.h.roots)

    def start_recovery(self):
        h = self.h
        h.stop_process(h.gateway)
        session = h.command(
            h.args.gateway,
            [
                "begin-recovery",
                "--database",
                h.gateway_config["database"],
                "--recovery-id",
                self.recovery,
            ],
            h.env,
        )
        require(
            session.get("recovery_id") == self.recovery
            and session.get("kind") == "restore",
            "offline recovery did not confirm the original restore intent",
        )
        h.start_gateway()
        h.check_auth()

    def reserved_attributed(self):
        h, root = self.h, self.h.roots[0]
        root.acquire_fixture_gate()
        fixture_before = root.fixture_execution_snapshot()
        prepared = h.prepare(root, "DELEGATE_PRIVATE_SILENCE_WAIT")
        h.mcp("dispatch_task", {"operation_id": prepared["operation_id"]})
        with root.fixture_execution_lease(fixture_before, prepared["task_id"]) as (
            live,
            lease,
        ):
            view = self.assert_reserved(root, prepared["task_id"], True)
            self.restart_while_active(root, prepared, fixture_before, live, lease)
        h.stop_process(h.gateway)
        origin_file = h.input_file(view["origin"])
        spec = self.native_spec(
            root, prepared["task_id"], origin_file, view.get("spec_sha256")
        )
        cancellation = h.operations[prepared["operation_id"]]["cancellation_id"]
        root.command(
            [
                "cancel",
                prepared["task_id"],
                "--id",
                cancellation,
                *native_guards(root, origin_file),
                "--expected-spec-sha256",
                spec,
            ],
            expected={0, 1},
        )
        self.native_closure(root, prepared["task_id"], origin_file)
        closure = h.acceptance.supervisor.read_managed_closure(
            root.state, tuple(root.tasks)
        )
        require_requested_closure(closure, prepared["task_id"])
        root.release_fixture_gate()
        return view

    def restart_while_active(self, root, prepared, fixture_before, live, lease):
        h = self.h
        require_same_live_fixture(live, live)
        require(
            live.task_id == prepared["task_id"], "fixture lease belongs to another task"
        )
        expected_executions = fixture_before.executions + 1
        require(
            root.invocations() == expected_executions,
            "active restart execution count changed",
        )
        h.assert_fixture_attempts(3)
        lease.assert_live()
        h.stop_process(h.gateway)
        # A joined Gateway process is not proof of continued native execution.
        lease.assert_live()
        h.start_gateway()
        h.until(
            lambda: self.connected(root),
            10,
            "same-device reconnect after active restart",
        )
        after = FixtureLeaseObservation(
            prepared["task_id"], lease.pid, lease.path, lease.identity
        )
        require_same_live_fixture(live, after)
        lease.assert_live()
        require(
            root.invocations() == expected_executions,
            "restart changed fixture execution count",
        )
        handle = {"operation_id": prepared["operation_id"]}
        observed = h.mcp("resolve_operation", handle)
        require_active_operation(observed, root, prepared)
        # A non-prepared response permits only the existing-operation dispatch
        # retry; Gateway's dispatch contract cannot start a second admission.
        repeated = h.mcp("dispatch_task", handle)
        require_active_operation(repeated, root, prepared)
        lease.assert_live()
        require(
            root.invocations() == expected_executions,
            "restart/retry executed another fixture",
        )
        h.assert_fixture_attempts(3)
        h.summary["restart_while_active"] = {
            "operation_id": prepared["operation_id"],
            "task_id": prepared["task_id"],
            "device_id": root.device,
            "provider_pid": live.pid,
            "fifo_identity": list(live.identity),
            "fixture_attempts": 3,
        }
        h.summary["stages"].append("same_registry_gateway_restart_during_live_task")

    def native_spec(self, root, task, origin_file, known_spec=None):
        origin = json.loads(origin_file.read_text())
        response = root.command(
            ["resolve", task, *native_guards(root, origin_file)], expected={0, 1}
        )
        connector = response.get("connector") if isinstance(response, dict) else None
        require(
            isinstance(connector, dict), "native resolution omitted connector evidence"
        )
        receipt = connector.get("receipt")
        require(isinstance(receipt, dict), "native resolution omitted task receipt")
        require(
            not response.get("error")
            and connector.get("resolution") == "existing"
            and receipt.get("task_id") == task
            and receipt.get("origin") == origin
            and receipt.get("root_token") == root.context["root_token"]
            and receipt.get("project_token") == root.context["project_token"],
            "native resolution returned another frozen task binding",
        )
        spec = receipt.get("spec_sha256")
        require(
            isinstance(spec, str)
            and len(spec) == 64
            and all(value in "0123456789abcdef" for value in spec),
            "native resolution omitted a valid specification digest",
        )
        require(
            known_spec is None or known_spec == spec,
            "native specification differs from known receipt",
        )
        return spec

    def native_closure(self, root, task, origin_file):
        origin = json.loads(origin_file.read_text())

        def observe():
            response = root.command(
                ["resolve", task, *native_guards(root, origin_file)], expected={0, 1}
            )
            connector = response.get("connector") or {}
            if not connector.get("execution_closure"):
                return None
            receipt = connector["receipt"]
            require(
                receipt["task_id"] == task
                and receipt["origin"] == origin
                and receipt["root_token"] == root.context["root_token"]
                and receipt["project_token"] == root.context["project_token"],
                "native closure returned another frozen task binding",
            )
            return connector

        return self.h.until(observe, 45, "public native canonical task closure")

    def native_unattributed(self):
        h, root = self.h, self.h.roots[0]
        context = root.command(
            [
                "context",
                "inspect",
                "--cwd",
                root.workspace,
                "--gateway-id",
                h.gateway_id,
            ]
        )["connector"]
        origin = {
            "gateway_id": h.gateway_id,
            "admission_generation": context["origin_barrier"]["generation"],
            "operation_id": uuid.uuid4().hex,
            "principal_ref": "fixture-local-import",
            "gateway_request_sha256": hashlib.sha256(
                b"local-import-request"
            ).hexdigest(),
        }
        origin_file = h.input_file(origin)
        task = uuid.uuid4().hex
        root.tasks.append(task)
        brief = root.base / "import-brief.txt"
        with brief.open("x", encoding="utf-8") as stream:
            brief.chmod(0o600)
            stream.write("Return the controlled fixture sentence.")
        root.command(
            [
                "dispatch",
                "--id",
                task,
                "--provider",
                "pi:json",
                "--brief",
                brief,
                "--cwd",
                root.workspace,
                "--permission",
                "read-only",
                "--budget",
                "29.5s",
                "--model",
                "openai/gpt-4.1",
                "--expected-root",
                root.context["root_token"],
                "--expected-project",
                root.context["project_token"],
                "--origin",
                origin_file,
            ]
        )
        observation = self.native_closure(root, task, origin_file)
        require(observation["receipt"]["origin"] == origin, "native origin changed")
        return {"task_id": task, "origin": origin}

    def assert_reserved(self, root, task, attributed):
        key = task_key(root, task)
        view = self.h.admin("get-administrative-task", key)
        require(
            view["key"] == key
            and view["attributed"] is attributed
            and view["reserved"],
            "recovery reservation classification or identity changed",
        )
        return view

    def replace_credentials(self, mode, generation):
        h = self.h
        joins = tuple(h.stop_process(process) for process in h.connectors)
        for root in h.roots:
            output = root.base / f"enrollment-{mode}-{generation}.json"
            h.admin(
                "issue-enrollment-token",
                {"device_id": root.device, "mode": mode, "generation": generation},
                output=output,
            )
            h.command(
                h.args.gateway,
                [
                    "connector",
                    "enroll",
                    "--config",
                    root.connector_config_path,
                    "--token-file",
                    output,
                    "--replace-existing",
                ],
                root.env,
            )
            h.start_connector(root)
        for root in h.roots:
            self.establish_routing_coverage(root, generation, joins)
        for root in h.roots:
            h.until(
                lambda: self.connected(root), 20, "recovery current connector proof"
            )

    def routing_target(self, root, generation):
        status, value = private_request(
            self.h.admin_socket,
            "/v1/routing/drain-target",
            {"device_id": root.device},
        )
        if (status, value.get("code")) in (
            (403, "forbidden"),
            (404, "not_found"),
            (409, "conflict"),
            (409, "pending"),
        ):
            # A newly issued credential can precede its first fenced peer.
            require(
                value == {"code": value["code"], "committed": False},
                "routing target pending response changed its closed contract",
            )
            return None
        require(status == 200, "routing target was not available")
        credential, connection = value.get("credential"), value.get("connection")
        require(
            isinstance(credential, dict)
            and isinstance(credential.get("epoch"), str)
            and bool(credential["epoch"])
            and isinstance(connection, dict)
            and isinstance(connection.get("boot_epoch"), str)
            and bool(connection["boot_epoch"])
            and type(connection.get("counter")) is int
            and connection["counter"] > 0,
            "routing target omitted its authenticated identity",
        )
        require(
            value.get("device_id") == root.device
            and value.get("recovery_id") == self.recovery
            and credential.get("device_id") == root.device
            and type(credential.get("generation")) is int
            and credential["generation"] == generation
            and isinstance(value.get("process_boot"), str)
            and len(value["process_boot"]) == 32
            and all(char in "0123456789abcdef" for char in value["process_boot"])
            and type(value.get("blocked")) is bool
            and type(value.get("covered")) is bool,
            "routing target did not match the enrolled fixture device",
        )
        return value

    def establish_routing_coverage(self, root, generation, joins):
        h = self.h
        require(
            joins and all(type(code) is int and code == 0 for code in joins),
            "prior connector CLI owners have not joined",
        )
        target = h.until(
            lambda: self.routing_target(root, generation),
            20,
            "fenced current routing target",
        )
        confirmation = {
            "device_id": root.device,
            "recovery_id": self.recovery,
            "expected_credential": dict(target["credential"]),
            "expected_process_boot": target["process_boot"],
            "expected_connection": dict(target["connection"]),
            "scope": "all_prior_controls",
            "prior_cli_joins_confirmed": True,
        }
        result = h.admin("attest-routing-drained", confirmation)
        require(
            (result.get("disposition"), result.get("committed"))
            in (("drained", True), ("already_satisfied", False)),
            "routing drain did not establish its explicit disposition",
        )

        def ready():
            current = self.routing_target(root, generation)
            if current is None:
                return None
            require(
                current["credential"] == confirmation["expected_credential"]
                and current["process_boot"] == confirmation["expected_process_boot"],
                "routing confirmation changed its authenticated owner",
            )
            if (
                result["disposition"] == "drained"
                and current["connection"] == confirmation["expected_connection"]
            ):
                return None
            return current if current["covered"] and not current["blocked"] else None

        current = h.until(ready, 20, "joined routing census coverage")
        # Discard the first observation, then repeat the original confirmation
        # across the reconnect without rebinding its expected connection.
        repeated = h.admin("attest-routing-drained", confirmation)
        require(
            repeated.get("disposition") == "already_satisfied"
            and repeated.get("committed") is False
            and repeated.get("connection_status") == "unchanged"
            and repeated.get("target", {}).get("connection") == current["connection"],
            "routing confirmation retry changed or drained the current connection",
        )

    def connected(self, root):
        status, value = private_request(
            self.h.admin_socket, "/v1/projects/refresh", root_input(root)
        )
        if (status, value.get("code")) in (
            (503, "device_offline"),
            (503, "device_not_ready"),
            (409, "pending"),
        ):
            require(
                value == {"code": value["code"], "committed": False},
                "connection retry response changed its closed contract",
            )
            self.h.summary.setdefault("recovery_connection_pending", []).append(
                {"status": status, "code": value["code"]}
            )
            return False
        require(status == 200, "unexpected recovery connection response")
        require(
            value["alias"] == root.alias
            and value["context"]
            == {
                "root": root_input(root)["root_guard"],
                "project": root_input(root)["project_guard"],
            },
            "recovery connector returned another context",
        )
        return True

    def progress(self):
        value = self.h.admin(
            "recovery-progress", {"recovery_id": self.recovery, "limit": 20}
        )
        require(value.get("next") is None, "two-root recovery unexpectedly paginated")
        require(len(value["destinations"]) == 2, "recovery root roster changed")
        return value

    def advance(self, root):
        route = root_input(root)
        route.pop("project_guard")
        return self.h.admin("advance-recovery", {"recovery_id": self.recovery, **route})

    def inventory(self):
        for root in self.h.roots:
            for _ in range(6):
                progress = self.advance(root)
                if progress["stage"] in ("needs_mapping", "needs_regular_credential"):
                    require(
                        progress.get("completeness_sha256"), "inventory proof missing"
                    )
                    break
            else:
                require(False, "bounded native inventory did not finish")

    def denial(self, path, value):
        status, response = private_request(self.h.admin_socket, path, value)
        require_denial(status, response)
        self.h.summary.setdefault("recovery_gate_denials", []).append(
            {"path": path, "status": status, "code": response["code"]}
        )

    def drain(self, root, task, origin):
        view = self.h.admin(
            "drain-administrative-task",
            {**task_key(root, task), "project_alias": root.alias, "action": "resolve"},
        )
        require(
            view["key"] == task_key(root, task)
            and view["origin"] == origin
            and not view["reserved"]
            and view["observation"]["kind"] == "terminal"
            and view["observation"].get("closure"),
            "administrative resolve failed canonical identity-bound closure",
        )

    def reopen(self):
        for root in self.h.roots:
            for _ in range(6):
                progress = self.advance(root)
                if progress["stage"] == "ready":
                    require(
                        progress["reopen_recorded"], "native reopen receipt missing"
                    )
                    break
            else:
                require(False, "bounded native reopen did not become ready")

    def verify_public_result(self):
        h = self.h
        handle = {"operation_id": h.baseline_prepared["operation_id"]}
        repeated = h.mcp("dispatch_task", handle)
        require(
            repeated["task_id"] == h.baseline_prepared["task_id"],
            "post-recovery retry changed the task identity",
        )
        chunk = h.mcp(
            "read_result_chunk",
            {
                **handle,
                "descriptor": h.baseline_descriptor,
                "offset": 0,
                "limit": 65536,
            },
        )
        require(
            base64.b64decode(chunk["data_base64"], validate=True)
            == b"private supervisor acceptance passed",
            "post-recovery accepted result bytes changed",
        )

    def verify_execution_readiness(self):
        # OriginReopen invalidates the dated project capability. Refresh it only
        # after every root has reopened and the whole recovery has finished.
        for root in self.h.roots:
            self.h.admin("refresh-project", root_input(root))

            def ready():
                value = self.h.mcp(
                    "get_capabilities",
                    {"device_id": root.device, "project_alias": root.alias},
                )
                require(
                    value.get("device_id") == root.device
                    and value.get("project_alias") == root.alias
                    and type(value.get("delegate_ready")) is bool
                    and type(value.get("online")) is bool,
                    "post-recovery capability changed its selected device or contract",
                )
                return value["online"] and value["delegate_ready"]

            self.h.until(ready, 10, "post-recovery dated capability publication")
