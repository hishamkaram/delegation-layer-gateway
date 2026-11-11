"""Pure validated data contracts for opt-in live acceptance tooling.

No filesystem, process, network, clock mutation or execution ownership lives here.
"""

from dataclasses import dataclass
from datetime import datetime
import ipaddress
from pathlib import Path
import re
from urllib.parse import urlsplit

MAX_JSON = 1 << 20
MAX_HELPER_OUTPUT = 2 << 20
MAX_RESULT = 1 << 20
CHUNK_BYTES = 65536
IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
CLOSURE_KINDS = frozenset(
    {
        "registered-native",
        "registered-recovered",
        "legacy-previous-boot",
        "unregistered-recovered",
        "never-started",
    }
)


class Failure(RuntimeError):
    """A fixed local failure kind; never a raw remote error or user value."""


def require(condition, code):
    if not condition:
        raise Failure(code)


def absolute_path(value):
    require(type(value) is str and 0 < len(value) <= 4096, "invalid_path")
    path = Path(value)
    require(
        path.is_absolute()
        and str(path) == value
        and ".." not in path.parts
        and not any(ord(char) < 32 for char in value),
        "invalid_path",
    )
    return path


def https_url(value, *, endpoint=False):
    require(type(value) is str and len(value) <= 2048, "invalid_https_url")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        require(
            value.startswith("https://")
            and parsed.scheme == "https"
            and host is not None
            and parsed.username is None
            and parsed.password is None
            and "?" not in value
            and "#" not in value
            and "%" not in value
            and "\\" not in value
            and not any(ord(char) <= 32 or ord(char) >= 127 for char in value)
            and not parsed.netloc.endswith(":")
            and (port is None or 1 <= port <= 65535),
            "invalid_https_url",
        )
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise Failure("system_trust_requires_dns")
        require(
            host == host.lower()
            and len(host) <= 253
            and all(DNS_LABEL.fullmatch(label) for label in host.split("."))
            and parsed.netloc == host + (f":{port}" if port is not None else ""),
            "invalid_dns_authority",
        )
        require(not endpoint or parsed.path == "/mcp", "invalid_mcp_path")
        return value
    except ValueError as error:
        raise Failure("invalid_https_url") from error


def identifier(value):
    require(type(value) is str and IDENTIFIER.fullmatch(value), "invalid_identifier")
    return value


def selection(value):
    require(
        type(value) is str
        and 0 < len(value.encode()) <= 256
        and not any(ord(char) < 32 for char in value),
        "invalid_selection",
    )
    return value


def timestamp(value):
    require(
        type(value) is str
        and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})",
            value,
        ),
        "invalid_time",
    )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise Failure("invalid_time") from error
    require(parsed.tzinfo is not None, "invalid_time")
    return parsed


@dataclass(frozen=True)
class Config:
    endpoint: str
    helper: Path
    token_file: Path
    native_repository: Path
    mode: str
    targets: tuple[tuple[str, str], ...]
    provider: str = ""
    budget_seconds: int = 0
    model: str | None = None
    effort: str | None = None
    expected_issuer: str = ""

    @classmethod
    def parse(cls, value, mode):
        require(type(value) is dict, "invalid_configuration")
        common = {"endpoint", "helper", "token_file", "native_repository"}
        if mode == "provider":
            required = common | {
                "device_id",
                "project_alias",
                "provider",
                "permission",
                "budget_seconds",
                "max_tasks",
            }
            require(
                required <= set(value) <= required | {"model", "effort"},
                "invalid_configuration",
            )
            require(value["permission"] == "read-only", "invalid_permission")
            require(
                type(value["max_tasks"]) is int and value["max_tasks"] == 1,
                "invalid_task_limit",
            )
            budget = value["budget_seconds"]
            require(type(budget) is int and 1 <= budget <= 3600, "invalid_task_budget")
            targets = (
                (identifier(value["device_id"]), identifier(value["project_alias"])),
            )
            return cls(
                https_url(value["endpoint"], endpoint=True),
                absolute_path(value["helper"]),
                absolute_path(value["token_file"]),
                absolute_path(value["native_repository"]),
                mode,
                targets,
                identifier(value["provider"]),
                budget,
                selection(value["model"]) if "model" in value else None,
                selection(value["effort"]) if "effort" in value else None,
            )
        require(
            mode == "preflight"
            and set(value) == common | {"targets", "expected_issuer"},
            "invalid_configuration",
        )
        require(
            type(value["targets"]) is list and len(value["targets"]) == 2,
            "invalid_targets",
        )
        targets = []
        for target in value["targets"]:
            require(
                type(target) is dict and set(target) == {"device_id", "project_alias"},
                "invalid_target",
            )
            targets.append(
                (identifier(target["device_id"]), identifier(target["project_alias"]))
            )
        require(targets[0][0] != targets[1][0], "distinct_devices_required")
        return cls(
            https_url(value["endpoint"], endpoint=True),
            absolute_path(value["helper"]),
            absolute_path(value["token_file"]),
            absolute_path(value["native_repository"]),
            mode,
            tuple(targets),
            expected_issuer=https_url(value["expected_issuer"]),
        )

    def document(self):
        value = {
            "endpoint": self.endpoint,
            "helper": str(self.helper),
            "token_file": str(self.token_file),
            "native_repository": str(self.native_repository),
        }
        if self.mode == "preflight":
            return {
                **value,
                "expected_issuer": self.expected_issuer,
                "targets": [
                    {"device_id": device, "project_alias": project}
                    for device, project in self.targets
                ],
            }
        value.update(
            {
                "device_id": self.targets[0][0],
                "project_alias": self.targets[0][1],
                "provider": self.provider,
                "permission": "read-only",
                "budget_seconds": self.budget_seconds,
                "max_tasks": 1,
            }
        )
        for key, selected in (("model", self.model), ("effort", self.effort)):
            if selected is not None:
                value[key] = selected
        return value

    def prepare_request(self, brief: str) -> dict[str, str | int]:
        """Project only public prepare fields; private configuration stays local."""
        require(self.mode == "provider", "invalid_configuration")
        request = {
            "device_id": self.targets[0][0],
            "project_alias": self.targets[0][1],
            "provider": self.provider,
            "permission": "read-only",
            "budget_seconds": self.budget_seconds,
            "brief": brief,
        }
        if self.model is not None:
            request["model"] = self.model
        if self.effort is not None:
            request["effort"] = self.effort
        return request


def require_capability(value, config, target, *, dispatch):
    require(
        type(value) is dict
        and value.get("device_id") == target[0]
        and value.get("project_alias") == target[1],
        "capability_destination_changed",
    )
    require(
        value.get("online") is True and value.get("delegate_ready") is True,
        "device_not_ready",
    )
    if not dispatch:
        return
    require(
        value.get("task_read_allowed") is True
        and value.get("task_cancel_allowed") is True,
        "cleanup_authority_missing",
    )
    providers = value.get("providers")
    require(type(providers) is list and len(providers) <= 64, "invalid_providers")
    selected = [
        row
        for row in providers
        if type(row) is dict and row.get("provider") == config.provider
    ]
    require(len(selected) == 1, "selected_provider_unavailable")
    provider = selected[0]
    require(
        provider.get("dispatch_allowed") is True
        and type(provider.get("permissions")) is list
        and "read-only" in provider["permissions"]
        and type(provider.get("max_budget_seconds")) is int
        and config.budget_seconds <= provider["max_budget_seconds"],
        "dispatch_ceiling_denied",
    )
    for key, requested in (("models", config.model), ("efforts", config.effort)):
        if requested is not None:
            require(
                type(provider.get(key)) is list and requested in provider[key],
                "selection_unavailable",
            )


def prepared_binding(value, config, cancellation, intent_digest, *, fresh, now=None):
    require(
        type(value) is dict and set(value) == {"operation_id", "task_id", "expires_at"},
        "invalid_prepared_response",
    )
    operation = identifier(value["operation_id"])
    require(
        type(value["task_id"]) is str and HEX32.fullmatch(value["task_id"]),
        "invalid_task_id",
    )
    expiry = timestamp(value["expires_at"])
    require(
        not fresh or (now is not None and expiry > now), "prepared_operation_expired"
    )
    return {
        "schema_version": 1,
        "operation_id": operation,
        "task_id": value["task_id"],
        "expires_at": value["expires_at"],
        "device_id": config.targets[0][0],
        "project_alias": config.targets[0][1],
        "cancellation_id": cancellation,
        "intent_sha256": intent_digest,
    }


def descriptor(value):
    require(
        type(value) is dict and set(value) == {"sha256", "length"},
        "invalid_result_descriptor",
    )
    require(
        type(value["sha256"]) is str
        and HEX64.fullmatch(value["sha256"])
        and type(value["length"]) is int
        and 0 <= value["length"] <= MAX_RESULT,
        "invalid_result_descriptor",
    )
    return dict(value)


def operation_observation(value, binding):
    require(
        type(value) is dict
        and all(
            value.get(key) == binding[key]
            for key in ("operation_id", "task_id", "device_id", "project_alias")
        ),
        "operation_binding_changed",
    )
    if "cancellation_id" in value:
        require(
            value["cancellation_id"] == binding["cancellation_id"],
            "cancellation_binding_changed",
        )
    require(type(value.get("reserved")) is bool, "invalid_operation_reservation")
    observation = value.get("observation")
    if observation is None:
        return None
    require(
        type(observation) is dict
        and observation.get("kind") in {"existing", "terminal", "refused", "unknown"},
        "invalid_observation",
    )
    timestamp(observation.get("observed_at"))
    closure = observation.get("execution_closure")
    if closure is not None:
        require(
            type(closure) is dict
            and set(closure) == {"kind", "reference_sha256"}
            and closure["kind"] in CLOSURE_KINDS
            and type(closure["reference_sha256"]) is str
            and HEX64.fullmatch(closure["reference_sha256"])
            and observation["kind"] == "terminal",
            "invalid_execution_closure",
        )
    if "result" in observation:
        descriptor(observation["result"])
        require(
            observation["kind"] in {"existing", "terminal"},
            "invalid_result_observation",
        )
    return observation
