"""Shared immutable evidence values for CLI and imported acceptance consumers."""

from dataclasses import dataclass
from pathlib import Path


class ProofFailure(RuntimeError):
    """A bounded acceptance invariant failed; private resources stay retained."""


class CleanupUnconfirmed(ProofFailure):
    """An owned process reports cleanup whose completion is still unknown."""


@dataclass(frozen=True)
class FixtureExecutionSnapshot:
    root: Path
    nonce: str
    context: tuple[str, str]
    executions: int
    waiters: frozenset[tuple[str, int, int]]


@dataclass(frozen=True)
class FixtureLeaseObservation:
    task_id: str
    pid: int
    path: Path
    identity: tuple[int, int]
