#!/usr/bin/env python3
"""Pinned, repository-local Go tooling adapted from Delegate's quality floor."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"
VERSIONS = {"golangci-lint": "2.14.0", "gofumpt": "0.12.0", "govulncheck": "1.8.0"}
# Official release archive digests, inherited from Delegate 0eed5e28.
LINT_ARCHIVES = {
    (
        "linux",
        "amd64",
    ): "ab90aeb7b066f92a33415b638a50fe5344bbb75a0d32ad30cc248d88f81032ab",
    (
        "linux",
        "arm64",
    ): "ee7ec5f3453d15ddf106fae5a4d6c71737712348a979d1fe9cd52ec7ea299bae",
    (
        "darwin",
        "amd64",
    ): "a5667c1c3536be1740133213e1e822bfb8f0d98ea12903174d6d5f635e4ed68d",
    (
        "darwin",
        "arm64",
    ): "5ef5f36a7147e91dc58ef9ef4d11bb7bad5ead0c76eb6c01327a73c641d1dcc3",
}


def run(args: list[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        args, cwd=ROOT, env=env, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def compiler() -> None:
    pin = (ROOT / ".go-version").read_bytes()
    if not re.fullmatch(
        rb"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\n", pin
    ):
        raise RuntimeError(".go-version must contain exactly one stable X.Y.Z line")
    if os.environ.get("GOTOOLCHAIN", "local") != "local":
        raise RuntimeError(
            "Set GOTOOLCHAIN=local and select the installed pinned compiler on PATH"
        )
    actual = run(["go", "version"]).split()
    expected = "go" + pin.decode().strip()
    if len(actual) < 3 or actual[2] != expected:
        raise RuntimeError(
            f"Install/select {expected} on PATH; observed {' '.join(actual)}"
        )
    compiler_version = run(["go", "tool", "compile", "-V"]).strip()
    if compiler_version != "compile version " + expected:
        raise RuntimeError(
            f"GOROOT selects {compiler_version}; unset it or select the matching {expected} GOROOT"
        )


def verify() -> None:
    compiler()
    probes = {
        "golangci-lint": ["version"],
        "gofumpt": ["-version"],
        "govulncheck": ["-version"],
    }
    for name, args in probes.items():
        binary = BIN / name
        if not binary.is_file():
            raise RuntimeError(f"Missing {binary}; run make tools")
        output = run([str(binary), *args])
        expected = VERSIONS[name]
        if not re.search(rf"(?<![\d.])v?{re.escape(expected)}(?![\d.])", output):
            raise RuntimeError(f"{name} must be {expected}; run make tools")


def install() -> None:
    compiler()
    BIN.mkdir(exist_ok=True)
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)
    target = (system, arch)
    if target not in LINT_ARCHIVES:
        raise RuntimeError(f"Unsupported tool archive platform {system}/{machine}")
    version = VERSIONS["golangci-lint"]
    stem = f"golangci-lint-{version}-{system}-{arch}"
    url = f"https://github.com/golangci/golangci-lint/releases/download/v{version}/{stem}.tar.gz"
    # Integrity applies to the distribution archive, never installed executable bytes.
    with urllib.request.urlopen(url, timeout=60) as response:
        archive = response.read(128 * 1024 * 1024 + 1)
    if len(archive) > 128 * 1024 * 1024:
        raise RuntimeError("Tool archive exceeds 128 MiB")
    if hashlib.sha256(archive).hexdigest() != LINT_ARCHIVES[target]:
        raise RuntimeError("Official golangci-lint archive integrity mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        member = bundle.getmember(stem + "/golangci-lint")
        if not member.isfile() or not 0 < member.size <= 256 * 1024 * 1024:
            raise RuntimeError("Invalid golangci-lint archive member")
        source = bundle.extractfile(member)
        if source is None:
            raise RuntimeError("Missing golangci-lint archive member")
        with source:
            data = source.read(member.size + 1)
        if len(data) != member.size:
            raise RuntimeError("Incomplete golangci-lint archive member")
    destination = BIN / "golangci-lint"
    destination.write_bytes(data)
    destination.chmod(0o755)
    tool_env = dict(os.environ, GOBIN=str(BIN), GOTOOLCHAIN="local")
    for module in [
        "mvdan.cc/gofumpt@v0.12.0",
        "golang.org/x/vuln/cmd/govulncheck@v1.8.0",
    ]:
        run(["go", "install", module], env=tool_env)
    verify()


def format_check() -> None:
    verify()
    # Git owns source membership, including new contributor files. Ignored
    # dependency checkouts must not inherit Gateway's formatting policy.
    inventory = run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "*.go",
        ]
    )
    files = sorted(
        {name for name in inventory.split("\x00") if name and (ROOT / name).is_file()}
    )
    if not files:
        raise RuntimeError(
            "No Go sources selected; formatting is unverified, not passed"
        )
    output = run([str(BIN / "gofumpt"), "-l", *files])
    if output.strip():
        raise RuntimeError("Run bin/gofumpt -w on these files:\n" + output)


def packages() -> None:
    compiler()
    if not run(["go", "list", "./..."]).strip():
        raise RuntimeError("No Go packages selected; runtime checks remain unverified")


def main() -> int:
    actions = {
        "compiler": compiler,
        "verify": verify,
        "install": install,
        "format-check": format_check,
        "packages": packages,
    }
    if len(sys.argv) != 2 or sys.argv[1] not in actions:
        print(
            "Usage: scripts/tools.py compiler|verify|install|format-check|packages",
            file=sys.stderr,
        )
        return 2
    try:
        actions[sys.argv[1]]()
    except (OSError, RuntimeError, tarfile.TarError, KeyError) as error:
        print(f"Tooling error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
