#!/usr/bin/env python3
"""Verify published artifact bindings, not rendering or system behavior."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys


def record(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("expected string object keys")
        result[key] = item
    return result


def records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise ValueError("expected a nonempty receipt list")
    return [record(item) for item in value]


def verify_file(base: Path, description: dict[str, object]) -> str:
    name, expected_hash, expected_size = (
        description.get("path", description.get("artifact")),
        description.get("sha256"),
        description.get("bytes"),
    )
    if (
        not isinstance(name, str)
        or not name
        or Path(name).is_absolute()
        or ".." in Path(name).parts
    ):
        raise ValueError("artifact path must be local to diagrams")
    if not isinstance(expected_hash, str) or not re.fullmatch(
        r"[a-f0-9]{64}", expected_hash
    ):
        raise ValueError(f"{name}: invalid artifact digest")
    if type(expected_size) is not int or expected_size < 0:
        raise ValueError(f"{name}: invalid artifact length")
    path = base / name
    if path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):
        raise ValueError(f"{name}: artifact escapes diagrams")
    data = path.read_bytes()
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError(
            f"{name}: artifact changed; regenerate and refresh validation evidence"
        )
    return expected_hash


def verify(base: Path) -> int:
    summary = record(json.loads((base / "validation.json").read_text()))
    exports = record(json.loads((base / "svg-exports.json").read_text()))
    export_records = records(exports.get("exports"))
    diagrams = records(summary.get("diagrams"))
    names = [record(item.get("html")).get("path") for item in diagrams]
    if len(set(names)) != len(names) or set(names) != {
        path.name for path in base.glob("*.html")
    }:
        raise ValueError("each maintained HTML diagram requires exactly one receipt")
    patch_hash = hashlib.sha256(
        (base.parent / "tools/archify-whitespace.patch").read_bytes()
    ).hexdigest()
    for item in [exports, *diagrams]:
        renderer = record(item.get("renderer"))
        if (
            renderer.get("localPatch") != "../tools/archify-whitespace.patch"
            or renderer.get("patchSha256") != patch_hash
        ):
            raise ValueError("renderer patch changed; regenerate validation evidence")
    count = 0
    for diagram in diagrams:
        source = record(diagram.get("source"))
        html = record(diagram.get("html"))
        verify_file(base, source)
        html_hash = verify_file(base, html)
        svg = record(diagram.get("svgExport"))
        matches = [
            item for item in export_records if item.get("artifact") == svg.get("path")
        ]
        if len(matches) != 1 or matches[0].get("sourceHtmlSha256") != html_hash:
            raise ValueError("SVG export is not bound to its current HTML")
        verify_file(base, matches[0])
        count += 3
    return count


def main() -> int:
    try:
        count = verify(Path(__file__).resolve().parent.parent / "diagrams")
    except (OSError, ValueError) as error:
        print(f"Diagram verification failed: {error}", file=sys.stderr)
        return 1
    print(
        f"Verified {count} source/HTML/SVG bindings; no rendering or runtime acceptance inferred."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
