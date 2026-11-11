#!/usr/bin/env python3
"""Validate harness wiring and local references without external packages or agents."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

if sys.version_info < (3, 12):
    sys.exit(
        "verify-harness requires Python 3.12+: select python3.12, then rerun make verify-harness"
    )

import tomllib

ROLES = {
    "researcher": "read-only",
    "reviewer": "read-only",
    "implementer": "workspace-write",
}
SKILLS = (
    "go-implementer",
    "go-reviewer",
    "go-test-writer",
    "go-concurrency",
    "docs-updater",
)
LINK = re.compile(r"!?\[[^\]]*\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)")
FRONTMATTER_KEY = re.compile(r"^([a-z][a-z_-]*):\s*(\S.*)$")
# Generated trees and the separately validated Native test-source checkout do
# not own Gateway instructions or documentation.
EXCLUDED_TREES = frozenset(
    {".git", "bin", ".local", ".ci-native", "node_modules", "__pycache__"}
)


def markdown_body(text: str) -> str:
    """Exclude fenced examples from local-link and heading discovery."""
    lines: list[str] = []
    fence = ""
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            if not fence:
                fence = marker[1][0]
            elif fence == marker[1][0]:
                fence = ""
            continue
        if not fence:
            lines.append(line)
    return "\n".join(lines)


def headings(path: Path) -> set[str]:
    result: set[str] = set()
    for title in re.findall(
        r"^#{1,6}\s+(.+?)\s*#*\s*$", markdown_body(path.read_text()), re.MULTILINE
    ):
        slug = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        original, suffix = slug, 0
        while slug in result:
            suffix += 1
            slug = f"{original}-{suffix}"
        result.add(slug)
    return result


def references(root: Path, paths: list[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        for target in LINK.findall(markdown_body(path.read_text())):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or parsed.netloc:
                continue
            destination = (
                (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            )
            if not destination.is_relative_to(root):
                errors.append(
                    f"{path.relative_to(root)}: reference escapes repository: {target}"
                )
            elif not destination.exists():
                errors.append(
                    f"{path.relative_to(root)}: missing reference {target}; add its owner file or correct the link"
                )
            elif (
                parsed.fragment
                and destination.suffix == ".md"
                and unquote(parsed.fragment) not in headings(destination)
            ):
                errors.append(
                    f"{path.relative_to(root)}: missing heading {target}; update the anchor or destination heading"
                )
    return errors


def frontmatter(path: Path) -> tuple[dict[str, str], list[str]]:
    """Harness metadata deliberately uses only flat, unquoted YAML strings."""
    parts = path.read_text().split("---", 2)
    if len(parts) != 3 or parts[0].strip():
        return {}, [
            f"{path}: add opening/closing YAML frontmatter with name and description"
        ]
    values: dict[str, str] = {}
    errors: list[str] = []
    for line in parts[1].splitlines():
        if not line.strip():
            continue
        match = FRONTMATTER_KEY.fullmatch(line)
        if not match or match[1] in values:
            errors.append(
                f"{path}: use unique flat key/value frontmatter entries: {line!r}"
            )
            continue
        values[match[1]] = match[2]
    for key in ("name", "description"):
        if not values.get(key):
            errors.append(f"{path}: missing required frontmatter field {key}")
    if values.get("name") and not re.fullmatch(r"[a-z0-9-]{1,64}", values["name"]):
        errors.append(
            f"{path}: name must be 1..64 lowercase letters, digits or hyphens"
        )
    return values, errors


def required_file(root: Path, relative: str, errors: list[str]) -> Path | None:
    path = root / relative
    if not path.is_file():
        errors.append(
            f"missing {relative}; restore this harness dependency before validation"
        )
        return None
    return path


def validate(root: Path, docs: bool = False) -> list[str]:
    errors: list[str] = []
    rules = required_file(root, "AGENTS.md", errors)
    claude = required_file(root, "CLAUDE.md", errors)
    if claude and claude.read_text().strip() != "@AGENTS.md":
        errors.append(
            "CLAUDE.md must import @AGENTS.md only; keep AGENTS.md as the sole rules authority"
        )
    config = required_file(root, ".codex/config.toml", errors)
    catalog: dict[str, object] = {}
    if config:
        try:
            parsed_catalog = tomllib.loads(config.read_text()).get("agents", {})
            if isinstance(parsed_catalog, dict):
                catalog = parsed_catalog
            else:
                errors.append(
                    ".codex/config.toml: agents must be a table of role registrations"
                )
        except tomllib.TOMLDecodeError as exc:
            errors.append(f".codex/config.toml: invalid TOML: {exc}")
    if catalog:
        errors.append(
            ".codex/config.toml: use standalone definitions, not legacy role registrations"
        )
    for role, sandbox in ROLES.items():
        canonical = required_file(root, f"agents/{role}.md", errors)
        native = required_file(root, f".codex/agents/{role}.toml", errors)
        if native:
            try:
                value = tomllib.loads(native.read_text())
                if value.get("name") != role or not value.get("description"):
                    errors.append(
                        f"{native.relative_to(root)}: require role {role} and description"
                    )
                if set(value) - {"name", "description", "developer_instructions"}:
                    errors.append(
                        f"{native.relative_to(root)}: unsupported role override; permissions are inherited"
                    )
                instructions = value.get("developer_instructions", "")
                if (
                    not isinstance(instructions, str)
                    or f"agents/{role}.md" not in instructions
                ):
                    errors.append(
                        f"{native.relative_to(root)}: point developer_instructions at agents/{role}.md"
                    )
            except tomllib.TOMLDecodeError as exc:
                errors.append(f"{native.relative_to(root)}: invalid TOML: {exc}")
        wrapper = required_file(root, f".claude/agents/{role}.md", errors)
        if wrapper:
            values, problems = frontmatter(wrapper)
            errors.extend(problems)
            if values.get("name") != role:
                errors.append(
                    f"{wrapper.relative_to(root)}: native name must match {role}"
                )
            tools = {item.strip() for item in values.get("tools", "").split(",")}
            allowed = {"Read", "Glob", "Grep"}
            if sandbox == "workspace-write":
                allowed |= {"Edit", "Write", "Bash"}
            if tools != allowed:
                errors.append(
                    f"{wrapper.relative_to(root)}: require tools {', '.join(sorted(allowed))}; read-only roles cannot mutate"
                )
            if canonical and f"../../agents/{role}.md" not in wrapper.read_text():
                errors.append(
                    f"{wrapper.relative_to(root)}: link the canonical agents/{role}.md role"
                )
    discovered = {path.parent.name for path in (root / "skills").glob("*/SKILL.md")}
    for name in SKILLS:
        if name not in discovered:
            errors.append(f"missing skills/{name}/SKILL.md; restore the catalog skill")
    for name in sorted(discovered):
        path = root / "skills" / name / "SKILL.md"
        values, problems = frontmatter(path)
        errors.extend(problems)
        if values.get("name") != name:
            errors.append(
                f"{path.relative_to(root)}: frontmatter name must match directory {name}"
            )
        if rules and f"skills/{name}/SKILL.md" not in rules.read_text():
            errors.append(
                f"AGENTS.md: catalog skills/{name}/SKILL.md for both harnesses"
            )
    paths = [root / "AGENTS.md", root / "CLAUDE.md"]
    for directory in ("agents", "skills", ".claude", "docs"):
        paths.extend((root / directory).rglob("*.md"))
    paths.extend((root / ".github").glob("*template*.md"))
    if docs:
        paths = [
            path
            for path in root.rglob("*.md")
            if not any(part in EXCLUDED_TREES for part in path.relative_to(root).parts)
        ]
    errors.extend(references(root, sorted({path for path in paths if path.is_file()})))
    return errors


def self_test(root: Path) -> list[str]:
    """Challenge real validator boundaries in an isolated repository copy."""
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="gateway-harness-") as directory:
        fixture = Path(directory)
        # Copy metadata only; referenced non-Markdown dependencies need existence, not content.
        for directory, children, filenames in os.walk(root):
            children[:] = [name for name in children if name not in EXCLUDED_TREES]
            for filename in filenames:
                source = Path(directory) / filename
                if source.is_symlink() or source.suffix not in {".md", ".toml"}:
                    continue
                target = fixture / source.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        for path in list(fixture.rglob("*.md")):
            for target in LINK.findall(markdown_body(path.read_text())):
                parsed = urlsplit(target.strip("<>"))
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                relative = (path.parent / unquote(parsed.path)).resolve()
                if not relative.is_relative_to(fixture):
                    continue
                original = root / relative.relative_to(fixture)
                if (
                    original.exists()
                    and not relative.exists()
                    and original.suffix != ".md"
                ):
                    if original.is_dir():
                        relative.mkdir(parents=True, exist_ok=True)
                    else:
                        relative.parent.mkdir(parents=True, exist_ok=True)
                        relative.touch()
        baseline = validate(fixture)
        if baseline:
            return ["self-test baseline failed: " + error for error in baseline]
        dependency = fixture / ".ci-native"
        dependency.mkdir()
        (dependency / "README.md").write_text("[Native-owned reference](absent.md)\n")
        if validate(fixture, docs=True):
            errors.append(
                "self-test: external Native checkout entered Gateway docs scope"
            )
        cases = (
            (
                "legacy Codex registration",
                ".codex/config.toml",
                '[agents.reviewer]\nconfig_file = "agents/reviewer.toml"\n',
                "use standalone definitions",
            ),
            (
                "missing role dependency",
                "agents/researcher.md",
                None,
                "missing agents/researcher.md",
            ),
            (
                "ineffective permission override",
                ".codex/agents/reviewer.toml",
                'name = "reviewer"\nsandbox_mode = "workspace-write"\ndeveloper_instructions = "agents/reviewer.md"\n',
                "unsupported role override",
            ),
            (
                "Claude write tool exposure",
                ".claude/agents/reviewer.md",
                "---\nname: reviewer\ndescription: Review\ntools: Read, Glob, Grep, Bash\n---\n[Role](../../agents/reviewer.md)\n",
                "read-only roles cannot mutate",
            ),
            (
                "undiscoverable skill",
                "AGENTS.md",
                (fixture / "AGENTS.md")
                .read_text()
                .replace("skills/go-concurrency/SKILL.md", "missing.md"),
                "catalog skills/go-concurrency/SKILL.md",
            ),
            (
                "broken local reference",
                "agents/researcher.md",
                "[Missing](absent.md)\n",
                "missing reference absent.md",
            ),
            (
                "broken heading",
                "agents/researcher.md",
                "[Missing](../AGENTS.md#absent-heading)\n",
                "missing heading",
            ),
            (
                "invalid skill metadata",
                "skills/go-implementer/SKILL.md",
                "---\nname: Wrong\n---\n",
                "missing required frontmatter field description",
            ),
        )
        for label, relative, replacement, expected in cases:
            target = fixture / relative
            original = target.read_text()
            if replacement is None:
                target.unlink()
            else:
                target.write_text(replacement)
            observed = validate(fixture)
            target.write_text(original)
            if not any(expected in error for error in observed):
                errors.append(
                    f"self-test {label}: invalid fixture was not rejected for {expected}"
                )
        if validate(fixture):
            errors.append("self-test: restored valid fixture was rejected")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--docs",
        action="store_true",
        help="also validate all maintained Markdown local links/anchors",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    errors = validate(root, docs=args.docs)
    if not errors:
        errors.extend(self_test(root))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "Harness validation passed: Codex/Claude roles, skills, local references, 8 isolated rejection fixtures and Native dependency isolation."
    )
    print(
        "Scope: structural wiring only; no model behavior, native harness launch or live integration claim."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
