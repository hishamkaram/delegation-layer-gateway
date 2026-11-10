# Engineering harness

[AGENTS](../AGENTS.md) is the only repository rules authority. `CLAUDE.md`
imports it. Both harnesses use its shared skill catalog; loading a skill is
explicitly routed by the applicable task rather than copied global policy.

## Native roles

[Codex configuration](../.codex/config.toml) documents standalone researcher,
reviewer and implementer TOML definitions under `.codex/agents/`. Claude discovers
Markdown wrappers under `.claude/agents/`; each points at the same canonical
[researcher](../agents/researcher.md), [reviewer](../agents/reviewer.md) or
[implementer](../agents/implementer.md) document. Codex agents inherit parent
permissions; research/review instructions request no edits and do not establish
a separate sandbox. Claude wrappers restrict tools to Read/Glob/Grep for these
roles. Implementers receive explicit owned paths. No model/effort is pinned by
these definitions; preserve the caller's selection.

[Official Codex documentation](https://developers.openai.com/codex/multi-agent)
defines standalone discovery and inherited permissions. Set actual permission
controls on the parent session; a custom role cannot override them.

For a bounded implementation, Root supplies base, owned paths, prerequisites and
done condition; implementer follows the shared Go skill and hands back changes,
checks and blockers. For independent review, a different reader loads the review
skill and examines integrated source plus evidence. Research traces source and
reports facts without edits. Role definitions never authorize external delegation.

## Source inventory and provenance

Adapted from read-only Delegate source commit
`0eed5e28288628490c6fb0297616f4d64d4584c9`. The source checkout was clean when
inspected. This table records decisions, not an automatic synchronization promise.
Gateway changes must follow its own public contracts and product boundary.

| Source artifact | Decision | Gateway owner / reason |
| --- | --- | --- |
| `AGENTS.md` shared engineering/coordination/docs rules | Adapt | [AGENTS](../AGENTS.md); Gateway/connector/Delegate authorities and P0/P1/P2 review gates |
| `.codex/config.toml`, `.codex/agents/*.toml` | Adapt | Standalone native definitions plus canonical `agents/*.md`; replace legacy registration and ineffective per-role sandbox declarations |
| No source `CLAUDE.md` or Claude native roles | Replace missing integration | `CLAUDE.md` import and `.claude/agents/*.md` wrappers; one shared authority |
| `agents/_data/product-boundary.md` | Adapt | [Gateway product boundary](../agents/_data/product-boundary.md); public CLI only, no execution authority |
| `agents/_data/maintainability-contract.md` | Adapt | [Maintainability](../agents/_data/maintainability-contract.md); cohesive packages, real stores, lifetime owners |
| `agents/_data/code-quality-floor.md` | Adapt | [Quality floor](../agents/_data/code-quality-floor.md); preserve Go lint/race/tool pins, replace distribution/static-tool targets |
| `skills/go-implementer`, `go-reviewer`, `go-test-writer`, `go-concurrency`, `docs-updater` | Adapt | Shared skills under `skills/`; Gateway-specific correlation, authorization, cleanup and documentation boundaries |
| Generic ownership, independent-oracle and evidence distinctions | Reuse | Retained within the adapted rules/skills without a second authority |
| `scripts/verify_skills.py` package/role lists and distribution checks | Replace | [Harness validator](../scripts/verify_harness.py); Gateway-owned native wiring, links and fault fixtures |
| Provider/adapter contracts, `add-an-adapter`, provider roles | Exclude | Gateway never implements provider adapters |
| Supervisor/Pueue/runtime roles and Delegate lifecycle internals | Exclude | Delegate alone owns execution and canonical evidence |
| npm/plugin/CCR/install/release machinery and hardcoded package checks | Exclude | No Gateway distribution/runtime requirement; no copied provider lifecycle |

## Validation and limits

Run `python3 scripts/verify_harness.py` or `make verify-harness` with Python
3.12+. Only the Python standard library is needed. Missing role/config/skill
files fail with a concrete dependency path. It validates standalone metadata,
unsupported role overrides, Claude tool lists, canonical role pointers, skill frontmatter/catalog discovery and
local Markdown references/anchors. `--docs` extends reference checks to maintained
repository Markdown. Metadata uses flat unquoted YAML fields; TOML uses stdlib
`tomllib`. Extend the parser deliberately if introducing richer metadata.

Eight isolated rejection fixtures exercise legacy registrations, missing role dependencies, Codex
ineffective permission overrides, Claude write-tool exposure, undiscoverable skills,
missing files, broken anchors and invalid metadata. A valid copied harness passes
before all challenges and after restoration of all challenged files. The validator launches no agent/provider and alters no
repository files. These checks prove structural wiring and actionable failures;
they do not prove an LLM follows instructions or a native harness can load them.
Native role launch/behavior and independent integrated Sol/Opus review remain
separate evidence. `make check-docs` and the integrated engineering gate remain
required; local fixture success alone never establishes release readiness.
