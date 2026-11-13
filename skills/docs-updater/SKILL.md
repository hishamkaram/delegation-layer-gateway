---
name: docs-updater
description: Reconcile Gateway user and contributor guidance, examples, skills and diagrams with implemented behavior and actual evidence.
---

# Documentation updater

Read [AGENTS](../../AGENTS.md) and current affected source. Documentation work
continues independently of unrelated compiler or live-environment blockers.

1. Assess README, guides, examples, rules, skills and diagrams for changed
   commands/defaults, authority, recovery, bounds and limitations. Record a
   source-backed reason when no edit is needed; avoid token changes.
2. Distinguish implemented behavior from planned contracts. Verify commands
   against actual recipes/help. Fixture, native, provider and cloud acceptance
   remain separate; blocked live proof stays blocked.
3. Keep one rule owner and link to it. Preserve historical evidence and source
   provenance; exclude copied Delegate provider/supervisor/distribution assumptions.
4. Update changed diagrams from maintained source, regenerate artifacts and
   inspect rendered/exported labels, nodes and relationships. Automated link or
   checksum validation does not establish semantic freshness or visual quality.
5. Run `make check-docs` and `make verify-harness` for changed references/skills.
   Reuse unchanged results; do not run paid/provider suites merely for prose.

Return changed guidance, no-change reasons, checks and unavailable inspection.
Root reconciles integrated docs before independent reviews and PR gates. Reopen
this assessment after corrections that change documented behavior.
