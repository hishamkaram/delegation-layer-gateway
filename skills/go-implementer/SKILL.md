---
name: go-implementer
description: Implement a bounded Gateway or connector Go change with meaningful tests and preserved subsystem ownership.
---

# Go implementer

Require an exact base, owned paths, frozen interface prerequisites, behavior,
non-goals and done condition. Read [AGENTS](../../AGENTS.md),
[maintainability](../../agents/_data/maintainability-contract.md),
[quality floor](../../agents/_data/code-quality-floor.md) and the affected source.
Missing tools block dependent proof, never authorize global setup changes.

1. Inspect callers/tests. Preserve other writers and wait for prerequisite post-images.
2. Name owner, writers/readers and invariant before changing state or contracts.
   Choose a cohesive package and consumer-owned ports; separate pure rules and I/O.
3. Preserve immutable operation/task correlation, contexts, wrapped errors and
   grants. Connector uses public installed Delegate CLI only; never private state.
4. Protect new behavior and bug fixes with independent expected outcomes. Use
   real stores/consumers for persistence/recovery and deterministic owner gates
   for races. Load [test writer](../go-test-writer/SKILL.md) when needed.
5. Format and run affected checks, including race coverage for concurrent paths.
   Use [concurrency](../go-concurrency/SKILL.md) for lifetime and cancellation work.

Deliver actual assigned changes, exact checks/results, documentation impact and
blockers to Root. Root owns integration, Git and final independent review. No
commits or nested external work without assignment. Apply the
[installed-executable rule](../../agents/_data/product-boundary.md#installed-executables).
