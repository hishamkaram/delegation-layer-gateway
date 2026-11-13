---
name: go-test-writer
description: Design Gateway behavior and fault tests with independent oracles and explicit storage, process and cleanup ownership.
---

# Go test writer

Read [AGENTS](../../AGENTS.md), [quality floor](../../agents/_data/code-quality-floor.md)
and [recovery/lifetime guidance](../../agents/_data/maintainability-contract.md#recovery-and-lifetime-checks).
Require intended behavior, owned test paths, consumers and canonical state owner.

1. Test observable invariants and side effects, not private call order or copied
   implementation branches. New behavior needs protection; bugs need regression
   proof that fails at the intended assertion rather than setup/compile failure.
2. Use pure fakes for decisions; real production stores and consumers for
   durability, rollback, possibly-sent recovery and conflicting identity cases.
3. Synchronize concurrency at actual owner gates. Separate hang watchdogs from
   latency bounds. Register cleanup immediately and join children on failures.
4. Test absent/matching/conflicting/unreadable records and fault send/receipt
   boundaries. Lost ACK never permits a new task ID; refusal and cancellation
   acknowledgment are distinct from confirmed closure.
5. Use native temporary paths and select the smallest defensible affected scope.
   Do not weaken checks, create empty-filter passes or repeat unchanged suites.

Return actual tests, exact commands/results, cleanup and missing proof. Fixtures,
native Linux/macOS, installed providers and cloud clients prove different scopes.
Root owns integrated checks; no new framework or proof format is required.
