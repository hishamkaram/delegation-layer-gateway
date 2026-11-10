---
name: go-concurrency
description: Design and test Gateway goroutine, lock, deadline, queue and subprocess changes with explicit lifetime ownership.
---

# Go concurrency

Read [AGENTS](../../AGENTS.md), [product boundary](../../agents/_data/product-boundary.md)
and [recovery/lifetime guidance](../../agents/_data/maintainability-contract.md#recovery-and-lifetime-checks).

1. Name each resource owner, lifetime, close condition and failure path. Trace
   context propagation and lock order before editing. Wait for frozen contracts.
2. Separate observation lifetime from execution. Timeout, disconnection, shutdown
   or stop acceptance is never proof of no admission or worker termination.
3. Keep slots until Wait and owned pipe/helper joins settle. Every Start has one
   Wait. Unresolved cleanup blocks capacity/readiness instead of freeing a slot.
4. Bound queues by bytes and count, controls by finite contexts and explicit
   acquisition limits. Reserve cancellation/fence capacity independently. Never
   use unbounded goroutines, direct provider signals or process searches.
5. Test send/receipt/commit races at owner gates, generation changes, revocation,
   joined cleanup faults and shutdown. Use real stores for durable claims.
   Queue length, sleeps and launch barriers do not prove active capacity.

Run affected race tests and report exact results, cleanup and limits. Native
primitives require native checks on the affected host; cross-builds are insufficient.
Root owns integrated gates. Report documentation impact with changes/findings.
