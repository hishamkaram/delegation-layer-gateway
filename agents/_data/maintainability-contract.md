# Maintainability and architecture

[AGENTS](../../AGENTS.md) owns engineering and coordination policy;
[product boundary](product-boundary.md) owns product authority.

## Package and state boundaries

Choose the owning cohesive package before adding a capability. Shared values
and pure decisions point inward; adapters and application composition point
inward through narrow consumer-owned interfaces. A wrapper or filename-prefix
family does not establish a boundary. Do not add empty layers or forwarding
facades. Mutable state stays behind its named owner; caches state their source,
freshness and invalidation rule. Explicitly validate typed input at I/O edges.

## Recovery and lifetime checks

Persist immutable operation identity before a possibly-sent transition. Never
infer absence/closure from timeout, missing validation dependencies or transport
failure. Preserve concrete joined errors; a pending marker must not hide storage,
unlock or cleanup faults. Use canonical store transactions and owner APIs.

Durability/recovery tests exercise production stores and real consumers at
absent, matching, conflicting and unreadable boundaries. Fakes prove isolated
decisions, not fsync/crash safety. Synchronize races at actual owner boundaries;
sleeps and queue counts do not establish concurrent execution capacity.

Every Start has one Wait. Keep slots and subprocess cleanup ownership until
Wait and owned pipe/helper joins settle, even after transport timeout. Gateway
shutdown never cancels Delegate work. No direct provider signals or supervisor
inspection. Use native temporary-file APIs; only remove test-owned paths after
confirmed closure. Cross-builds do not prove native host behavior.

## Independent review

Read actual integrated source including untracked files and affected consumers.
Check public contracts, authorization, recovery, resource bounds, secret handling,
meaningful assertions and cleanup. Report severity, file/line, impact and proof.
Review corrections and rerun invalidated checks; reuse evidence only for unchanged
inputs. Missing checks remain unverified. Keep unrelated findings separate.
