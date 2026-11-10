# Working on Delegation Layer Gateway

This is the authoritative repository rules file. [CLAUDE.md](CLAUDE.md) imports
it; harness configuration and skills refer here rather than duplicating rules.

## Product and ownership

Read [product boundary](agents/_data/product-boundary.md) before changing a
contract. Gateway owns registry, grants, operation correlation and routing;
connector owns local alias configuration and its stricter grant ceiling;
Delegate alone owns task admission, launch, supervision and accepted outcomes.
Gateway observations are dated caches. Same device account is one trust boundary;
a project grant is routing, never an OS sandbox.

Before changing state or an interface, name its owner, writers, readers and
invariant. Use one authority per state. Keep data, pure decisions and thin I/O
separate; dependencies point inward through consumer-owned typed interfaces.
Use cohesive packages, explicit errors and immutable defaults. No hidden global
state, shell-built CLI commands, unchecked boundary values or duplicated policy.
See [maintainability](agents/_data/maintainability-contract.md).

## Coordination

Root owns shared contracts, integration, Git, documentation reconciliation and
review gates. Assign each worker an exact base, owned paths, stable prerequisites
and done condition. One writer owns overlapping files. Wait for required
contracts; independent owned work can proceed. Preserve others' changes.
Workers leave changes uncommitted unless explicitly assigned Git operations.
Do not recruit agents or external sessions without authorization. Preserve the
user's chosen model, effort, permissions and integration.

## Verification and completion

Read source before claims. Use focused meaningful checks during editing and
[the quality floor](agents/_data/code-quality-floor.md) for final verification.
Do not weaken assertions, lint or types. Tests protect observable invariants
with independent expected results; storage/recovery boundaries need real stores.
Every owned goroutine/process has cleanup and a join; timeout or socket closure
never proves task closure. See [go-concurrency](skills/go-concurrency/SKILL.md).

Report exact commands, results and limits. Missing prerequisites block dependent
claims, not unrelated work. Label missing proof `Unverified:`. Fixture execution,
installed-provider behavior, cross-builds, native Linux/macOS, multi-network and
cloud-client acceptance are distinct evidence categories. No paid workload or
external deployment without explicit environment and budget authorization.

Before opening a PR, reconcile affected guidance and diagrams using
[docs-updater](skills/docs-updater/SKILL.md), then independently review actual
integrated code and evidence. Root arranges the user-selected independent Sol
and Opus reviews plus security/concurrency review for affected boundaries.
Resolve known P0/P1/P2 findings and review fixes before PR gates pass. No review
or CI result implies release readiness when mandatory live proof is blocked.
The creator owns test resources and cleanup on success, failure and interruption;
retain evidence and report unresolved closure before removing owned paths.

## Discovery and skills

Use graph discovery when available, verify freshness/coverage and confirm exact
source. Use bounded live search for missing/stale coverage; empty results prove
no absence. Use version-matched local or primary documentation for external APIs.
Never send private source or secrets to external searches.

Load only the matching skill:

- [go-implementer](skills/go-implementer/SKILL.md): bounded Go implementation.
- [go-reviewer](skills/go-reviewer/SKILL.md): independent integrated review.
- [go-test-writer](skills/go-test-writer/SKILL.md): behavior and fault tests.
- [go-concurrency](skills/go-concurrency/SKILL.md): lifetimes and recovery races.
- [docs-updater](skills/docs-updater/SKILL.md): documentation reconciliation.

Native role definitions and skill discovery are described in
[the harness guide](docs/harness.md). Run `make verify-harness` after harness
changes and `make check-docs` after documentation changes. `make check` is the
complete engineering gate; [contributing](docs/contributing.md) explains scope.
